"""A minimal RFC 6455 WebSocket server implementation.

Only what the dashboard needs: text frames, ping/pong and close.
"""

from __future__ import annotations

import base64
import hashlib
import struct
import threading
from typing import BinaryIO, Optional

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

# Dashboard frames are small JSON/control messages, not file transfers.
MAX_FRAME_BYTES = 1 * 1024 * 1024
_CONTROL_OPCODES = {OP_CLOSE, OP_PING, OP_PONG}
_ALLOWED_OPCODES = {OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG}


def accept_token(client_key: str) -> str:
    """Compute the ``Sec-WebSocket-Accept`` value for a handshake."""
    digest = hashlib.sha1((client_key + _GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


class WebSocket:
    """A single server-side websocket connection."""

    def __init__(self, reader: BinaryIO, writer: BinaryIO) -> None:
        self._reader = reader
        self._writer = writer
        self._lock = threading.Lock()
        self.closed = False

    # -- reading ---------------------------------------------------------

    def receive(self) -> Optional[tuple[int, bytes]]:
        """Read one frame.  Returns ``(opcode, payload)`` or ``None`` on close."""
        try:
            header = self._read_exact(2)
        except Exception:
            self.closed = True
            return None

        fin = bool(header[0] & 0x80)
        reserved = header[0] & 0x70
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F

        # Complete, unfragmented frames only. No extension is negotiated, so
        # any RSV bit set is a protocol error, and RFC 6455 requires every
        # browser-to-server frame to be masked.
        if reserved or not fin or not masked or opcode not in _ALLOWED_OPCODES:
            self.closed = True
            return None

        try:
            if length == 126:
                length = struct.unpack(">H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._read_exact(8))[0]

            if length > MAX_FRAME_BYTES:
                self.closed = True
                return None
            if opcode in _CONTROL_OPCODES and length > 125:
                self.closed = True
                return None

            mask = self._read_exact(4)
            payload = bytearray(self._read_exact(length))
        except Exception:
            self.closed = True
            return None

        if masked:
            for index in range(length):
                payload[index] ^= mask[index & 3]
        return opcode, bytes(payload)

    def _read_exact(self, count: int) -> bytes:
        buffer = self._reader.read(count)
        if not buffer or len(buffer) < count:
            raise ConnectionError("short websocket read")
        return buffer

    # -- writing ---------------------------------------------------------

    def send_text(self, text: str) -> None:
        self._send(OP_TEXT, text.encode("utf-8"))

    def send_binary(self, data: bytes) -> None:
        self._send(OP_BINARY, data)

    def ping(self) -> None:
        self._send(OP_PING, b"")

    def pong(self, payload: bytes = b"") -> None:
        self._send(OP_PONG, payload)

    def close(self, code: int = 1000) -> None:
        self._send(OP_CLOSE, struct.pack(">H", code))
        self.closed = True

    def _send(self, opcode: int, payload: bytes) -> None:
        if self.closed:
            return
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(length)
        elif length < 65536:
            header.append(126)
            header += struct.pack(">H", length)
        else:
            header.append(127)
            header += struct.pack(">Q", length)
        with self._lock:
            try:
                self._writer.write(bytes(header) + payload)
                self._writer.flush()
            except Exception:
                self.closed = True
