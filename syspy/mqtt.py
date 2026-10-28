"""A minimal MQTT 3.1.1 client.

Implements just enough of the spec for SysPy: CONNECT, SUBSCRIBE, PUBLISH
(QoS 0 and 1), PINGREQ and DISCONNECT.  No paho, no external processes.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import threading
import time
from typing import Callable, Optional

from . import config, log

# Control packet types as they appear in the fixed header's high nibble.
PACKET_CONNECT = 0x10
PACKET_PUBLISH = 0x30
PACKET_PUBACK = 0x40
PACKET_SUBSCRIBE = 0x82
PACKET_PINGREQ = 0xC0
PACKET_DISCONNECT = 0xE0

# Same values, but used when *reading* (already shifted down).
TYPE_CONNACK = 2
TYPE_PUBLISH = 3
TYPE_PUBACK = 4
TYPE_SUBACK = 9
TYPE_PINGRESP = 13

#: Refuse absurd packets. The broker never sends more than CHUNK_SIZE plus a
#: small header, and a 64 MB allocation from a hostile broker is avoidable.
MAX_PACKET_BYTES = 64 * 1024 * 1024
#: Outbound QoS1 backlog ceiling before we start dropping the oldest.
MAX_PENDING = 512


def _varint(value: int) -> bytes:
    """Encode an MQTT remaining-length field."""
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


class MqttClient:
    """Blocking-connect, thread-driven MQTT client.

    Args:
        client_id: unique client identifier for this connection.
        on_message: called as ``on_message(topic, payload)`` for every message.
    """

    def __init__(self, client_id: str, on_message: Callable[[str, bytes], None]) -> None:
        self.client_id = client_id
        self._on_message = on_message
        self._sock: Optional[socket.socket] = None
        self._write_lock = threading.Lock()
        self._packet_id = 0
        self._alive = False
        self._keepalive = config.MQTT_KEEPALIVE
        self._pending: dict[int, tuple[str, bytes, float, int]] = {}
        self._acked: dict[int, threading.Event] = {}
        self._suback: Optional[threading.Event] = None
        self._suback_code = -1
        self.dropped = 0

    # -- connection ------------------------------------------------------

    @property
    def alive(self) -> bool:
        return self._alive and self._sock is not None

    def connect(self, host: str, port: int, use_tls: bool, timeout: float = 12.0,
                clean_session: bool = True, will_topic: str = "", will_payload: bytes = b"",
                username: str = "", password: str = "") -> None:
        """Open the socket and perform the MQTT handshake."""
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_tls:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.settimeout(90)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except (OSError, AttributeError):
            pass
        self._sock = sock

        flags = 0x02 if clean_session else 0x00
        tail = b""
        if will_topic:
            flags |= 0x04
            encoded_will = will_topic.encode("utf-8")
            tail += (struct.pack(">H", len(encoded_will)) + encoded_will
                     + struct.pack(">H", len(will_payload)) + will_payload)

        u = (username or getattr(config, "SYSPY_BROKER_USER", "")).encode("utf-8")
        p = (password or getattr(config, "SYSPY_BROKER_PASS", "")).encode("utf-8")
        if u:
            flags |= 0x80
            tail += struct.pack(">H", len(u)) + u
        if p:
            flags |= 0x40
            tail += struct.pack(">H", len(p)) + p

        identifier = self.client_id.encode("ascii")
        payload = (
            b"\x00\x04MQTT\x04"
            + bytes([flags])
            + struct.pack(">H", self._keepalive)
            + struct.pack(">H", len(identifier))
            + identifier
            + tail
        )
        self._send(PACKET_CONNECT, payload)
        header, body = self._read_packet()
        if header >> 4 != TYPE_CONNACK or (body and body[1]):
            code = body[1] if body else "?"
            raise ConnectionError(f"broker refused connection (code {code})")

        self._alive = True
        threading.Thread(target=self._read_loop, name="mqtt-read", daemon=True).start()
        threading.Thread(target=self._ping_loop, name="mqtt-ping", daemon=True).start()
        threading.Thread(target=self._retry_loop, name="mqtt-retry", daemon=True).start()

    def disconnect(self) -> None:
        self._alive = False
        try:
            if self._sock:
                self._send(PACKET_DISCONNECT, b"")
                self._sock.close()
        except OSError:
            pass
        self._sock = None

    # -- operations ------------------------------------------------------

    def subscribe(self, topic: str, qos: int = 1, timeout: float = 8.0) -> bool:
        """Subscribe and wait for SUBACK. False when the broker refused."""
        if not self.alive:
            return False
        encoded = topic.encode("utf-8")
        payload = b"\x00\x01" + struct.pack(">H", len(encoded)) + encoded + bytes([qos])
        event = threading.Event()
        self._suback = event
        self._suback_code = -1
        self._send(PACKET_SUBSCRIBE, payload)
        if not event.wait(timeout):
            return False
        return self._suback_code == 0

    def publish(self, topic: str, payload: bytes, qos: int = 1) -> None:
        if not self.alive:
            return
        encoded = topic.encode("utf-8")
        body = struct.pack(">H", len(encoded)) + encoded
        if qos:
            self._packet_id = self._packet_id % 65535 + 1
            body += struct.pack(">H", self._packet_id)
            self._pending[self._packet_id] = (topic, payload, time.time(), 0)
            if len(self._pending) > MAX_PENDING:
                self._pending.pop(next(iter(self._pending)), None)
                self.dropped += 1
        self._send(PACKET_PUBLISH | (qos << 1), body + payload)

    def publish_wait(self, topic: str, payload: bytes, qos: int = 1,
                     timeout: float = 6.0) -> bool:
        """Publish and block for the PUBACK. False means the broker never acked."""
        if not self.alive:
            return False
        if not qos:
            self.publish(topic, payload, 0)
            return True
        event = threading.Event()
        self._packet_id = self._packet_id % 65535 + 1
        pid = self._packet_id
        self._acked[pid] = event
        encoded = topic.encode("utf-8")
        body = (struct.pack(">H", len(encoded)) + encoded
                + struct.pack(">H", pid) + payload)
        self._pending[pid] = (topic, payload, time.time(), 0)
        self._send(PACKET_PUBLISH | 0x02, body)
        try:
            return event.wait(timeout)
        finally:
            self._acked.pop(pid, None)

    # -- internals -------------------------------------------------------

    def _send(self, header: int, body: bytes) -> None:
        if not self._sock:
            return
        with self._write_lock:
            try:
                self._sock.sendall(bytes([header]) + _varint(len(body)) + body)
            except OSError:
                self._alive = False

    def _read_exact(self, count: int) -> bytes:
        assert self._sock is not None
        chunks = bytearray()
        while len(chunks) < count:
            piece = self._sock.recv(count - len(chunks))
            if not piece:
                raise ConnectionError("broker closed the connection")
            chunks += piece
        return bytes(chunks)

    def _read_packet(self) -> tuple[int, bytes]:
        header = self._read_exact(1)[0]
        multiplier = 1
        length = 0
        bytes_read = 0
        while True:
            digit = self._read_exact(1)[0]
            length += (digit & 127) * multiplier
            bytes_read += 1
            if not digit & 128:
                break
            if bytes_read >= 4:
                raise ConnectionError("malformed MQTT packet: remaining length exceeds 4 bytes")
            multiplier *= 128
        if length > MAX_PACKET_BYTES:
            raise ConnectionError(f"MQTT packet too large: {length}")
        return header, (self._read_exact(length) if length else b"")

    def _read_loop(self) -> None:
        try:
            while self._alive:
                header, body = self._read_packet()
                kind = header >> 4
                if kind == TYPE_PUBLISH:
                    self._handle_publish(header, body)
                elif kind == TYPE_PUBACK:
                    if len(body) >= 2:
                        pid = struct.unpack(">H", body[:2])[0]
                        self._pending.pop(pid, None)
                        waiter = self._acked.get(pid)
                        if waiter is not None:
                            waiter.set()
                elif kind == TYPE_SUBACK:
                    if len(body) >= 3:
                        self._suback_code = body[2]
                    if self._suback is not None:
                        self._suback.set()
                elif kind == TYPE_PINGRESP:
                    continue
        except Exception as error:
            # Was silent: a protocol error killed the connection with no trace.
            log.get("mqtt").warning("read loop ended: %s", error)
        self._alive = False

    def _handle_publish(self, header: int, body: bytes) -> None:
        """Never raises. A truncated PUBLISH used to kill the read loop."""
        try:
            if len(body) < 2:
                return
            qos = (header >> 1) & 3
            topic_length = struct.unpack(">H", body[:2])[0]
            cursor = 2 + topic_length
            if cursor > len(body):
                return
            topic = body[2:cursor].decode("utf-8", "replace")
            if qos:
                if cursor + 2 > len(body):
                    return
                packet_id = body[cursor:cursor + 2]
                cursor += 2
                if qos == 1:
                    # PUBACK lives at 0x40, not 0x04.
                    self._send(PACKET_PUBACK, packet_id)
        except Exception as error:
            log.get("mqtt").warning("malformed PUBLISH dropped: %s", error)
            return
        try:
            self._on_message(topic, body[cursor:])
        except Exception:
            pass

    def _retry_loop(self) -> None:
        while self._alive:
            time.sleep(2)
            now = time.time()
            for pid, (topic, payload, when, tries) in list(self._pending.items()):
                if now - when < 5 or tries >= 4:
                    if tries >= 4:
                        self._pending.pop(pid, None)
                        self.dropped += 1
                    continue
                encoded = topic.encode("utf-8")
                body = (struct.pack(">H", len(encoded)) + encoded
                        + struct.pack(">H", pid) + payload)
                self._send(PACKET_PUBLISH | 0x02, body)
                self._pending[pid] = (topic, payload, now, tries + 1)

    def _ping_loop(self) -> None:
        while self._alive:
            time.sleep(self._keepalive / 2)
            if self._alive:
                try:
                    self._send(PACKET_PINGREQ, b"")
                except Exception:
                    self._alive = False
                    break


def random_client_id(prefix: str = "syspy") -> str:
    """Return a short unique client id."""
    return f"{prefix}-{os.urandom(4).hex()}"
