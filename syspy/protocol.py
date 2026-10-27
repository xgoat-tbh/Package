"""Message framing on top of :mod:`syspy.crypto`.

Every packet on the wire is a sealed JSON document.  Large payloads are split
into chunks that are reassembled on the far side, so a 3 MB screenshot travels
over a public MQTT broker without any broker-specific configuration.
"""

from __future__ import annotations

import base64
import json
import threading
import zlib
from typing import Any, Optional

from . import config
from .crypto import ReplayFilter, seal, unseal

NONCE_SIZE = 8


class Codec:
    """Encodes and decodes sealed protocol messages."""

    def __init__(self, key: bytes, replay_capacity: int = 1024) -> None:
        self._key = key
        self._replay = ReplayFilter(replay_capacity)

    def encode(self, message: dict[str, Any]) -> bytes:
        """Serialise, seal and return a message."""
        raw = json.dumps(message, separators=(",", ":")).encode("utf-8")
        return seal(self._key, raw)

    def decode(self, blob: bytes, allow_replay: bool = False) -> dict[str, Any]:
        """Verify, decrypt and deserialise a message."""
        raw = unseal(self._key, blob)
        if not allow_replay and not self._replay.check(blob[:NONCE_SIZE]):
            raise ValueError("replayed packet")
        return json.loads(raw.decode("utf-8"))


class Reassembler:
    """Collects chunked payloads and returns them once complete."""

    def __init__(self, timeout: float = 120.0) -> None:
        self._timeout = timeout
        self._parts: dict[str, dict[int, bytes]] = {}
        self._meta: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    def feed(self, message: dict[str, Any], now: float) -> Optional[bytes]:
        """Add a chunk.  Returns the full payload when the last chunk arrives."""
        transfer = str(message.get("xid") or "")
        total = int(message.get("total") or 1)
        index = int(message.get("part") or 0)
        if not transfer or not 0 <= index < total:
            return None

        decoded = base64.b64decode(message["data"])
        with self._lock:
            bucket = self._parts.setdefault(transfer, {})
            if index in bucket:                 # QoS-1 redelivery
                return None
            bucket[index] = decoded
            self._meta[transfer] = (total, now)

            if len(bucket) < total:
                self._expire(now)
                return None

            data = b"".join(bucket[i] for i in range(total))
            self._parts.pop(transfer, None)
            self._meta.pop(transfer, None)

        if message.get("z"):
            try:
                data = zlib.decompress(data)
            except zlib.error:
                pass
        return data

    def _expire(self, now: float) -> None:
        stale = [k for k, (_, seen) in self._meta.items() if now - seen > self._timeout]
        for key in stale:
            self._parts.pop(key, None)
            self._meta.pop(key, None)

    def progress(self, message: dict[str, Any]) -> tuple[int, int]:
        """Return ``(received, total)`` for a chunk message."""
        transfer = str(message.get("xid") or "")
        total = int(message.get("total") or 1)
        with self._lock:
            received = len(self._parts.get(transfer, {}))
        return received, total


def chunk(payload: bytes, transfer: str, chunk_size: int = config.CHUNK_SIZE, compress: bool = False) -> list[dict[str, Any]]:
    """Split ``payload`` into a list of chunk messages."""
    data = zlib.compress(payload, 6) if compress else payload
    total = max(1, (len(data) + chunk_size - 1) // chunk_size)
    return [
        {
            "xid": transfer,
            "part": index,
            "total": total,
            "data": base64.b64encode(data[index * chunk_size:(index + 1) * chunk_size]).decode("ascii"),
            **({"z": 1} if compress else {}),
        }
        for index in range(total)
    ]
