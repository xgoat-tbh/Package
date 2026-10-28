"""Message framing on top of :mod:`syspy.crypto`.

Every packet on the wire is a sealed JSON document. Large payloads are split
into chunks that are reassembled on the far side, so a 3 MB screenshot travels
over a public MQTT broker without any broker-specific configuration.

Two things changed in this revision.

**Format negotiation.** ``Codec`` carries the envelope format it writes. A v2
controller speaks v2 to a v2 agent and v1 to a v1 agent, decided per peer from
the ``fmt`` field in its hello. Decoding always auto-detects, so nothing has to
be migrated in lockstep.

**QoS-1 retransmits work.** A retried publish is byte-identical, so its nonce is
already in the replay filter. Rejecting it outright silently defeated every
retry. ``decode_message`` therefore treats a replay as "already seen": harmless
for a chunk (the reassembler dedups by index anyway) and dropped for a logical
message.
"""

from __future__ import annotations

import base64
import json
import threading
import zlib
from typing import Any, Optional

from . import config
from .crypto import ReplayFilter, nonce_span, seal, unseal

#: Guard rails. All three were previously unbounded.
MAX_TOTAL_CHUNKS = 20_000
MAX_LIVE_TRANSFERS = 64
MAX_AGGREGATE_BYTES = 512 * 1024 * 1024
MAX_DECOMPRESSED = 256 * 1024 * 1024

REASON_OK = "ok"
REASON_REPLAY = "replay"
REASON_BAD = "bad"


class Codec:
    """Encodes and decodes sealed protocol messages."""

    def __init__(self, key: bytes, replay_capacity: int = 1024, fmt: int = 2) -> None:
        self._key = key
        self._fmt = fmt
        self._replay = ReplayFilter(replay_capacity)

    @property
    def fmt(self) -> int:
        return self._fmt

    def encode(self, message: dict[str, Any]) -> bytes:
        raw = json.dumps(message, separators=(",", ":")).encode("utf-8")
        return seal(self._key, raw, fmt=self._fmt)

    def decode(self, blob: bytes, allow_replay: bool = False) -> dict[str, Any]:
        """Verify, decrypt and deserialise. Raises ``ValueError`` on failure."""
        raw = unseal(self._key, blob)
        start, end = nonce_span(blob)
        if not allow_replay and not self._replay.check(blob[start:end]):
            raise ValueError("replayed packet")
        return json.loads(raw.decode("utf-8"))

    def decode_message(self, blob: bytes) -> tuple[Optional[dict[str, Any]], str]:
        """Chunk-aware decode.

        Returns ``(message, REASON_OK)``, ``(None, REASON_REPLAY)`` for a
        duplicate that has already been handled, or ``(None, REASON_BAD)``.
        """
        try:
            return self.decode(blob), REASON_OK
        except ValueError as error:
            if "replayed" not in str(error):
                return None, REASON_BAD
        try:
            message = self.decode(blob, allow_replay=True)
        except ValueError:
            return None, REASON_BAD
        if "xid" in message:
            return message, REASON_OK          # QoS-1 redelivery of a chunk
        return None, REASON_REPLAY             # duplicate logical message


class Reassembler:
    """Collects chunked payloads and returns them once complete."""

    def __init__(self, timeout: float = 120.0) -> None:
        self._timeout = timeout
        self._parts: dict[str, dict[int, bytes]] = {}
        self._meta: dict[str, tuple[int, float]] = {}
        self._bytes = 0
        self._lock = threading.Lock()
        self.dropped = 0

    def feed(self, message: dict[str, Any], now: float) -> Optional[bytes]:
        """Add a chunk. Returns the full payload when the last chunk arrives."""
        transfer = str(message.get("xid") or "")
        try:
            total = int(message.get("total") or 1)
            index = int(message.get("part") or 0)
        except (TypeError, ValueError):
            return None
        if not transfer or total < 1 or total > MAX_TOTAL_CHUNKS:
            return None
        if not 0 <= index < total:
            return None

        try:
            decoded = base64.b64decode(message.get("data") or "")
        except Exception:
            return None

        with self._lock:
            self._expire(now)
            if transfer not in self._parts and len(self._parts) >= MAX_LIVE_TRANSFERS:
                self.dropped += 1
                return None
            if self._bytes + len(decoded) > MAX_AGGREGATE_BYTES:
                self._parts.pop(transfer, None)
                self._meta.pop(transfer, None)
                self.dropped += 1
                return None

            bucket = self._parts.setdefault(transfer, {})
            if index in bucket:                 # QoS-1 redelivery
                return None
            bucket[index] = decoded
            self._bytes += len(decoded)
            self._meta[transfer] = (total, now)

            if len(bucket) < total:
                return None

            data = b"".join(bucket[i] for i in range(total) if i in bucket)
            self._bytes -= sum(len(part) for part in bucket.values())
            self._parts.pop(transfer, None)
            self._meta.pop(transfer, None)

        if message.get("z"):
            try:
                data = zlib.decompressobj().decompress(data, MAX_DECOMPRESSED)
            except zlib.error:
                pass
        return data

    def _expire(self, now: float) -> None:
        stale = [k for k, (_, seen) in self._meta.items() if now - seen > self._timeout]
        for key in stale:
            bucket = self._parts.pop(key, None) or {}
            self._bytes -= sum(len(part) for part in bucket.values())
            self._meta.pop(key, None)

    def progress(self, message: dict[str, Any]) -> tuple[int, int]:
        transfer = str(message.get("xid") or "")
        try:
            total = int(message.get("total") or 1)
        except (TypeError, ValueError):
            total = 1
        with self._lock:
            received = len(self._parts.get(transfer, {}))
        return received, total

    def live(self) -> int:
        with self._lock:
            return len(self._parts)


def chunk(payload: bytes, transfer: str, chunk_size: int = config.CHUNK_SIZE,
          compress: bool = False) -> list[dict[str, Any]]:
    """Split ``payload`` into a list of chunk messages."""
    data = zlib.compress(payload, 6) if compress else payload
    total = max(1, (len(data) + chunk_size - 1) // chunk_size)
    return [
        {
            "xid": transfer,
            "part": index,
            "total": total,
            "data": base64.b64encode(
                data[index * chunk_size:(index + 1) * chunk_size]
            ).decode("ascii"),
            **({"z": 1} if compress else {}),
        }
        for index in range(total)
    ]
