"""Authenticated encryption built from :mod:`hashlib` alone.

Two envelope formats live here.

**v2 (what this build writes).**  A versioned, self-describing header, a 12-byte
nonce, and *separate* encryption and authentication subkeys derived by
HKDF-Expand::

    "S2" | alg(1) | keyid(4) | nonce(12) | ciphertext(n) | tag(32)

The header is covered by the MAC, so ``alg`` and ``keyid`` cannot be flipped.
``keyid`` is ``SHA-256(key)[:4]`` and exists so a receiver can tell which key a
packet belongs to instead of guessing.

**v1 (legacy, still readable).**  ``nonce(8) | ciphertext | tag`` with one key
for both jobs. Kept so a patched controller and an unpatched agent interoperate
in both directions with no flag day.

``unseal`` auto-detects: it tries v2, and falls back to legacy when the v2 parse
fails. This is not a security downgrade -- a tampered v2 blob fails both.

This is still not AES-GCM. The agent runs where nothing is installed, so a
maintained AE library means vendoring one. What v2 fixes relative to v1 is the
real problem: no version marker, no algorithm marker, no key identity, an 8-byte
nonce, and one key doing two jobs.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import threading
from collections import deque

MAGIC = b"S2"
ALG_LEGACY = 0
ALG_CTR_HMAC = 1
HDR_SIZE = len(MAGIC) + 1 + 4

NONCE_SIZE_LEGACY = 8
NONCE_SIZE = 12
TAG_SIZE = 32
KEY_SIZE = 32

#: Envelope format written by :func:`seal` unless told otherwise.
CURRENT_FMT = 2

_ENC_INFO = b"syspy/v2/enc"
_MAC_INFO = b"syspy/v2/mac"


def derive_key(passphrase: str, salt: bytes = b"", iterations: int = 60_000) -> bytes:
    """Stretch a passphrase into a 32-byte key."""
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_SIZE
    )


def subkey(master_key: bytes, context) -> bytes:
    """HKDF-Expand (RFC 5869) over HMAC-SHA-256 for a purpose- or peer-specific key."""
    info = context.encode("utf-8") if isinstance(context, str) else context
    return hmac.new(master_key, info + b"\x01", hashlib.sha256).digest()[:KEY_SIZE]


def key_id(key: bytes) -> bytes:
    """4-byte public fingerprint of ``key``."""
    return hashlib.sha256(key).digest()[:4]


def _enc_key(key: bytes) -> bytes:
    return subkey(key, _ENC_INFO)


def _mac_key(key: bytes) -> bytes:
    return subkey(key, _MAC_INFO)


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    blocks = (length + 31) // 32
    out = bytearray()
    for counter in range(blocks):
        out += hashlib.sha256(key + nonce + struct.pack(">I", counter)).digest()
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


# --------------------------------------------------------------------------- seal

def seal(key: bytes, plaintext: bytes, fmt: int = CURRENT_FMT) -> bytes:
    """Encrypt and authenticate ``plaintext``."""
    if fmt < 2:
        return _seal_legacy(key, plaintext)

    nonce = os.urandom(NONCE_SIZE)
    header = MAGIC + bytes([ALG_CTR_HMAC]) + key_id(key)
    ciphertext = _xor(plaintext, _keystream(_enc_key(key), nonce, len(plaintext)))
    tag = hmac.new(_mac_key(key), header + nonce + ciphertext, hashlib.sha256).digest()
    return header + nonce + ciphertext + tag


def _seal_legacy(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE_LEGACY)
    ciphertext = _xor(plaintext, _keystream(key, nonce, len(plaintext)))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


# ------------------------------------------------------------------------- unseal

def _looks_v2(blob: bytes) -> bool:
    return blob[:len(MAGIC)] == MAGIC and len(blob) >= HDR_SIZE + NONCE_SIZE + TAG_SIZE


def nonce_span(blob: bytes) -> tuple[int, int]:
    """Byte range of the nonce, for whichever format ``blob`` uses."""
    if _looks_v2(blob):
        return HDR_SIZE, HDR_SIZE + NONCE_SIZE
    return 0, NONCE_SIZE_LEGACY


def header_of(blob: bytes) -> tuple[int, bytes]:
    """``(algorithm, key_id)``; ``(ALG_LEGACY, b"")`` for a legacy blob."""
    if _looks_v2(blob):
        return blob[len(MAGIC)], blob[len(MAGIC) + 1:HDR_SIZE]
    return ALG_LEGACY, b""


def unseal(key: bytes, blob: bytes) -> bytes:
    """Verify and decrypt. Raises ``ValueError`` on any failure."""
    if _looks_v2(blob):
        try:
            return _unseal_v2(key, blob)
        except ValueError as error:
            # A legacy blob whose random nonce happens to start with "S2"
            # lands here. Retry legacy before giving up.
            try:
                return _unseal_legacy(key, blob)
            except ValueError:
                raise error
    return _unseal_legacy(key, blob)


def _unseal_v2(key: bytes, blob: bytes) -> bytes:
    if len(blob) < HDR_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("blob too short")
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("bad magic")
    alg = blob[len(MAGIC)]
    if alg != ALG_CTR_HMAC:
        raise ValueError(f"unsupported algorithm {alg}")
    header = blob[:HDR_SIZE]
    nonce = blob[HDR_SIZE:HDR_SIZE + NONCE_SIZE]
    ciphertext = blob[HDR_SIZE + NONCE_SIZE:-TAG_SIZE]
    tag = blob[-TAG_SIZE:]
    expected = hmac.new(_mac_key(key), header + nonce + ciphertext,
                        hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")
    return _xor(ciphertext, _keystream(_enc_key(key), nonce, len(ciphertext)))


def _unseal_legacy(key: bytes, blob: bytes) -> bytes:
    if len(blob) < NONCE_SIZE_LEGACY + TAG_SIZE:
        raise ValueError("blob too short")
    nonce = blob[:NONCE_SIZE_LEGACY]
    ciphertext = blob[NONCE_SIZE_LEGACY:-TAG_SIZE]
    tag = blob[-TAG_SIZE:]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")
    return _xor(ciphertext, _keystream(key, nonce, len(ciphertext)))


# ------------------------------------------------------------------ kit signing

def kit_hmac_key(room: str, passphrase: str) -> bytes:
    """Symmetric integrity key for kit/update payloads.

    Used where an Ed25519 verifier is not available (PowerShell 5.1 has no
    Ed25519). Catches a LAN MITM and a tampered archive; does *not* stop someone
    who knows the passphrase, which is what the pinned public key is for.
    """
    return hashlib.sha256(
        ("syspy/kit/v1|" + room + "|" + passphrase).encode("utf-8")
    ).digest()


def hmac_hex(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, signature_hex: str, public_hex: str,
                     hmac_key: bytes = b"") -> tuple[bool, str]:
    """Check a payload against a pinned Ed25519 key, else an HMAC.

    Returns ``(ok, how)``. Fails closed: a pinned key that is present but does
    not verify is a failure, never a silent fall back to HMAC.
    """
    if public_hex:
        try:
            from . import ed25519
            public = bytes.fromhex(public_hex)
            if len(public) != 32:
                return False, "pinned public key is not 32 bytes"
            if not signature_hex:
                return False, "no signature supplied"
            if ed25519.verify(bytes.fromhex(signature_hex), payload, public):
                return True, "ed25519"
            return False, "ed25519 signature mismatch"
        except Exception as error:
            return False, f"ed25519 verify error: {error}"

    if hmac_key:
        digest = hmac_hex(hmac_key, payload)
        if hmac.compare_digest(digest, (signature_hex or "").lower()):
            return True, "hmac"
        return False, "hmac mismatch"

    return True, "unverified"


# ------------------------------------------------------------------- replay

class ReplayFilter:
    """Remembers recently seen nonces so replayed packets are dropped."""

    def __init__(self, capacity: int = 1024) -> None:
        self._capacity = capacity
        self._seen: set[bytes] = set()
        self._order: deque[bytes] = deque()
        self._lock = threading.Lock()

    def check(self, nonce: bytes) -> bool:
        """True when ``nonce`` is new, False when it is a replay."""
        with self._lock:
            if nonce in self._seen:
                return False
            self._seen.add(nonce)
            self._order.append(nonce)
            while len(self._order) > self._capacity:
                self._seen.discard(self._order.popleft())
            return True

    def reset(self) -> None:
        with self._lock:
            self._seen.clear()
            self._order.clear()
