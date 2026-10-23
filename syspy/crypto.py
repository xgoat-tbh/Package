"""Authenticated encryption built from :mod:`hashlib` alone.

Third-party crypto libraries are great, but the agent has to run on a machine
where nothing is installed.  This module therefore implements a small,
auditable encrypt-then-MAC construction:

* key derivation : PBKDF2-HMAC-SHA-256
* keystream      : SHA-256 in counter mode
* authenticator  : HMAC-SHA-256 over ``nonce || ciphertext``

The output is ``nonce(8) || ciphertext(n) || tag(32)``.

This is not AES-GCM.  It is, however, standard, simple, and correct for the
threat model here (a public MQTT broker that anyone can subscribe to).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from collections import deque
import threading

NONCE_SIZE = 8
TAG_SIZE = 32
KEY_SIZE = 32


def derive_key(passphrase: str, salt: bytes = b"", iterations: int = 60_000) -> bytes:
    """Stretch a passphrase into a 32-byte key."""
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_SIZE
    )


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Expand ``key`` and ``nonce`` into ``length`` pseudo-random bytes."""
    blocks = (length + 31) // 32
    out = bytearray()
    for counter in range(blocks):
        out += hashlib.sha256(key + nonce + struct.pack(">I", counter)).digest()
    return bytes(out[:length])


def seal(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt and authenticate ``plaintext``."""
    nonce = os.urandom(NONCE_SIZE)
    stream = _keystream(key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def unseal(key: bytes, blob: bytes) -> bytes:
    """Verify and decrypt a blob produced by :func:`seal`.

    Raises:
        ValueError: if the blob is malformed or the tag does not match.
    """
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("blob too short")
    nonce = blob[:NONCE_SIZE]
    ciphertext = blob[NONCE_SIZE:-TAG_SIZE]
    tag = blob[-TAG_SIZE:]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")
    stream = _keystream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


class ReplayFilter:
    """Remembers recently seen nonces so replayed packets are dropped."""

    def __init__(self, capacity: int = 1024) -> None:
        self._capacity = capacity
        self._seen: set[bytes] = set()
        self._order: deque[bytes] = deque()
        self._lock = threading.Lock()

    def check(self, nonce: bytes) -> bool:
        """Return ``True`` if this nonce is new, ``False`` if it is a replay."""
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
