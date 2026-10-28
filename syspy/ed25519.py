"""Ed25519 (RFC 8032) in pure Python -- no dependencies, verify + sign.

Small and slow-ish (~25 ms per verify) but the agent has to run where nothing is
installed, and a signature is the only thing that turns "anyone who learns the
passphrase can push code to my fleet" into "anyone who learns the passphrase can
read my traffic".

Ported from the well-known compact reference implementation.
"""

from __future__ import annotations

import hashlib

P = 2 ** 255 - 19
Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x: int) -> int:
    return pow(x % P, P - 2, P)


_d = (-121665 * _inv(121666)) % P
_I = pow(2, (P - 1) // 4, P)

_By = 4 * _inv(5) % P
_Bx = _xrecover(_By) if False else 0  # replaced below


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * _I) % P
    if x % 2 != 0:
        x = P - x
    return x


_By = 4 * _inv(5) % P
_Bx = _xrecover(_By)
_B = (_Bx, _By)
_IDENTITY = (0, 1)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(_sha512(data), "little") % Q


def _add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    k = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k)
    return (x3 % P, y3 % P)


def _mul(s: int, point):
    result = _IDENTITY
    while s > 0:
        if s & 1:
            result = _add(result, point)
        point = _add(point, point)
        s >>= 1
    return result


def _encode(point) -> bytes:
    x, y = point
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decode(blob: bytes):
    if len(blob) != 32:
        raise ValueError("bad point length")
    raw = int.from_bytes(blob, "little")
    y = raw & ((1 << 255) - 1)
    if y >= P:
        raise ValueError("y out of range")
    x = _xrecover(y)
    if (x & 1) != ((raw >> 255) & 1):
        x = P - x
    return (x, y)


def _clamped_scalar(seed: bytes) -> int:
    digest = _sha512(seed)
    return 2 ** 254 + sum(
        2 ** i * ((digest[i // 8] >> (i % 8)) & 1) for i in range(3, 254)
    )


def publickey(seed: bytes) -> bytes:
    """32-byte public key for a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    return _encode(_mul(_clamped_scalar(seed), _B))


def sign(message: bytes, seed: bytes) -> bytes:
    """64-byte detached signature."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    digest = _sha512(seed)
    a = _clamped_scalar(seed)
    r = _sha512_modq(digest[32:] + message)
    big_r = _mul(r, _B)
    hram = _sha512_modq(_encode(big_r) + publickey(seed) + message)
    s = (r + hram * a) % Q
    return _encode(big_r) + s.to_bytes(32, "little")


def verify(signature: bytes, message: bytes, public: bytes) -> bool:
    """True when ``signature`` is valid for ``message`` under ``public``."""
    try:
        if len(signature) != 64 or len(public) != 32:
            return False
        r_bytes = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= Q:
            return False
        a_point = _decode(public)
        r_point = _decode(r_bytes)
        h = _sha512_modq(r_bytes + public + message)
        return _add(r_point, _mul(h, a_point)) == _mul(s, _B)
    except Exception:
        return False


def seed_from_hex(text: str) -> bytes:
    raw = bytes.fromhex(text.strip())
    if len(raw) != 32:
        raise ValueError("seed hex must be 64 characters")
    return raw
