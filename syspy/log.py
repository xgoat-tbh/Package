"""Structured logging with an in-memory ring buffer.

Everything used to be ``except Exception: pass``. This gives every subsystem a
logger, keeps the last 2000 records for ``log.tail``/``/api/logs``, and writes a
rotating file so a failure survives the process.

Stdlib only, like the rest of the project.
"""

from __future__ import annotations

import collections
import logging
import logging.handlers
import os
import sys
import threading
import time
import traceback

RING: collections.deque = collections.deque(maxlen=2000)
_counter = collections.Counter()
_lock = threading.Lock()
_ready = False

LEVELS = {
    "debug": logging.DEBUG, "info": logging.INFO,
    "warning": logging.WARNING, "error": logging.ERROR, "critical": logging.CRITICAL,
}


class RingHandler(logging.Handler):
    """Keep recent records in memory and count them by level."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
        except Exception:
            message = "<unformattable>"
        with _lock:
            RING.append({
                "ts": record.created,
                "level": record.levelname,
                "src": record.name,
                "msg": message,
                "exc": (self.format(record) if record.exc_info else ""),
            })
            if record.levelno >= logging.WARNING:
                _counter[record.levelname] += 1


def setup(directory: str = "", tag: str = "agent", level: int = logging.INFO) -> None:
    """Install the handlers once."""
    global _ready
    root = logging.getLogger("syspy")
    root.setLevel(level)
    root.propagate = False
    if _ready:
        return
    _ready = True
    root.addHandler(RingHandler())

    if not directory:
        return
    try:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"{tag}.log")
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=1_048_576, backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        root.addHandler(handler)
    except OSError:
        pass

    def _hook(exc_type, exc, tb):
        logging.getLogger("syspy.unhandled").error(
            "".join(traceback.format_exception(exc_type, exc, tb)))

    sys.excepthook = _hook
    threading.excepthook = lambda args: _hook(
        args.exc_type, args.exc_value, args.exc_traceback)


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"syspy.{name}")


def set_level(name: str) -> str:
    value = LEVELS.get((name or "").lower())
    if value is None:
        return "usage: log.level <debug|info|warning|error>"
    logging.getLogger("syspy").setLevel(value)
    return f"log level -> {name.upper()}"


def tail(count: int = 200, minimum: int = 0) -> list[dict]:
    with _lock:
        rows = [r for r in RING if r["level"] in ("WARNING", "ERROR", "CRITICAL")
                or minimum == 0]
        return rows[-max(1, min(count, 2000)):]


def counters() -> dict:
    with _lock:
        return dict(_counter)


def dump(count: int = 2000) -> str:
    lines = []
    for row in tail(count):
        stamp = time.strftime("%H:%M:%S", time.localtime(row["ts"]))
        lines.append(f"{stamp} {row['level']:<7} {row['src']}: {row['msg']}")
        if row["exc"]:
            lines.append(row["exc"])
    return "\n".join(lines) or "(log empty)"


def clear() -> str:
    with _lock:
        RING.clear()
        _counter.clear()
    return "log cleared"
