"""Tiny in-memory diagnostics: ring log plus command timing.

Cheap enough to update on every dispatch, small enough to ship in a heartbeat.
"""

from __future__ import annotations

import collections
import threading
import time

MAX_EVENTS = 300


class Health:
    """Per-process counters and a bounded event log."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: collections.deque = collections.deque(maxlen=MAX_EVENTS)
        self.started = time.time()
        self.commands = 0
        self.errors = 0
        self.last_command = ""
        self.last_command_at = 0.0
        self.last_error = ""

    # -- writing ---------------------------------------------------------

    def note(self, kind: str, text: str = "") -> None:
        with self._lock:
            self._events.append((time.time(), kind, str(text)[:300]))

    def mark_command(self, line: str) -> None:
        with self._lock:
            self.commands += 1
            self.last_command = str(line)[:200]
            self.last_command_at = time.time()

    def mark_error(self, text: str = "") -> None:
        with self._lock:
            self.errors += 1
            self.last_error = str(text)[:300]
        self.note("error", text)

    # -- reading ---------------------------------------------------------

    def uptime(self) -> float:
        return time.time() - self.started

    def recent(self, limit: int = 60) -> list[dict]:
        with self._lock:
            items = list(self._events)[-limit:]
        return [{"t": round(t, 3), "kind": kind, "text": text}
                for t, kind, text in items]

    def summary(self) -> dict:
        return {
            "uptime": int(self.uptime()),
            "commands": self.commands,
            "errors": self.errors,
            "last_command": self.last_command,
            "last_command_age": (round(time.time() - self.last_command_at, 1)
                                 if self.last_command_at else None),
            "last_error": self.last_error,
            "recent": self.recent(20),
        }
