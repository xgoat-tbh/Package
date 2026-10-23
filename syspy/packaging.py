"""Helpers for turning the source tree into a zip and back again."""

from __future__ import annotations

import hashlib
import io
import json
import os
import zipfile
from typing import Iterable

MANIFEST_NAME = "syspy-manifest.json"

#: Files and folders that make up a deployable agent build.
BUNDLE_FILES = ("agent.py",)
BUNDLE_DIRS = ("syspy",)

SKIP_DIRS = {"__pycache__", ".git", ".idea", ".vscode", "received", "dist"}
SKIP_SUFFIXES = (".pyc", ".pyo")


def _iter_files(root: str) -> Iterable[tuple[str, str]]:
    """Yield ``(absolute_path, archive_name)`` for every bundle file."""
    for name in BUNDLE_FILES:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            yield path, name
    for directory in BUNDLE_DIRS:
        base = os.path.join(root, directory)
        if not os.path.isdir(base):
            continue
        for current, subdirs, filenames in os.walk(base):
            subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
            for filename in filenames:
                if filename.endswith(SKIP_SUFFIXES):
                    continue
                full = os.path.join(current, filename)
                yield full, os.path.relpath(full, root).replace(os.sep, "/")


def build_zip(root: str) -> bytes:
    """Return a zip archive of the deployable agent bundle."""
    buffer = io.BytesIO()
    manifest: dict[str, str] = {}

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, name in _iter_files(root):
            with open(path, "rb") as handle:
                data = handle.read()
            manifest[name] = hashlib.sha256(data).hexdigest()
            archive.writestr(name, data)
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=1).encode("utf-8"))

    return buffer.getvalue()


def verify_manifest(extracted_root: str) -> tuple[bool, str]:
    """Check an extracted bundle against its manifest."""
    manifest_path = os.path.join(extracted_root, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        return False, "manifest missing"
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    for name, expected in manifest.items():
        path = os.path.join(extracted_root, name)
        if not os.path.isfile(path):
            return False, f"missing file: {name}"
        with open(path, "rb") as handle:
            actual = hashlib.sha256(handle.read()).hexdigest()
        if actual != expected:
            return False, f"hash mismatch: {name}"
    return True, "ok"


def sha256(data: bytes) -> str:
    """Return the hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()
