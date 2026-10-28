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
BUNDLE_FILES = ("agent.py", "bootstrap.py")
BUNDLE_DIRS = ("syspy", "install")

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


def build_zip(root: str, extra: dict[str, bytes] | None = None) -> bytes:
    """Return a zip archive of the deployable agent bundle."""
    buffer = io.BytesIO()
    manifest: dict[str, str] = {}

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, name in _iter_files(root):
            with open(path, "rb") as handle:
                data = handle.read()
            manifest[name] = hashlib.sha256(data).hexdigest()
            archive.writestr(name, data)
        for name, blob in (extra or {}).items():
            manifest[name] = hashlib.sha256(blob).hexdigest()
            archive.writestr(name, blob)
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=1).encode("utf-8"))

    return buffer.getvalue()


def build_zip_from_dir(source: str, names: "Iterable[str]" = ()) -> bytes:
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


def verify_manifest_zip(bundle: "zipfile.ZipFile") -> tuple[bool, str]:
    """Check a zip in memory. Rejects members the manifest does not list, so a
    tampered archive cannot smuggle in a new ``sitecustomize.py``."""
    try:
        raw = bundle.read(MANIFEST_NAME)
    except KeyError:
        return False, "manifest missing"
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except ValueError:
        return False, "manifest unreadable"

    names = {n for n in bundle.namelist() if n != MANIFEST_NAME}
    allowed = set(manifest)
    extra = names - allowed
    if extra:
        return False, "unlisted member: " + sorted(extra)[0]

    for name, expected in manifest.items():
        if name not in names:
            return False, f"missing file: {name}"
        if hashlib.sha256(bundle.read(name)).hexdigest() != expected:
            return False, f"hash mismatch: {name}"
    return True, "ok"


def sha256(data: bytes) -> str:
    """Return the hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()
