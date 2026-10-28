"""On-demand installation of optional third-party dependencies.

SysPy ships with no dependencies at all.  A couple of features need more than
the standard library though — webcam capture needs OpenCV and NumPy, which
together are around 50 MB of wheels.  Downloading those on every install would
be wasteful when most targets never use the camera.

So the agent installs them the first time a feature actually asks for them,
straight into its own private runtime.  The whole thing is invisible: every
subprocess runs with ``CREATE_NO_WINDOW`` and the only sign anything happened
is a line of text in the dashboard terminal.
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from typing import Callable, Optional

from .. import config, log
from . import runtime

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

PIP_BOOTSTRAP_URL = "https://bootstrap.pypa.io/get-pip.py"
EMBED_URL = ("https://www.python.org/ftp/python/{version}/"
             "python-{version}-embed-amd64.zip")

#: Module name -> pip requirement, tried in order.  Older pins are kept so a
#: brand new interpreter (which the newest wheel may not support yet) still
#: has something to fall back on.
PACKAGES: dict[str, list[str]] = {
    "cv2": [
        "opencv-python-headless",
        "opencv-python-headless<4.10",
    ],
}

#: Embeddable Python builds to try, keyed by ``(major, minor)``.
EMBED_VERSIONS: dict[tuple[int, int], tuple[str, ...]] = {
    (3, 15): ("3.15.0",),
    (3, 14): ("3.14.2", "3.14.1", "3.14.0"),
    (3, 13): ("3.13.9", "3.13.1", "3.13.0"),
    (3, 12): ("3.12.11", "3.12.8", "3.12.7", "3.12.6"),
    (3, 11): ("3.11.11", "3.11.9", "3.11.8"),
    (3, 10): ("3.10.11",),
    (3, 9): ("3.9.13",),
}

_notified: set[str] = set()


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def have(module: str) -> bool:
    """Return ``True`` when ``module`` can be imported right now."""
    try:
        importlib.invalidate_caches()
        importlib.import_module(module)
        return True
    except Exception as error:
        log.get("deps").warning("dependency probe failed: %s", error)
        return False


def ensure(module: str, notify: Optional[Callable[[str], None]] = None) -> tuple[bool, str]:
    """Make ``module`` importable, installing it if that is what it takes.

    Args:
        module: import name, e.g. ``"cv2"``.
        notify: optional callback for progress lines (usually ``agent.reply``).

    Returns:
        ``(ok, detail)``.  ``detail`` is human readable either way.
    """
    if have(module):
        return True, "already available"

    if not getattr(config, "AUTO_INSTALL_DEPS", True):
        return False, "automatic installation is disabled in config"

    requirements = PACKAGES.get(module)
    if not requirements:
        return False, f"no package mapping for '{module}'"

    python = _installer_python(notify, allow_download=True)
    if not python:
        return False, "no usable interpreter to install into"

    _say(notify, f"installing {requirements[0]} - first use only, this takes a minute")

    ok, detail = _ensure_pip(python, notify)
    if not ok:
        return False, f"pip unavailable ({detail})"

    ok, detail = _pip_install(python, requirements, notify)
    if not ok:
        return False, f"install failed ({detail})"

    _extend_sys_path(python)
    importlib.invalidate_caches()

    if have(module):
        return True, "installed"
    return False, "installed but still not importable"


def status() -> str:
    """Human readable report used by the ``deps.status`` command."""
    python = _installer_python(None, allow_download=False)
    lines = [
        f"auto install : {getattr(config, 'AUTO_INSTALL_DEPS', True)}",
        f"frozen       : {bool(getattr(sys, 'frozen', False))}",
        f"installer py : {python or '(none - would be downloaded on demand)'}",
        f"runtime dir  : {runtime.runtime_directory()}",
    ]
    for module, requirements in PACKAGES.items():
        state = "present" if have(module) else "missing"
        lines.append(f"{module:<12} : {state}  (would install {requirements[0]})")
    if python:
        for directory in _site_directories(python):
            lines.append(f"site-packages: {directory}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Interpreter discovery
# --------------------------------------------------------------------------


def _console_variant(python: str) -> str:
    """Prefer ``python.exe`` over ``pythonw.exe`` so output can be captured."""
    if IS_WINDOWS and python.lower().endswith("pythonw.exe"):
        candidate = python[: -len("pythonw.exe")] + "python.exe"
        if os.path.exists(candidate):
            return candidate
    return python


def _installer_python(notify: Optional[Callable[[str], None]],
                      allow_download: bool) -> Optional[str]:
    """Find an interpreter that can host pip packages."""
    # Prefer our private runtime: it survives the user uninstalling Python.
    existing = runtime.private_python()
    if existing and os.path.exists(existing):
        return _console_variant(existing)

    if not getattr(sys, "frozen", False) and os.path.exists(sys.executable):
        return _console_variant(sys.executable)

    if not allow_download:
        return None

    # Frozen build with no interpreter on disk: fetch an embeddable one that
    # matches this process's ABI so its C extensions will load here.
    _say(notify, "fetching a private Python for the camera - one time only")
    return _download_embedded_python(notify)


def _embed_versions() -> tuple[str, ...]:
    """Pick embeddable build strings for this interpreter's ABI."""
    exact = EMBED_VERSIONS.get(sys.version_info[:2])
    if exact:
        return exact
    older = [key for key in EMBED_VERSIONS if key <= sys.version_info[:2]]
    if older:
        return EMBED_VERSIONS[max(older)]
    return EMBED_VERSIONS[max(EMBED_VERSIONS)]


def _download_embedded_python(notify: Optional[Callable[[str], None]]) -> Optional[str]:
    """Download and unpack an embeddable interpreter matching this process."""
    target = runtime.runtime_directory()
    os.makedirs(target, exist_ok=True)
    handle, archive = tempfile.mkstemp(prefix="syspy-embed-", suffix=".zip")
    os.close(handle)

    for version in _embed_versions():
        try:
            _download(EMBED_URL.format(version=version), archive)
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(target)
        except Exception:
            continue

        python = os.path.join(target, "python.exe")
        if not os.path.exists(python):
            python = os.path.join(target, "python")
        if os.path.exists(python):
            _enable_site(python)
            _say(notify, f"private interpreter ready ({version})")
            return python
    return None


# --------------------------------------------------------------------------
# pip bootstrap
# --------------------------------------------------------------------------


def _ensure_pip(python: str, notify: Optional[Callable[[str], None]]) -> tuple[bool, str]:
    """Guarantee that ``python -m pip`` works."""
    code, _ = _run(python, ["-m", "pip", "--version"])
    if code == 0:
        return True, "present"

    # An embeddable interpreter ignores site-packages until we tell it not to.
    _enable_site(python)

    handle, script = tempfile.mkstemp(prefix="syspy-get-pip-", suffix=".py")
    os.close(handle)
    try:
        if not os.path.exists(script) or os.path.getsize(script) < 1024:
            _say(notify, "bootstrapping pip")
            _download(PIP_BOOTSTRAP_URL, script)
    except Exception as error:
        return False, f"cannot download get-pip.py ({error})"

    code, output = _run(python, [script, "--no-warn-script-location",
                                 "--disable-pip-version-check"], timeout=600)
    if code == 0:
        return True, "bootstrapped"
    return False, _last_line(output) or "bootstrap failed"


def _enable_site(python: str) -> None:
    """Turn on ``site`` in an embeddable interpreter's ``._pth`` file.

    Without this, an embeddable Python never looks at ``Lib/site-packages``
    and every install appears to vanish.
    """
    directory = os.path.dirname(os.path.abspath(python))
    try:
        entries = os.listdir(directory)
    except OSError:
        return

    for name in entries:
        if not name.endswith("._pth"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError:
            continue

        cleaned: list[str] = []
        changed = False
        for line in lines:
            compact = line.replace(" ", "").strip()
            if compact == "#importsite":
                cleaned.append("import site")
                changed = True
            else:
                cleaned.append(line)

        if "import site" not in [line.strip() for line in cleaned]:
            cleaned.append("import site")
            changed = True

        lowered = [line.replace("/", "\\").strip().lower() for line in cleaned]
        if "lib\\site-packages" not in lowered:
            cleaned.append("Lib\\site-packages")
            changed = True

        if not changed:
            continue
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(cleaned) + "\n")
        except OSError:
            pass


# --------------------------------------------------------------------------
# pip install
# --------------------------------------------------------------------------


def _pip_install(python: str, requirements: list[str],
                 notify: Optional[Callable[[str], None]]) -> tuple[bool, str]:
    """Install the first requirement that works."""
    base = ["-m", "pip", "install", "--disable-pip-version-check",
            "--no-warn-script-location", "--progress-bar", "off"]

    # --user put packages in %APPDATA%\Python, which _extend_sys_path only
    # patched for the current process - the camera worked once then broke.
    # --target keeps them inside the bundle and survives a restart.
    vendor = os.path.join(runtime.runtime_directory(), "Lib", "site-packages")
    try:
        os.makedirs(vendor, exist_ok=True)
    except OSError:
        vendor = ""
    target = ["--target", vendor] if vendor else []

    last = ""
    for requirement in requirements:
        for extra in (["--only-binary", ":all:"], []):
            code, output = _run_streaming(python, base + extra + target + [requirement],
                                          timeout=config.DEP_INSTALL_TIMEOUT, notify=notify)
            if code == 0:
                return True, "ok"
            last = _last_line(output) or last
    return False, last or "pip returned an error"


# --------------------------------------------------------------------------
# sys.path plumbing
# --------------------------------------------------------------------------


def _site_directories(python: str) -> list[str]:
    """Ask ``python`` where it would put packages."""
    code = ("import json,site;"
            "print(json.dumps(site.getsitepackages()+[site.getusersitepackages()]))")
    status_code, output = _run(python, ["-c", code])
    if status_code != 0:
        return []
    try:
        payload = json.loads(output.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return []
    return [entry for entry in payload if entry]


def _extend_sys_path(python: str) -> None:
    """Make freshly installed packages visible to *this* process."""
    for directory in _site_directories(python):
        if os.path.isdir(directory) and directory not in sys.path:
            sys.path.append(directory)


# --------------------------------------------------------------------------
# Process helpers
# --------------------------------------------------------------------------


def _run(python: str, args: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run ``python args`` and capture everything."""
    try:
        completed = subprocess.run(
            [python] + args, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
        )
        return completed.returncode, (completed.stdout or "") + (completed.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except OSError as error:
        return 1, str(error)


def _run_streaming(python: str, args: list[str], timeout: int,
                   notify: Optional[Callable[[str], None]]) -> tuple[int, str]:
    """Run a command, forwarding interesting output lines to ``notify``."""
    try:
        process = subprocess.Popen(
            [python] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, bufsize=1,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError as error:
        return 1, str(error)

    collected: list[str] = []
    deadline = time.time() + timeout
    assert process.stdout is not None
    for line in iter(process.stdout.readline, ""):
        line = line.rstrip()
        if not line:
            continue
        collected.append(line)
        if notify and line.startswith(("Collecting", "Downloading", "Installing", "Building")):
            notify("  " + line[:110])
        if time.time() > deadline:
            process.kill()
            break
    process.wait()
    return process.returncode, "\n".join(collected)


def _download(url: str, target: str) -> None:
    """Fetch ``url`` to ``target``."""
    request = urllib.request.Request(url, headers={"User-Agent": "SysPy"})
    with urllib.request.urlopen(request, timeout=120) as response:
        with open(target, "wb") as handle:
            handle.write(response.read())


def _last_line(text: str) -> str:
    """Last non-empty line of ``text``."""
    for line in reversed((text or "").splitlines()):
        if line.strip():
            return line.strip()[:180]
    return ""


def _say(notify: Optional[Callable[[str], None]], message: str) -> None:
    """Send a progress line, de-duplicated."""
    if notify is None or message in _notified:
        return
    _notified.add(message)
    try:
        notify(message)
    except Exception:
        pass
