"""LAN discovery, presence beacon, kit server and lateral spread.

The LAN layer is what turns N independent agents into one graph:
  * discover  -> sweep the local subnet, ARP, NetBIOS/mDNS/SSDP name services
  * beacon    -> UDP presence so peers find each other without a broker
  * KitServer -> tiny HTTP server so a peer can fetch the bundle over LAN
  * spread    -> tier-A pull (peer runs bootstrap) and tier-B push (SMB+schtasks)
"""

from .discover import (
    local_interfaces,
    local_subnets,
    arp_table,
    sweep,
    discover,
    classify,
    same_subnet,
    subnet_hosts,
)
from .beacon import Beacon, KitServer, LanService, start_service

__all__ = [
    "local_interfaces",
    "local_subnets",
    "arp_table",
    "sweep",
    "discover",
    "classify",
    "same_subnet",
    "subnet_hosts",
    "Beacon",
    "KitServer",
    "LanService",
    "start_service",
]
