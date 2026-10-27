"""Subnet discovery that needs nothing but the stdlib.

Everything here is best-effort and must never raise: a missing ARP table or a
blocked ICMP echo is normal, not an error.
"""
from __future__ import annotations

import ctypes
import ipaddress
import os
import re
import socket
import struct
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Fast phase then slow phase, so a /24 costs ~2s instead of ~15s.
FAST_PORTS = (445, 135, 22, 80)
SLOW_PORTS = (139, 3389, 5985, 5900, 443, 8006, 21, 23, 3306, 5432, 8080)
MAX_HOSTS = 1024
_LOCK = threading.Lock()
_CACHE: dict = {"at": 0.0, "data": {}}
_CACHE_TTL = 20.0


# ---------------------------------------------------------------- interfaces

class _SOCKADDR(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_byte * 26)]


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [
        ("lpSockaddr", ctypes.POINTER(_SOCKADDR)),
        ("iSockaddrLength", ctypes.c_int),
    ]


class _UNICAST(ctypes.Structure):
    pass


_UNICAST._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_UNICAST)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", ctypes.c_ulong),
    ("PreferredLifetime", ctypes.c_ulong),
    ("LeaseLifetime", ctypes.c_ulong),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class _ADAPTER(ctypes.Structure):
    pass


_ADAPTER._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", ctypes.POINTER(_ADAPTER)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_UNICAST)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Mtu", ctypes.c_ulong),
    ("IfType", ctypes.c_ulong),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", ctypes.c_ulong),
    ("ZoneIndices", ctypes.c_ulong * 16),
    ("FirstPrefix", ctypes.c_void_p),
]

_IF_TYPE_SOFTWARE_LOOPBACK = 24
_IF_OPER_STATUS_UP = 1
_GAA_FLAGS = 0x0E  # skip anycast | multicast | dns servers


def _windows_interfaces() -> list:
    out = []
    try:
        getter = ctypes.windll.iphlpapi.GetAdaptersAddresses
    except Exception:
        return out
    getter.argtypes = [
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.POINTER(_ADAPTER),
        ctypes.POINTER(ctypes.c_ulong),
    ]
    size = ctypes.c_ulong(16 * 1024)
    buf = ctypes.create_string_buffer(size.value)
    for _ in range(4):
        ret = getter(socket.AF_UNSPEC, _GAA_FLAGS, None,
                     ctypes.cast(buf, ctypes.POINTER(_ADAPTER)), ctypes.byref(size))
        if ret == 0:
            break
        if ret != 111:  # ERROR_BUFFER_OVERFLOW
            return out
        buf = ctypes.create_string_buffer(size.value)
    else:
        return out

    node = ctypes.cast(buf, ctypes.POINTER(_ADAPTER))
    while node:
        ad = node.contents
        node = ad.Next
        if ad.IfType == _IF_TYPE_SOFTWARE_LOOPBACK or ad.OperStatus != _IF_OPER_STATUS_UP:
            continue
        mac = ":".join("%02X" % ad.PhysicalAddress[i]
                       for i in range(min(ad.PhysicalAddressLength, 6)))
        uni = ad.FirstUnicastAddress
        while uni:
            sa = uni.contents.Address.lpSockaddr
            if sa:
                family = sa.contents.sa_family
                raw = bytes(sa.contents.sa_data)
                try:
                    if family == socket.AF_INET:
                        ip = socket.inet_ntoa(raw[2:6])
                        prefix = uni.contents.OnLinkPrefixLength
                    elif family == socket.AF_INET6:
                        ip = socket.inet_ntop(socket.AF_INET6, raw[4:20])
                        prefix = uni.contents.OnLinkPrefixLength
                    else:
                        uni = uni.contents.Next
                        continue
                except Exception:
                    uni = uni.contents.Next
                    continue
                if ip.startswith("169.254.") or ip.lower().startswith("fe80"):
                    uni = uni.contents.Next
                    continue
                out.append({
                    "ip": ip,
                    "prefix": int(prefix or 24),
                    "family": "inet6" if family == socket.AF_INET6 else "inet",
                    "name": (ad.FriendlyName or "").strip(),
                    "mac": mac,
                    "ifindex": int(ad.IfIndex),
                })
            uni = uni.contents.Next
    # Prefer IPv4 per adapter: IPv6-only entries just duplicate the host.
    v4_ifaces = {a["ifindex"] for a in out if a["family"] == "inet"}
    return [a for a in out if a["family"] == " inet" or a["ifindex"] not in v4_ifaces]


def _posix_interfaces() -> list:
    out = []
    try:
        import fcntl
    except Exception:
        fcntl = None
    try:
        names = socket.if_nameindex()
    except Exception:
        names = []
    for _idx, name in names:
        if name == "lo":
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packed = struct.pack("256s", name[:15].encode())
            ip = socket.inet_ntoa(fcntl.ioctl(sock, 0x8915, packed)[20:24])  # SIOCGIFADDR
            mask = socket.inet_ntoa(fcntl.ioctl(sock, 0x891B, packed)[20:24])  # SIOCGIFNETMASK
            sock.close()
        except Exception:
            continue
        if ip.startswith("169.254."):
            continue
        try:
            prefix = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
        except Exception:
            prefix = 24
        out.append({"ip": ip, "prefix": prefix, "family": "inet", "name": name,
                    "mac": "", "ifindex": _idx})
    return out


def local_interfaces() -> list:
    """Up interfaces with an address, loopback and APIPA removed."""
    try:
        result = _windows_interfaces() if IS_WINDOWS else _posix_interfaces()
    except Exception:
        result = []
    if result:
        return result
    # Last resort: resolve our own hostname.
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith(("127.", "169.254.")):
                result.append({"ip": ip, "prefix": 24, "family": "inet",
                               "name": "hostname", "mac": "", "ifindex": 0})
    except Exception:
        pass
    return result


def local_subnets() -> list:
    """[(network_string, interface_dict), ...] for every usable interface."""
    seen, out = set(), []
    for iface in local_interfaces():
        try:
            net = ipaddress.ip_network("%s/%s" % (iface["ip"], iface["prefix"]), strict=False)
        except Exception:
            continue
        key = str(net)
        if key in seen:
            continue
        seen.add(key)
        out.append((key, iface))
    return out


def local_subnet() -> str:
    nets = local_subnets()
    if not nets:
        return ""
    # Prefer a private /24-ish network, that's the office LAN.
    for key, _iface in nets:
        if ipaddress.ip_network(key).num_addresses <= 1024:
            return key
    return nets[0][0]


def subnet_hosts(network: str, limit: int = MAX_HOSTS):
    net = ipaddress.ip_network(network, strict=False)
    if net.num_addresses > limit + 2:
        net = ipaddress.ip_network(
            "%s/%s" % (str(net.network_address), max(24, 32 - (limit.bit_length() - 1))),
            strict=False,
        )
    for host in net.hosts():
        yield str(host)


def same_subnet(ip: str, network: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
    except Exception:
        return False


# ----------------------------------------------------------------------- ARP

_ARP_WIN = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)", re.M)
_ARP_NIX = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})")


def arp_table() -> dict:
    """{ip: {"mac":.., "state":..}} from the OS neighbour cache (free, no packets)."""
    out = {}
    try:
        if IS_WINDOWS:
            raw = subprocess.run(["arp", "-a"], capture_output=True, timeout=8,
                                 creationflags=CREATE_NO_WINDOW).stdout
        elif os.path.exists("/proc/net/arp"):
            raw = open("/proc/net/arp", "rb").read()
        else:
            raw = subprocess.run(["arp", "-an"], capture_output=True, timeout=8).stdout
        text = raw.decode("utf-8", "replace")
        if IS_WINDOWS:
            for ip, mac, state in _ARP_WIN.findall(text):
                if mac.replace("-", "").lower() == "ffffffffffff":
                    continue
                out[ip] = {"mac": mac.replace("-", ":").upper(), "state": state}
        else:
            for ip, mac in _ARP_NIX.findall(text):
                if mac == "00:00:00:00:00:00":
                    continue
                out[ip] = {"mac": mac.upper(), "state": "REACHABLE"}
    except Exception:
        pass
    return out


# -------------------------------------------------------------------- probing

def probe(ip: str, ports, timeout: float = 0.35) -> list:
    open_ports = []
    for port in ports:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return open_ports


def sweep(hosts, ports=FAST_PORTS, workers: int = 128, timeout: float = 0.35) -> dict:
    hosts = [h for h in hosts]
    found = {}
    if not hosts:
        return found
    with ThreadPoolExecutor(max_workers=max(4, min(workers, len(hosts) * 2))) as pool:
        futures = {pool.submit(probe, ip, ports, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                ports_open = fut.result()
            except Exception:
                ports_open = []
            if ports_open:
                found[ip] = ports_open
    return found


def classify(ports) -> str:
    ports = set(ports or ())
    if 445 in ports and (135 in ports or 139 in ports):
        return "windows"
    if 3389 in ports or 5985 in ports:
        return "windows"
    if 22 in ports:
        return "linux"
    if 80 in ports or 443 in ports:
        return "router" if (53 in ports or 23 in ports) else "http"
    if 5900 in ports or 8006 in ports:
        return "hypervisor"
    if ports:
        return "unknown"
    return "idle"

# ------------------------------------------------------------- name services

def netbios_name(ip: str, timeout: float = 0.6) -> str:
    """NBSTAT node-status query on UDP/137 -> the Windows machine name."""
    packet = bytearray(b"\xAA\xAA\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                       b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(bytes(packet), (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) < 57:
            return ""
        count = data[56]
        if not count:
            return ""
        name = data[57:72].decode("ascii", "replace").strip()
        return re.sub(r"[^ -~]", "", name)
    except Exception:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def mdns_lookup(timeout: float = 1.2) -> dict:
    """Reverse mDNS: ask 224.0.0.251 for services and harvest A records."""
    out = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        query = (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")
        sock.sendto(query, ("224.0.0.251", 5353))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                break
            ip = addr[0]
            # Harvest any printable label that looks like a hostname.
            labels = re.findall(rb"[A-Za-z0-9][A-Za-z0-9-]{2,30}", data)
            for label in labels:
                text = label.decode("ascii", "replace")
                if text in ("local", "services", "dns-sd", "udp", "tcp", "_tcp", "_udp"):
                    continue
                if text[0].isupper() or "-" in text:
                    out.setdefault(ip, text)
    except Exception:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return out


def ssdp_lookup(timeout: float = 1.2) -> dict:
    """SSDP M-SEARCH: routers/NAS/printers announce themselves (and their model)."""
    out = {}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").encode()
        sock.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode("utf-8", "replace")
            server = ""
            for line in text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break
            out.setdefault(addr[0], server)
    except Exception:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return out


# ----------------------------------------------------------------- discovery

def discover(timeout: float = 3.0, force: bool = False) -> dict:
    """Full sweep of every local subnet. Returns {ip: record}."""
    with _LOCK:
        if not force and (time.time() - _CACHE["at"]) < _CACHE_TTL and _CACHE["data"]:
            return dict(_CACHE["data"])

    nets = local_subnets()
    hosts = []
    mine = set()
    for net, iface in nets:
        mine.add(iface["ip"])
        for host in subnet_hosts(net, limit=MAX_HOSTS):
            if host not in hosts:
                hosts.append(host)
    if len(hosts) > MAX_HOSTS:
        hosts = hosts[:MAX_HOSTS]

    records: dict = {}
    for ip, info in arp_table().items():
        if any(same_subnet(ip, net) for net, _ in nets):
            records[ip] = {"ip": ip, "mac": info["mac"], "ports": [],
                           "hostname": "", "kind": "idle", "source": "arp"}

    # Phase 1: cheap port sweep.
    for ip, ports in sweep(hosts, FAST_PORTS, workers=128, timeout=0.35).items():
        rec = records.setdefault(ip, {"ip": ip, "mac": "", "ports": [],
                                      "hostname": "", "kind": "", "source": "tcp"})
        rec["ports"] = sorted(set(rec["ports"]) | set(ports))
        rec["source"] = "tcp"

    # Phase 2: deeper ports only on hosts that answered.
    live = [ip for ip in records if ip not in mine]
    for ip, ports in sweep(live, SLOW_PORTS, workers=64, timeout=0.3).items():
        records[ip]["ports"] = sorted(set(records[ip]["ports"]) | set(ports))

    # Phase 3: names (cheap, only for live hosts).
    for ip, name in mdns_lookup(timeout=min(1.5, timeout)).items():
        records.setdefault(ip, {"ip": ip, "mac": "", "ports": [], "hostname": "",
                                "kind": "", "source": "mdns"})["hostname"] = name
    for ip, banner in ssdp_lookup(timeout=min(1.5, timeout)).items():
        rec = records.setdefault(ip, {"ip": ip, "mac": "", "ports": [], "hostname": "",
                                      "kind": "", "source": "ssdp"})
        if banner and not rec.get("hostname"):
            rec["hostname"] = banner[:60]

    for ip in list(records):
        if IS_WINDOWS and not records[ip].get("hostname"):
            name = netbios_name(ip)
            if name:
                records[ip]["hostname"] = name

    for ip, rec in records.items():
        rec["kind"] = classify(rec.get("ports"))
        rec["is_self"] = ip in mine
        rec["subnet"] = next((net for net, _ in nets if same_subnet(ip, net)), "")

    with _LOCK:
        _CACHE["at"] = time.time()
        _CACHE["data"] = dict(records)
    return records
