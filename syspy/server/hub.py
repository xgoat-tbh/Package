"""Agent registry and dashboard event bus.

The hub is the single source of truth for "what is connected".  Both the MQTT
listener and the HTTP API talk to it; nothing else holds agent state.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import queue
import re
import threading
import time
from typing import Any
from urllib.parse import quote

from .. import config, crypto, log, protocol


from ..mqtt import MqttClient, random_client_id


def _sign(payload: bytes) -> str:
    """Detached signature for an update archive.

    Ed25519 when SYSPY_SIGN_KEY is set, otherwise an HMAC the agent can verify
    with material it already has. Empty when neither is configured.
    """
    if config.SIGN_KEY_HEX:
        try:
            from .. import ed25519
            return ed25519.sign(payload, bytes.fromhex(config.SIGN_KEY_HEX)).hex()
        except Exception:
            pass
    if config.ROOM and config.PASSPHRASE:
        return crypto.hmac_hex(crypto.kit_hmac_key(config.ROOM, config.PASSPHRASE), payload)
    return ""


def safe_name(value: str) -> str:
    """Filesystem-safe version of a display name."""
    return re.sub(r"[^A-Za-z0-9._ -]", "_", str(value))[:60] or "agent"


class AgentSession:
    """Everything the controller knows about one connected agent."""

    def __init__(self, agent_id: str, name: str, remote_id: str) -> None:
        self.id = agent_id
        self.remote_id = remote_id          # value used in the MQTT topic
        self.name = name
        self.nick = ""
        self.version = "?"
        self.sha = ""
        self.path = ""
        self.pid = 0
        self.info: dict[str, Any] = {}
        self.admin = False
        self.persistence: dict[str, Any] = {}
        self.stats: dict[str, Any] = {}
        self.last_seen = time.time()
        self.connected_at = time.time()
        self.link_ok = False
        self.online = True

        self.fmt = 2          # envelope format the agent last declared (default to v2)
        self.proto = 1
        self.build = ""
        self.session = -1
        self.folder = ""
        self.use_master_key = False
        self.parent = ""
        self.hop = 0
        self.parent_ip = ""
        self.mac = ""
        self.subnet = ""
        self.group = ""
        self.kit_sha = ""
        self.health: dict[str, Any] = {}

    @property
    def display(self) -> str:
        return self.nick or self.name

    def touch(self) -> None:
        self.last_seen = time.time()
        self.online = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "remote_id": self.remote_id,
            "name": self.name,
            "nick": self.nick,
            "display": self.display,
            "version": self.version,
            "build": self.build,
            "proto": self.proto,
            "fmt": self.fmt,
            "session": self.session,
            "sha": self.sha,
            "path": self.path,
            "pid": self.pid,
            "info": self.info,
            "admin": self.admin,
            "stats": self.stats,
            "last_seen": self.last_seen,
            "connected_at": self.connected_at,
            "link_ok": self.link_ok,
            "persistence": self.persistence,
            "online": self.online,
            "parent": self.parent,
            "hop": self.hop,
            "parent_ip": self.parent_ip,
            "mac": self.mac,
            "subnet": self.subnet,
            "group": self.group,
            "health": self.health,
            "kit_sha": getattr(self, "kit_sha", ""),
            "use_master_key": getattr(self, "use_master_key", False),
        }


class Hub:
    """Holds agents, moves messages, publishes dashboard events."""

    def __init__(self, key: bytes, received_root: str, db_path: str = "") -> None:
        self.key = key
        self.codec = protocol.Codec(key)
        self.codecs: dict[str, protocol.Codec] = {}
        self.agents: dict[str, AgentSession] = {}
        self.reassembler = protocol.Reassembler()
        self.received_root = os.path.abspath(received_root)
        self.db_path = db_path or os.path.join(self.received_root, "..", "agents_db.json")
        self._subscribers: list[queue.Queue[str]] = []
        self._folders: dict[str, str] = {}
        self._master_key_agents: set[str] = set()
        self._lock = threading.Lock()
        self._client: MqttClient | None = None
        self.relay_up = False
        self._running = True
        self._dirty = False
        self._outbox: list[tuple[str, dict[str, Any]]] = []
        self._roster_sent: dict[str, float] = {}
        self.seq = 0
        self._fallback_warned: set[str] = set()
        self.counters = collections.Counter(
            {"decrypt_fail": 0, "master_key_fallback": 0, "publish_timeout": 0,
             "publish_error": 0, "outbox_overflow": 0, "ws_drop": 0,
             "replay_dropped": 0, "id_mismatch": 0, "proto_mismatch": 0})

        self._load_db()
        threading.Thread(target=self._flush_db_loop, name="hub-db-flush", daemon=True).start()

    def codec_for(self, identifier: str, fmt: int = 2) -> protocol.Codec:
        """Per-agent, per-format Codec derived via crypto.subkey, cached.

        The key is the same either way; only the envelope differs. That is what
        lets a patched controller talk v2 to a patched agent and v1 to an old
        one with no flag day.
        """
        ident = identifier[6:] if identifier.startswith("agent:") else identifier
        key = (ident, fmt)
        if key not in self.codecs:
            sub = crypto.subkey(self.key, ident)
            self.codecs[key] = protocol.Codec(sub, fmt=fmt)
        return self.codecs[key]

    def _flush_db_loop(self) -> None:
        while self._running:
            time.sleep(5)
            if self._dirty:
                self._dirty = False
                self._save_db()

    def _load_db(self) -> None:
        """Load known agents from local JSON database on controller start."""
        if os.path.isfile(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        agent_id = item.get("id")
                        if not agent_id:
                            continue
                        session = AgentSession(agent_id, item.get("name", "agent"), item.get("remote_id", ""))
                        session.nick = item.get("nick", "")
                        session.version = item.get("version", "?")
                        session.proto = int(item.get("proto") or 1)
                        session.fmt = int(item.get("fmt") or 2)
                        if session.proto < 2 or session.version == "5.1.1":
                            session.use_master_key = True
                            if session.remote_id:
                                self._master_key_agents.add(session.remote_id)
                        session.sha = item.get("sha", "")
                        session.path = item.get("path", "")
                        session.pid = item.get("pid", 0)
                        session.info = item.get("info", {})
                        session.admin = item.get("admin", False)
                        session.persistence = item.get("persistence", {})
                        session.stats = item.get("stats", {})
                        session.last_seen = item.get("last_seen", 0)
                        session.connected_at = item.get("connected_at", 0)
                        session.link_ok = False
                        session.online = False
                        session.parent = item.get("parent", "")
                        session.hop = int(item.get("hop") or 0)
                        session.parent_ip = item.get("parent_ip", "")
                        session.mac = item.get("mac", "")
                        session.subnet = item.get("subnet", "")
                        session.group = item.get("group", "")
                        session.kit_sha = item.get("kit_sha", "")
                        session.health = item.get("health", {})
                        self.agents[agent_id] = session
            except Exception:
                pass

    def _save_db(self) -> None:
        """Persist registered agents to disk so offline agents are never lost."""
        try:
            items = [a.to_dict() for a in self.agents.values()]
            tmp_path = self.db_path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(items, f, indent=2)
            os.replace(tmp_path, self.db_path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def agent_folder(self, agent_id: str) -> str:
        """Folder where this agent's received files live.

        Cached on first use so the URL is stable: it used to be derived from the
        display name while the session existed and from the raw id after the
        agent was deleted, so every previously received file 404'd.
        """
        with self._lock:
            cached = self._folders.get(agent_id)
            if cached:
                os.makedirs(cached, exist_ok=True)
                return cached
            agent = self.agents.get(agent_id)
            leaf = safe_name(agent.name) if agent else safe_name(agent_id)
            folder = os.path.join(self.received_root, leaf)
            self._folders[agent_id] = folder
        os.makedirs(folder, exist_ok=True)
        return folder

    # ------------------------------------------------------------------
    # Event bus
    # ------------------------------------------------------------------

    def subscribe(self) -> queue.Queue[str]:
        """Register a dashboard listener."""
        channel: queue.Queue[str] = queue.Queue(maxsize=2048)
        with self._lock:
            self._subscribers.append(channel)
        return channel

    def unsubscribe(self, channel: queue.Queue[str]) -> None:
        with self._lock:
            if channel in self._subscribers:
                self._subscribers.remove(channel)

    def publish(self, event: dict[str, Any]) -> None:
        """Fan an event out to every dashboard listener, with a sequence number."""
        with self._lock:
            self.seq += 1
            event = {**event, "seq": self.seq}
            targets = list(self._subscribers)
        payload = json.dumps(event, default=str)
        for channel in targets:
            try:
                channel.put_nowait(payload)
            except queue.Full:
                # Was a silent desync: the counter existed and was never bumped.
                self.counters["ws_drop"] += 1
                try:
                    channel.get_nowait()
                    channel.put_nowait(payload)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def get(self, agent_id: str) -> AgentSession | None:
        with self._lock:
            return self.agents.get(agent_id)

    def all(self) -> list[AgentSession]:
        with self._lock:
            return list(self.agents.values())

    def rename(self, agent_id: str, nick: str) -> bool:
        with self._lock:
            agent = self.agents.get(agent_id)
            if not agent:
                return False
            agent.nick = nick
            self._dirty = True
            data = agent.to_dict()
        self.publish({"type": "agent", "agent": data})
        return True

    def rename_many(self, targets: list[str], pattern: str) -> None:
        with self._lock:
            for idx, agent_id in enumerate(targets, start=1):
                agent = self.agents.get(agent_id)
                if not agent:
                    continue
                nick = pattern.replace("{n}", str(idx)).replace("{host}", agent.name)
                agent.nick = nick
                self.publish({"type": "agent", "agent": agent.to_dict()})
            self._dirty = True

    def set_group(self, agent_id: str, group: str) -> bool:
        with self._lock:
            agent = self.agents.get(agent_id)
            if not agent:
                return False
            agent.group = group
            self._dirty = True
            data = agent.to_dict()
        self.publish({"type": "agent", "agent": data})
        return True

    def delete(self, agent_id: str) -> bool:
        """Explicitly delete an uninstalled / stale agent from the dashboard."""
        with self._lock:
            if agent_id in self.agents:
                del self.agents[agent_id]
                self._dirty = True
            else:
                return False
        self.publish({"type": "agent_deleted", "id": agent_id})
        return True

    def forget_stale(self, timeout: float = config.AGENT_TIMEOUT) -> list[str]:
        """Mark agents that stopped reporting as offline rather than deleting them."""
        now = time.time()
        went_offline = []
        with self._lock:
            agent_items = list(self.agents.items())
        for agent_id, agent in agent_items:
            if agent.online and (now - agent.last_seen > timeout):
                agent.online = False
                agent.link_ok = False
                went_offline.append(agent_id)
                self.publish({"type": "agent_offline", "id": agent_id, "agent": agent.to_dict()})
        if went_offline:
            with self._lock:
                self._dirty = True
        return went_offline

    def resolve_targets(self, spec: Any) -> list[str]:
        if isinstance(spec, list):
            return [a for a in spec if a in self.agents]
        if spec == "online":
            return [a.id for a in self.all() if a.online]
        if spec == "all":
            # "all" targets ONLINE agents only — pushing to a stale offline
            # entry would silently queue and never deliver.
            return [a.id for a in self.all() if a.online]
        if isinstance(spec, str) and spec.startswith("group:"):
            want = spec.split(":", 1)[1]
            return [a.id for a in self.all() if a.group == want]
        # A specific agent id — include even if offline (caller's choice).
        if isinstance(spec, str) and spec in self.agents:
            return [spec]
        return [a.id for a in self.all() if a.online]

    def tree(self) -> list[dict[str, Any]]:
        nodes = {a.id: {**a.to_dict(), "children": []} for a in self.all()}
        roots = []
        for node in nodes.values():
            parent_id = "agent:" + node.get("parent", "")
            parent = nodes.get(parent_id)
            (parent["children"] if parent and parent is not node else roots).append(node)
        return roots

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    def send(self, agent_id: str, message: dict[str, Any]) -> str:
        """Send or queue message for agent. Returns 'sent', 'queued', or 'missing'."""
        agent = self.agents.get(agent_id)
        if not agent:
            return "missing"
        if not self._client or not self._client.alive:
            self._enqueue(agent_id, message)
            return "queued"
        try:
            is_legacy = (agent.remote_id in self._master_key_agents
                         or getattr(agent, "use_master_key", False)
                         or (agent.proto or 1) < 2
                         or agent.version == "5.1.1")
            if is_legacy:
                codec = protocol.Codec(self.key, fmt=1)
            else:
                codec = self.codec_for(agent.remote_id, agent.fmt or 2)
            payload = codec.encode(message)
            topic = config.topic_down(agent.remote_id)
            self._client.publish(topic, payload, qos=1)
            return "sent"
        except Exception as error:
            self.counters["publish_error"] += 1
            log.get("hub").warning("publish failed for %s: %s", agent_id, error)
            self._enqueue(agent_id, message)
            return "queued"

    def _enqueue(self, agent_id: str, message: dict[str, Any]) -> None:
        self._outbox.append((agent_id, message))
        if len(self._outbox) > 5000:
            self._outbox = self._outbox[-5000:]
            self.counters["outbox_overflow"] += 1

    def counters_snapshot(self) -> dict:
        return dict(self.counters) | {"seq": self.seq, "live_transfers": self.reassembler.live()}

    def flush_outbox(self) -> int:
        if not self._client or not self._client.alive or not self._outbox:
            return 0
        # Send from a copy and only clear what actually left, so an exception
        # mid-loop cannot drop the remainder.
        flushed = 0
        pending = list(self._outbox)
        for index, (agent_id, message) in enumerate(pending):
            if self.send(agent_id, message) == "sent":
                flushed += 1
            else:
                self._outbox = pending[index:]
                return flushed
        self._outbox = []
        return flushed

    def broadcast(self, message: dict[str, Any]) -> int:
        """Send a message to every connected agent."""
        return sum(1 for agent_id in list(self.agents) if self.send(agent_id, message) == "sent")

    def send_chunks(self, agent_id: str, kind: str, payload: bytes,
                    filename: str = "", destination: str = "") -> dict[str, Any]:
        """Send a chunked payload, returning a summary dict."""
        transfer = os.urandom(4).hex()
        parts = protocol.chunk(payload, transfer)
        digest = hashlib.sha256(payload).hexdigest()
        sent_count = 0
        for index, part in enumerate(parts):
            message: dict[str, Any] = {"t": kind, "name": filename,
                                       "dest": destination, **part}
            if kind == "update":
                message["sha"] = digest
                message["proto"] = config.PROTOCOL_VERSION
                signature = _sign(payload)
                if signature:
                    message["sig"] = signature
            status = self.send(agent_id, message)
            if status == "sent":
                sent_count += 1
            time.sleep(0.005)
        return {
            "chunks": len(parts),
            "status": "sent" if sent_count == len(parts) else "queued"
        }

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------

    def _on_message(self, topic: str, payload: bytes) -> None:
        # The topic segment is authoritative. The payload id is advisory.
        remote_id = topic.rsplit("/", 1)[-1]
        agent_id = "agent:" + remote_id

        known = self.agents.get(agent_id)
        fmts = [known.fmt if known else 2]
        if 1 not in fmts:
            fmts.append(1)

        message = None
        for fmt in fmts:
            message, reason = self.codec_for(remote_id, fmt).decode_message(payload)
            if reason == protocol.REASON_REPLAY:
                self.counters["replay_dropped"] += 1
                return
            if reason == protocol.REASON_OK:
                self._master_key_agents.discard(remote_id)
                if known:
                    known.use_master_key = False
                break
        if message is None:
            # Always try master-key fallback. An agent installed before the
            # per-agent subkey wiring may already have declared fmt=2 (from an
            # old hello that got stored), but still encodes with the master key
            # because it hasn't been updated yet. Dropping it silently would
            # make all commands invisible in the dashboard. Once the agent is
            # pushed the updated kit it will move to subkeys and fallback stops.
            try:
                message = self.codec.decode(payload)
                self.counters["master_key_fallback"] += 1
                self._master_key_agents.add(remote_id)
                if known:
                    known.use_master_key = True
                if remote_id not in self._fallback_warned:
                    self._fallback_warned.add(remote_id)
                    log.get("hub").warning(
                        "agent %s decoded with the master key (pre-update agent)",
                        remote_id)
            except Exception:
                self.counters["decrypt_fail"] += 1
                return

        if message.get("t") == "hello":
            self._register(agent_id, remote_id, message)
            return

        agent = self.agents.get(agent_id)
        if not agent:
            return
        agent.touch()

        kind = message.get("t")
        if kind == "bye":
            agent.online = False
            agent.link_ok = False
            self.publish({"type": "agent_offline", "id": agent_id, "agent": agent.to_dict()})
            self._dirty = True
            return
        elif kind == "out":
            if not agent.link_ok:
                agent.link_ok = True
                self.publish({"type": "link", "id": agent_id, "ok": True})
            self.publish({"type": "output", "id": agent_id, "text": message.get("d", "")})
        elif kind == "json":
            self.publish({"type": "json", "id": agent_id, "payload": message})
        elif kind == "evt":
            if message.get("k") == "stat":
                agent.stats = message
                self.publish({"type": "stats", "id": agent_id, "stats": message})
        elif kind == "keys":
            self.publish({"type": "keys", "id": agent_id, "text": message.get("d", "")})
        elif kind == "note":
            self.publish({"type": "note", "id": agent_id, "text": message.get("d", "")})
        elif kind == "progress":
            self.publish({"type": "progress", "id": agent_id, "text": message.get("d", "")})
        elif kind == "file":
            self._store_file(agent, message)

    def _register(self, agent_id: str, remote_id: str, message: dict[str, Any]) -> None:
        with self._lock:
            agent = self.agents.get(agent_id)
            if agent is None:
                agent = AgentSession(agent_id, message.get("name", remote_id), remote_id)
                self.agents[agent_id] = agent
                is_new = True
            else:
                is_new = False

        agent.touch()
        # Topic wins. The payload id is advisory and a mismatch used to silently
        # re-point both the codec and the downlink topic at the claimed id.
        claimed = str(message.get("id") or "")
        if claimed and claimed != remote_id:
            self.counters["id_mismatch"] += 1
            if agent_id not in self._fallback_warned:
                self._fallback_warned.add(agent_id)
                log.get("hub").warning(
                    "agent on topic %s claims id %s (topic wins)", remote_id, claimed)
        agent.remote_id = remote_id
        try:
            agent.fmt = int(message.get("fmt") or agent.fmt or 2)
        except (TypeError, ValueError):
            pass
        agent.proto = int(message.get("proto") or agent.proto or 1)
        if agent.proto > config.PROTOCOL_VERSION:
            self.counters["proto_mismatch"] += 1
        agent.build = str(message.get("build") or agent.build)
        try:
            agent.session = int(message.get("session", agent.session))
        except (TypeError, ValueError):
            pass
        agent.version = message.get("ver", agent.version)
        if agent.proto >= 2 and agent.version != "5.1.1":
            # Modern agent — always use subkeys; clear any stale legacy flag
            # so commands are not accidentally encrypted with the master key.
            self._master_key_agents.discard(remote_id)
            agent.use_master_key = False
        elif agent.proto < 2 or agent.version == "5.1.1":
            agent.use_master_key = True
            self._master_key_agents.add(remote_id)
        agent.sha = message.get("sha", agent.sha)
        agent.path = message.get("path", agent.path)
        agent.pid = message.get("pid", agent.pid)
        agent.info = message.get("info", agent.info)
        agent.admin = bool(message.get("admin", agent.admin))
        agent.persistence = message.get("persistence", agent.persistence)
        agent.parent = message.get("parent", agent.parent)
        agent.hop = int(message.get("hop") or 0)
        agent.parent_ip = message.get("parent_ip", agent.parent_ip)
        agent.mac = message.get("mac", agent.mac)
        agent.subnet = message.get("subnet", agent.subnet)
        agent.group = message.get("group", agent.group)
        agent.kit_sha = message.get("kit_sha", getattr(agent, "kit_sha", ""))
        agent.health = message.get("health", agent.health)
        self._dirty = True

        if is_new:
            self.publish({"type": "agent_new", "agent": agent.to_dict()})
            threading.Timer(1.5, self._probe, args=(agent_id,)).start()
        else:
            self.publish({"type": "agent", "agent": agent.to_dict()})
        self._maybe_send_roster(agent.remote_id)

    def _maybe_send_roster(self, agent_id: str) -> None:
        now = time.time()
        if now - self._roster_sent.get(agent_id, 0.0) < 60.0:
            return
        self._roster_sent[agent_id] = now
        ids = [a.id.split(":", 1)[-1] for a in self.all()]
        self.send("agent:" + agent_id, {"t": "roster", "ids": ids})

    def _probe(self, agent_id: str) -> None:
        """Ask a fresh agent for its version so we can prove the link works."""
        self.send(agent_id, {"t": "cmd", "d": "ver"})

    def _store_file(self, agent: AgentSession, message: dict[str, Any]) -> None:
        data = self.reassembler.feed(message, time.time())
        if data is None:
            return
        name = os.path.basename(message.get("name", "file.bin"))
        path = os.path.join(self.agent_folder(agent.id), name)
        with open(path, "wb") as handle:
            handle.write(data)
        self.publish({
            "type": "file",
            "id": agent.id,
            "name": name,
            "size": len(data),
            "url": f"/files/{quote(agent.id, safe='')}/{quote(name, safe='')}",
        })

    # ------------------------------------------------------------------
    # Relay
    # ------------------------------------------------------------------

    def start_relay(self) -> None:
        """Connect to a broker and keep reconnecting."""
        threading.Thread(target=self._relay_loop, name="relay", daemon=True).start()

    def _relay_loop(self) -> None:
        while self._running:
            for host, port, use_tls in config.broker_order():
                try:
                    client = MqttClient(config.controller_id(), self._on_message)
                    client.connect(
                        host, port, use_tls,
                        clean_session=False,
                        will_topic=config.topic_up("controller"),
                        will_payload=self.codec.encode({"t": "bye"}),
                    )
                    if not client.subscribe(config.ROOM + "/up/+", qos=1):
                        log.get("hub").warning(
                            "broker did not SUBACK %s/up/+ (ACL?)", config.ROOM)
                    self._client = client
                    self.relay_up = True
                    self.publish({"type": "relay", "up": True, "broker": f"{host}:{port}"})
                    self.flush_outbox()
                    while client.alive and self._running:
                        time.sleep(1)
                    self.relay_up = False
                    self.publish({"type": "relay", "up": False})
                except Exception:
                    continue
            time.sleep(3)

    def stop(self) -> None:
        self._running = False
