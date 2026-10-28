#!/usr/bin/env python3
"""SysPy controller — serves the web dashboard.

Run this on your own machine, open the printed URL in a browser, and any
agent that connects will appear in the sidebar.

    python controller.py
    python controller.py --host 0.0.0.0 --port 8787
    python controller.py --password hunter2
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser

from syspy import __version__, config, httpd, log
from syspy.server.api import Api

STATIC_FILES = ("index.html", "app.js", "style.css")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="SysPy controller")
    # A container platform must bind 0.0.0.0 or its health check fails and every
    # one-liner returns 502.  Never rely on the operator remembering the env var.
    _cloud = bool(os.environ.get("RENDER") or os.environ.get("PORT"))
    _default_host = os.environ.get("SYSPY_HOST") or ("0.0.0.0" if _cloud else config.DASHBOARD_HOST)
    parser.add_argument("--host", default=_default_host,
                        help="interface to bind (0.0.0.0 when hosted, else loopback)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT") or config.DASHBOARD_PORT))
    parser.add_argument("--password", default="", help="dashboard password")
    parser.add_argument("--genkey", action="store_true",
                        help="print a fresh Ed25519 signing keypair and exit")
    parser.add_argument("--genkey", action="store_true",
                        help="print a fresh Ed25519 signing keypair and exit")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--stopall", "--stop", action="store_true",
                        help="stop all running controller processes and free port")
    parser.add_argument("--version", action="version", version=f"SysPy {__version__}")
    return parser.parse_args(argv)


def stop_all_controllers(port: int = config.DASHBOARD_PORT) -> int:
    """Find and terminate all running controller processes and free the port."""
    my_pid = os.getpid()
    ppid = os.getppid() if hasattr(os, "getppid") else 0
    killed = 0
    print(f"\n  Checking for running SysPy controller instances (port {port})...")

    if os.name == "nt":
        import subprocess
        # 1. Kill any other python processes running controller.py
        ps_cmd = (
            f"Get-CimInstance Win32_Process -Filter \"Name LIKE 'python%'\" | "
            f"Where-Object {{ $_.CommandLine -like '*controller.py*' -and "
            f"$_.CommandLine -notlike '*--stop*' -and "
            f"$_.ProcessId -ne {my_pid} -and $_.ProcessId -ne {ppid} }} | "
            f"Select-Object -ExpandProperty ProcessId"
        )
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd],
                                 capture_output=True, text=True, timeout=10)
            pids = [int(p.strip()) for p in res.stdout.split() if p.strip().isdigit()]
            for pid in set(pids):
                if pid not in (my_pid, ppid):
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                       capture_output=True, timeout=5)
                        killed += 1
                        print(f"  [x] Terminated controller process (PID {pid})")
                    except Exception:
                        pass
        except Exception:
            pass

        # 2. Release port if still held by any process
        port_cmd = (
            f"Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | "
            f"Select-Object -ExpandProperty OwningProcess"
        )
        try:
            res = subprocess.run(["powershell", "-NoProfile", "-Command", port_cmd],
                                 capture_output=True, text=True, timeout=10)
            pids = [int(p.strip()) for p in res.stdout.split() if p.strip().isdigit()]
            for pid in set(pids):
                if pid not in (my_pid, ppid):
                    try:
                        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                       capture_output=True, timeout=5)
                        killed += 1
                        print(f"  [x] Released port {port} (PID {pid})")
                    except Exception:
                        pass
        except Exception:
            pass
    else:
        import subprocess
        ppid = os.getppid() if hasattr(os, "getppid") else 0
        try:
            out = subprocess.run("pgrep -f 'controller.py'", shell=True,
                                 capture_output=True, text=True).stdout.split()
            for pid in {int(p) for p in out if p.isdigit()} - {my_pid, ppid}:
                subprocess.run(["kill", "-9", str(pid)], capture_output=True)
                killed += 1
        except Exception:
            pass

    if killed > 0:
        print(f"  [OK] Successfully closed {killed} running controller process(es). Port {port} is now free.\n")
    else:
        print(f"  [OK] No other running controller processes were found. Port {port} is free.\n")
    return 0


def check_assets() -> list[str]:
    """Return the names of any missing dashboard files."""
    import syspy.server

    static_root = os.path.join(os.path.dirname(os.path.abspath(syspy.server.__file__)), "static")
    if not os.path.isdir(static_root):
        print(f"  error: static directory not found at {static_root}")
    return [name for name in STATIC_FILES
            if not os.path.isfile(os.path.join(static_root, name))]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.stopall:
        return stop_all_controllers(args.port)

    if getattr(sys, "frozen", False):
        root = os.path.dirname(os.path.abspath(sys.executable))
    else:
        root = os.path.dirname(os.path.abspath(__file__))

    os.environ.setdefault("SYSPY_DATA", os.path.join(root, "data"))
    os.makedirs(os.environ["SYSPY_DATA"], exist_ok=True)
    log.setup(os.path.join(os.environ["SYSPY_DATA"], "logs"), tag="controller")
    log.get("controller").info("controller starting on %s:%s", args.host, args.port)

    missing = check_assets()
    if missing:
        print(f"  error: missing dashboard files: {', '.join(missing)}")
        print("         the UI will load unstyled until they are restored.")
        print()

    api = Api(root)
    if args.password:
        from syspy.server.api import _hash_password
        api.state["password"] = _hash_password(args.password)
        api._save_state()

    try:
        server = httpd.Server((args.host, args.port), api.app)
    except OSError as err:
        print(f"\n  [ERROR] Controller port {args.port} is already in use by another running instance.")
        print(f"          Run 'python controller.py --stopall' to close all running instances.\n")
        return 1

    api.hub.start_relay()
    threading.Thread(target=_reaper, args=(api,), daemon=True).start()

    host = "127.0.0.1" if args.host in ("0.0.0.0", "") else args.host
    url = f"http://{host}:{args.port}/"

    print()
    print("  SysPy controller " + __version__)
    print("  " + "-" * 46)
    print(f"  dashboard : {url}")
    generated = not (os.environ.get("SYSPY_PASSWORD") or args.password)
    print(f"  password  : {api.state['password']}"
          + ("   (generated - set SYSPY_PASSWORD to pin it)" if generated else ""))
    if config.PUBKEY_HEX:
        print(f"  signing   : ed25519 {config.PUBKEY_HEX[:16]}...")
    else:
        print("  signing   : OFF (set SYSPY_SIGN_KEY/SYSPY_PUBKEY)")
    print(f"  room      : {config.ROOM}")
    print("  " + "-" * 46)
    print("  waiting for agents...  (ctrl+c to stop)")
    print()

    if not args.no_browser and not os.environ.get("RENDER"):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  bye")
    finally:
        api.hub.stop()
        server.server_close()
    return 0


def _reaper(api: Api) -> None:
    """Drop agents that stop reporting."""
    while True:
        time.sleep(5)
        try:
            api.hub.forget_stale()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
