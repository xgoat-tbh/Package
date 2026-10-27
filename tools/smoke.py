#!/usr/bin/env python3
"""End-to-end: start a controller, start an agent, assert they meet.

This is the test that catches a split fleet (room/pass mismatch), a broken
one-liner, and a dead relay.  Static tests do not.
"""
import json, os, subprocess, sys, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, SYSPY_ROOM="smoke-room", SYSPY_PASS="smoke-pass",
           SYSPY_DATA=os.path.join(ROOT, "data"), SYSPY_LAN="0", RENDER="1")


def main() -> int:
    ctl = subprocess.Popen([sys.executable, "controller.py", "--host", "127.0.0.1",
                            "--port", "8799", "--no-browser"],
                           cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(4)
    agt = subprocess.Popen([sys.executable, "agent.py", "--no-uac", "--no-elevate"],
                           cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with urllib.request.urlopen("http://127.0.0.1:8799/api/health", timeout=5) as r:
                    data = json.load(r)
            except Exception:
                time.sleep(2); continue
            if data.get("relay") and data.get("agents", 0) >= 1:
                print("SMOKE OK", data)
                return 0
            time.sleep(2)
        print("SMOKE FAIL - no agent appeared. Suspect ROOM/PASSPHRASE mismatch.")
        return 1
    finally:
        for p in (agt, ctl):
            try: p.kill()
            except Exception: pass


if __name__ == "__main__":
    raise SystemExit(main())
