#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix.py -- repair patch.py so it runs on a CRLF checkout.

patch.py failed 69 anchors because read() preserved CRLF while every multi-line
anchor uses LF. This fixes patch.py itself:

  1. newline-normalising read() / write_raw() / create()
  2. an idempotency guard in sub() and append(), plus dedupe_between() to
     collapse the blocks a second run already inserted twice
  3. the two genuinely wrong anchors in patch_webinstall()
  4. wrong relative-import depth in patch_guardian()
  5. the guardian "\\{" SyntaxWarning

Idempotent. Run twice and the second run reports nothing to do.

    python fix.py
    python fix.py --check

Then:
    python patch.py --dry-run     # expect zero ANCHOR FAILUREs
    python patch.py --verify
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(ROOT, "patch.py")

DONE: list[str] = []
SKIP: list[str] = []
FAIL: list[str] = []
_NL = "\n"


# ---------------------------------------------------------------------------
# newline-aware file access (patch.py itself is CRLF in this checkout)
# ---------------------------------------------------------------------------

def _detect(text: str) -> str:
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    return "\r\n" if crlf > lf else "\n"


def read(path: str) -> str:
    global _NL
    with open(path, "r", encoding="utf-8", newline="") as fh:
        raw = fh.read()
    _NL = _detect(raw)
    return raw.replace("\r\n", "\n").replace("\r", "\n")


def write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text if _NL == "\n" else text.replace("\n", "\r\n"))


# ---------------------------------------------------------------------------
# edit primitives
# ---------------------------------------------------------------------------

def edit(label: str, old: str, new: str, required: bool = True) -> bool:
    body = read(TARGET)
    if new and new in body and new != old:
        SKIP.append(label)
        return True
    if old not in body:
        (FAIL if required else SKIP).append(label)
        return False
    write(TARGET, body.replace(old, new, 1))
    DONE.append(label)
    return True


def insert(label: str, anchor: str, text: str, where: str = "before",
           required: bool = True) -> bool:
    body = read(TARGET)
    if text.strip() and text.strip() in body:
        SKIP.append(label)
        return True
    if anchor not in body:
        (FAIL if required else SKIP).append(label)
        return False
    if where == "before":
        write(TARGET, body.replace(anchor, text + anchor, 1))
    else:
        write(TARGET, body.replace(anchor, anchor + text, 1))
    DONE.append(label)
    return True


def dedupe_between(label: str, start_marker: str, end_marker: str) -> bool:
    """Delete the second and later copies of a marker-delimited block."""
    lines = read(TARGET).split("\n")
    starts = [i for i, line in enumerate(lines) if start_marker in line]
    if len(starts) < 2:
        SKIP.append(label)
        return True
    cut = starts[1]
    end = None
    for i in range(cut, len(lines)):
        if end_marker in lines[i]:
            end = i
            break
    if end is None:
        FAIL.append(label + " (no end marker)")
        return False

    head = lines[:cut]
    tail = lines[end + 1:]
    while head and not head[-1].strip():
        head.pop()
    while tail and not tail[0].strip():
        tail.pop(0)
    out = head + (["", ""] + tail if tail else [])
    while out and not out[-1].strip():
        out.pop()
    write(TARGET, "\n".join(out) + "\n")
    DONE.append(label)
    return True


# ---------------------------------------------------------------------------
# the edits
# ---------------------------------------------------------------------------

def apply() -> None:
    # ---- 1. newline handling -------------------------------------------------

    insert("add newline helpers", "def read(path: str) -> str:", r'''_NEWLINE: dict[str, str] = {}
TREE_NEWLINE = "\n"


def _detect_newline(text: str) -> str:
    """Dominant line ending in text."""
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    return "\r\n" if crlf > lf else "\n"


''')

    edit("read() normalises CRLF",
         r'''def read(path: str) -> str:
    with open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()''',
         r'''def read(path: str) -> str:
    """Read a file, normalising CRLF/LF so anchors only ever use \n.

    This is why 67 of 69 anchors failed on the first run: the checkout is CRLF,
    every multi-line anchor here is LF, and newline="" preserved the difference.
    """
    with open(path, "r", encoding="utf-8", newline="") as fh:
        raw = fh.read()
    _NEWLINE.setdefault(path, _detect_newline(raw))
    return raw.replace("\r\n", "\n").replace("\r", "\n")''')

    edit("write_raw() preserves style",
         r'''def write_raw(path: str, text: str) -> None:
    if DRY:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)''',
         r'''def write_raw(path: str, text: str) -> None:
    if DRY:
        return
    os.makedirs(os.path.dirname(path) or ROOT, exist_ok=True)
    newline = _NEWLINE.setdefault(path, TREE_NEWLINE)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text if newline == "\n" else text.replace("\n", "\r\n"))''')

    edit("create() learns style first",
         r'''def create(path: str, text: str) -> None:
    existed = os.path.exists(path)
    _record("rewritten" if existed else "created", path)
    write_raw(path, text)''',
         r'''def create(path: str, text: str) -> None:
    existed = os.path.exists(path)
    if existed:
        read(path)                      # learn the newline style before clobbering
    _record("rewritten" if existed else "created", path)
    write_raw(path, text)''')

    edit("main() probes tree newline",
         "    global DRY, BACKUP\n",
         "    global DRY, BACKUP, TREE_NEWLINE\n")

    insert("probe tree newline",
           r'''        print("error: run this from the repository root (agent.py + syspy/ not found)")
        return 2
''',
           r'''
    probe = P("agent.py")
    if os.path.exists(probe):
        with open(probe, "r", encoding="utf-8", newline="") as fh:
            TREE_NEWLINE = _detect_newline(fh.read())
''', where="after")

    # ---- 2. idempotency -----------------------------------------------------

    insert("sub() idempotency guard",
           "    body = read(path)\n    if old not in body:",
           r'''    if new and new in body:
        SKIPPED.append(f"{rel}: already applied ({old[:40]!r})")
        return False
''')

    edit("append() idempotency",
         r'''def append(path: str, text: str) -> None:
    body = read(path) if os.path.exists(path) else ""
    write_raw(path, body + text)
    _record("edited", path)''',
         r'''def append(path: str, text: str) -> None:
    """Append, unless the text is already there."""
    body = read(path) if os.path.exists(path) else ""
    if text.strip() and text.strip() in body:
        SKIPPED.append(
            f"{os.path.relpath(path, ROOT).replace(os.sep, '/')}: already appended")
        return
    write_raw(path, body + text)
    _record("edited", path)''')

    insert("add dedupe_between", "def backup_tree() -> str:", r'''def dedupe_between(path: str, start_marker: str, end_marker: str) -> bool:
    """Delete the second and later copies of a marker-delimited block.

    A sub whose anchor is a prefix of its own replacement (KEY_SALT,
    build_zip_from_dir) re-inserts the block on every run, and append() is
    unconditional. That left config.py and packaging.py holding two copies.
    """
    lines = read(path).split("\n")
    starts = [i for i, line in enumerate(lines) if start_marker in line]
    if len(starts) < 2:
        return False
    cut = starts[1]
    end = None
    for index in range(cut, len(lines)):
        if end_marker in lines[index]:
            end = index
            break
    if end is None:
        return False

    head = lines[:cut]
    tail = lines[end + 1:]
    while head and not head[-1].strip():
        head.pop()
    while tail and not tail[0].strip():
        tail.pop(0)
    out = head + (["", ""] + tail if tail else [])
    while out and not out[-1].strip():
        out.pop()
    write_raw(path, "\n".join(out) + "\n")
    _record("edited", path)
    return True


''')

    # ---- 3. call dedupe before the subs that caused the duplicates ----------

    insert("config.py dedupe calls",
           'def patch_config() -> None:\n    path = P("syspy", "config.py")\n',
           '''    dedupe_between(path, "# Patch additions: protocol versioning",
                   "frame-ancestors 'none'")
    dedupe_between(path, "# Patch: per-deployment namespace.",
                   '_setting("pubkey", "SYSPY_PUBKEY"')
''', where="after")

    insert("packaging.py dedupe call",
           'def patch_packaging() -> None:\n    path = P("syspy", "packaging.py")\n',
           '''    dedupe_between(path, "def build_zip_from_dir(source: str",
                   "return buffer.getvalue()")
''', where="after")

    # ---- 4. the two genuinely wrong anchors ---------------------------------

    edit("webinstall $target anchor (trailing space)",
         "$target  = '@@TARGET@@' ''',",
         "$target  = '@@TARGET@@'\n''',")

    edit("webinstall indent (12 -> 16 spaces)",
         r"""    sub(path,
        '''            base=request.param("base") or _base(request),''',
        '''            base=request.param("base") or _base(request),''')""",
         r"""    sub(path,
        '''                base=request.param("base") or _base(request),''',
        '''                base=request.param("base") or _base(request),''')""")

    # ---- 5. guardian relative-import depth ----------------------------------

    edit("guardian config import depth",
         "    from .. import config as _config",
         "    from . import config as _config")

    edit("guardian remove() import depth",
         r'''            from . import machine_state
            machine_state.forget("wmi")''',
         r'''            from .agent import machine_state
            machine_state.forget("wmi")''')

    edit("guardian install() import depth",
         r'''            from . import machine_state
            machine_state.record("wmi", CONSUMER_NAME, int(time.time()))''',
         r'''            from .agent import machine_state
            machine_state.record("wmi", CONSUMER_NAME, int(time.time()))''')

    insert("guardian escape SyntaxWarning",
           'def patch_guardian() -> None:\n    path = P("syspy", "guardian.py")\n',
           '''    sub_all(path, r'append(f"{label}\\{name}")',
            r'append(f"{label}\\\\{name}")', required=False)
''', where="after")


# ---------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------

def verify() -> list[str]:
    problems: list[str] = []
    try:
        compile(read(TARGET), TARGET, "exec")
    except SyntaxError as error:
        problems.append("patch.py does not compile: " + str(error))
        return problems

    body = read(TARGET)
    checks = (
        ("_detect_newline", "newline helper"),
        ("TREE_NEWLINE", "tree newline"),
        ("def dedupe_between", "dedupe helper"),
        ("raw.replace(\"\\r\\n\", \"\\n\")", "read() normalisation"),
        ("from .agent import machine_state", "guardian import depth"),
        ("                base=request.param", "webinstall indent"),
    )
    for needle, label in checks:
        if needle not in body:
            problems.append("missing: " + label)
    if "$target  = '@@TARGET@@' '''," in body:
        problems.append("missing: webinstall $target anchor fix")
    return problems


def check() -> int:
    problems = verify()
    if problems:
        print("patch.py needs fixing:")
        for item in problems:
            print("  -", item)
        return 1
    print("patch.py looks fixed.")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Repair patch.py")
    parser.add_argument("--check", action="store_true",
                        help="report whether patch.py still needs fixing")
    parser.add_argument("--no-backup", action="store_true")
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))

    if args.check:
        return check()

    if not os.path.isfile(TARGET):
        print("error: patch.py not found next to fix.py")
        return 2

    print()
    print("  fixing patch.py")
    print("  " + "-" * 52)

    if not args.no_backup:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = TARGET + ".bak-" + stamp
        shutil.copy2(TARGET, backup)
        print(f"  backup: {os.path.basename(backup)}")

    apply()

    for label in DONE:
        print(f"      + {label}")
    if SKIP:
        print(f"  {len(SKIP)} already in place:")
        for label in SKIP:
            print(f"      . {label}")

    problems = verify()
    print()
    if problems:
        print(f"  {len(problems)} PROBLEM(S):")
        for item in problems:
            print("      ! " + item)
    else:
        print("  patch.py compiles and every fix is present.")

    if FAIL:
        print()
        print(f"  {len(FAIL)} EDIT(S) COULD NOT BE APPLIED:")
        for label in FAIL:
            print("      ! " + label)

    print()
    print("  " + "-" * 52)
    if not problems and not FAIL:
        print("  next:")
        print("    python patch.py --dry-run    # expect zero ANCHOR FAILUREs")
        print("    python patch.py --verify")
    print()
    return 1 if (problems or FAIL) else 0


if __name__ == "__main__":
    raise SystemExit(main())