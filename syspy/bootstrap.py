"""Bridges ``syspy.agent.bootstrap_bridge`` to the root ``bootstrap.py``.

The root file cannot be a package sibling, so load it by path once.
"""

from __future__ import annotations

import importlib.util
import os

_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bootstrap.py")

_spec = importlib.util.spec_from_file_location("_wu_root_bootstrap", _PATH)
if _spec is None or _spec.loader is None:  # pragma: no cover
    raise ImportError(f"cannot load {_PATH}")
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

agent_alive = _module.agent_alive
start_agent = _module.start_agent
find_python = _module.find_python
ensure_runtime = _module.ensure_runtime

__all__ = ["agent_alive", "start_agent", "find_python", "ensure_runtime"]
