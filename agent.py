#!/usr/bin/env python3
"""SysPy agent — runs on the target machine.

    python agent.py                # normal start (console visible)
    python agent.py --hidden       # start with the console window hidden
    python agent.py --show         # keep the console visible
    python agent.py --install      # write persistence and exit
    python agent.py --uninstall    # remove everything and exit
    python agent.py --check        # print a health report and exit
    python agent.py --watchdog     # run as the supervisor process

Note: the docstring must come first, then ``from __future__``, then imports.
Anything before the future import makes it a syntax error.
"""

from __future__ import annotations

import os
import sys

# ---------------------------------------------------------------------------
# Frozen-build bootstrap
# ---------------------------------------------------------------------------
# A PyInstaller bundle imports ``syspy`` from a temporary extraction directory
# (``sys._MEIPASS``) that is wiped when the process exits. A pushed update
# writes a fresh ``syspy/`` next to the executable instead, so if that folder
# exists we put its parent at the front of ``sys.path`` and let it win.
#
# This must run *before* ``from syspy.agent.core import main``.
# ---------------------------------------------------------------------------

if getattr(sys, "frozen", False):
    _beside = os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "syspy")
    if os.path.isdir(_beside):
        _parent = os.path.dirname(_beside)
        while _parent in sys.path:
            sys.path.remove(_parent)
        sys.path.insert(0, _parent)

# A ``--noconsole`` build leaves these as ``None``, which turns ``print`` into
# a no-op and can make ``traceback.print_exc`` raise.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

from syspy.agent.core import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))