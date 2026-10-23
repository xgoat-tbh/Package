#!/usr/bin/env python3
"""SysPy agent — runs on the target machine.

    python agent.py                # normal start (console visible)
    python agent.py --hidden       # start with the console window hidden
    python agent.py --install      # write persistence and exit
    python agent.py --uninstall    # remove everything and exit
    python agent.py --check        # print a health report and exit
    python agent.py --watchdog     # run as the supervisor process

Note: the docstring must come first, then ``from __future__``, then imports.
Anything before the future import makes it a syntax error.
"""

from __future__ import annotations

import sys

from syspy.agent.core import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
