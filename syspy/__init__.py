"""SysPy - a small, dependency-free remote administration toolkit.

The package is organised into three layers:

``syspy.agent``
    Code that runs on the target machine.
``syspy.server``
    Code that runs on the operator machine (the web dashboard).
``syspy.*``
    Shared helpers: transport, cryptography, protocol framing.

Importing this package has no side effects.
"""

from __future__ import annotations

__version__ = "5.2.0"      # the ONLY version. build_dist derives from this.

#: Short build fingerprint reported in every hello, so the dashboard can
#: tell two builds apart without trusting a 12-char source hash.
BUILD_ID = __version__ + "+patch"
__author__ = "SysPy"

__all__ = ["__version__"]
