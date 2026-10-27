"""Bootstrap bridge for guardian self-heal.

Provides lazy imports of the main bootstrap helpers without creating a circular dependency.
"""

# Import the functions from the top-level bootstrap module. The relative import
# uses ``..`` because this file lives in ``syspy/agent``.
# ``agent_alive`` reports whether the agent process is currently running.
# ``start_agent`` launches the agent (used by the self‑heal routine).

from ..bootstrap import agent_alive, start_agent  # noqa: F401
