"""smoke-server: receives measurements from agents and stores them.

Grafana reads the database directly -- there is no bespoke web UI, by design.
"""

from smokecommon.version import __version__

__all__ = ["__version__"]
