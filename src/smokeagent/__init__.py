"""smoke-agent: the probing half of smokeping-py.

Runs probes on a schedule from one vantage point and ships the results to a
smoke-server.  Deliberately stateless -- everything it knows lives in its
config file and its (optional) spool directory.
"""

from smokecommon.version import __version__

__all__ = ["__version__"]
