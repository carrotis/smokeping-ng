"""Version constants.

``PROTOCOL_VERSION`` is bumped only when the ingest payload changes in a way
that an older server cannot handle.  The server reports the highest protocol
version it understands from ``/healthz`` so agents can warn on mismatch.
"""

__version__ = "0.1.0"

PROTOCOL_VERSION = 1
