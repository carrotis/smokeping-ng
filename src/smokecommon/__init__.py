"""Shared building blocks for smoke-agent and smoke-server.

Everything that travels over the wire between the two processes is defined
here so that the agent and the server can never drift apart.
"""

from smokecommon.errors import ErrorType
from smokecommon.models import (
    HopResult,
    Measurement,
    MeasurementBatch,
    ProbeResult,
    RttStats,
)
from smokecommon.version import PROTOCOL_VERSION, __version__

__all__ = [
    "PROTOCOL_VERSION",
    "ErrorType",
    "HopResult",
    "Measurement",
    "MeasurementBatch",
    "ProbeResult",
    "RttStats",
    "__version__",
]
