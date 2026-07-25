"""Shared test fixtures.

The probe tests deliberately do *not* touch the network.  Each probe is split
into "build the command line" and "parse the output", and the tests exercise
those two pure halves against real recorded output from the actual binaries.
That is what makes it possible to test the Windows ``ping`` parser on Linux
CI, and the mtr parser without raw-socket privileges.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from smokeagent.probes.base import load_builtin_probes  # noqa: E402
from smokecommon.models import Measurement, ProbeResult  # noqa: E402
from smokecommon.process import CommandOutput  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _load_probes() -> None:
    """Register the builtin probes once for the whole session."""
    load_builtin_probes()


def make_output(
    stdout: str = "",
    stderr: str = "",
    returncode: int = 0,
    argv: list[str] | None = None,
    duration_ms: float = 12.0,
    timed_out: bool = False,
) -> CommandOutput:
    """Build a :class:`CommandOutput` as if a binary had produced it."""
    return CommandOutput(
        argv=argv or ["fake"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        timed_out=timed_out,
    )


def make_measurement(**overrides: Any) -> Measurement:
    """A minimal valid measurement, for storage and server tests."""
    defaults: dict[str, Any] = {
        "agent_id": "agent-1",
        "agent_location": "seoul",
        "target_name": "dns",
        "target_group": "/kr",
        "target": "8.8.8.8",
        "probe": "ping",
        "success": True,
        "latency_ms": 12.0,
        "rtts_ms": [11.0, 12.0, 13.0],
        "packets_sent": 3,
        "packets_received": 3,
        "loss_pct": 0.0,
        "resolved_ip": "8.8.8.8",
        "ip_family": 4,
        "details": {"command": "ping -c 3 8.8.8.8"},
    }
    defaults.update(overrides)
    return Measurement(**defaults)


@pytest.fixture
def measurement() -> Measurement:
    return make_measurement()


@pytest.fixture
def probe_result() -> ProbeResult:
    return ProbeResult(
        success=True,
        rtts_ms=[10.0, 20.0, 30.0],
        packets_sent=3,
        packets_received=3,
        resolved_ip="1.1.1.1",
    )
