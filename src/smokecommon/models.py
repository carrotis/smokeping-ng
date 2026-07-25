"""Wire models shared by the agent and the server.

Design notes
------------
The original SmokePing kept a single number per cycle (plus the RRD "smoke"
band).  We keep the whole picture instead:

* ``rtts_ms`` -- every individual round-trip time in the cycle.  This is what
  reproduces the classic smoke graph, and it lets you recompute any percentile
  later without re-measuring.
* ``stats`` -- precomputed percentiles so Grafana does not have to unnest the
  array for the common case.
* ``resolved_ip`` -- the address actually talked to.  A single hostname behind
  anycast or a CDN is really N different services; without this column you
  cannot tell them apart.
* ``details`` -- the probe-specific payload (curl timing breakdown, dig answer
  section, ...).  Stored as JSON so probes can evolve without a migration.
* ``hops`` -- flattened to their own table server-side, because per-hop
  analysis is a different query shape than per-target analysis.
"""

from __future__ import annotations

import itertools
import math
import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from smokecommon.errors import ErrorType
from smokecommon.version import PROTOCOL_VERSION


def utcnow() -> datetime:
    """Timezone-aware UTC now.  Single definition so tests can monkeypatch it."""
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


def percentile(sorted_values: list[float], q: float) -> float:
    """Linear-interpolation percentile over an already sorted list.

    ``q`` is a fraction in ``[0, 1]``.  Matches numpy's default ("linear")
    method, so results line up with whatever people compute downstream.
    """
    if not sorted_values:
        raise ValueError("percentile() of empty sequence")
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * q
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return sorted_values[int(pos)]
    return sorted_values[lower] * (upper - pos) + sorted_values[upper] * (pos - lower)


class SmokeModel(BaseModel):
    """Base config: ignore unknown fields so a newer agent can talk to an
    older server (and vice versa) without a hard failure."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class RttStats(SmokeModel):
    """Distribution summary of one measurement cycle."""

    min_ms: float
    avg_ms: float
    median_ms: float
    max_ms: float
    stddev_ms: float
    p95_ms: float
    #: Mean absolute difference between consecutive RTTs -- the "how jumpy is
    #: this link" number.  Undefined (0.0) for a single sample.
    jitter_ms: float

    @classmethod
    def from_rtts(cls, rtts_ms: list[float]) -> RttStats | None:
        """Compute the summary, or ``None`` when there is nothing to summarise."""
        values = [float(v) for v in rtts_ms if v is not None]
        if not values:
            return None
        ordered = sorted(values)
        n = len(ordered)
        avg = sum(ordered) / n
        variance = sum((v - avg) ** 2 for v in ordered) / n
        if n > 1:
            jitter = sum(abs(b - a) for a, b in itertools.pairwise(values)) / (n - 1)
        else:
            jitter = 0.0
        return cls(
            min_ms=ordered[0],
            avg_ms=avg,
            median_ms=percentile(ordered, 0.5),
            max_ms=ordered[-1],
            stddev_ms=math.sqrt(variance),
            p95_ms=percentile(ordered, 0.95),
            jitter_ms=jitter,
        )


class HopResult(SmokeModel):
    """One router on the path, as reported by mtr/traceroute."""

    hop_no: int
    #: Reverse-DNS name when the probe resolved one.
    host: str | None = None
    #: The address that answered.  ``None`` for a silent (``*``) hop.
    ip: str | None = None
    loss_pct: float | None = None
    sent: int | None = None
    received: int | None = None
    last_ms: float | None = None
    avg_ms: float | None = None
    best_ms: float | None = None
    worst_ms: float | None = None
    stddev_ms: float | None = None
    asn: str | None = None


class ProbeResult(SmokeModel):
    """What a probe returns.

    Deliberately knows nothing about agents or targets -- the agent enriches
    this into a :class:`Measurement` before shipping.  That keeps probes
    trivially unit-testable.
    """

    success: bool
    error_type: ErrorType | None = None
    error_message: str | None = None

    #: Individual round-trip times.  Probes that produce a single timing
    #: (curl, dig, nc) return a one-element list.
    rtts_ms: list[float] = Field(default_factory=list)
    #: Explicit representative latency.  Only set it when it is *not* simply
    #: derived from ``rtts_ms`` (e.g. mtr's end-to-end figure).
    latency_ms: float | None = None

    packets_sent: int = 0
    packets_received: int = 0

    #: The address the probe actually exchanged packets with.
    resolved_ip: str | None = None

    details: dict[str, Any] = Field(default_factory=dict)
    hops: list[HopResult] = Field(default_factory=list)

    #: Wall-clock cost of running the probe, including process spawn.
    duration_ms: float | None = None

    @property
    def loss_pct(self) -> float | None:
        if self.packets_sent <= 0:
            return None
        lost = self.packets_sent - self.packets_received
        return round(100.0 * lost / self.packets_sent, 4)

    @property
    def effective_latency_ms(self) -> float | None:
        """Representative latency: explicit value, else the median RTT."""
        if self.latency_ms is not None:
            return self.latency_ms
        stats = RttStats.from_rtts(self.rtts_ms)
        return stats.median_ms if stats else None

    @classmethod
    def failure(
        cls,
        error_type: ErrorType,
        message: str,
        *,
        packets_sent: int = 0,
        details: dict[str, Any] | None = None,
        duration_ms: float | None = None,
        resolved_ip: str | None = None,
    ) -> ProbeResult:
        """Shorthand for the very common 'it broke' return."""
        return cls(
            success=False,
            error_type=error_type,
            error_message=message[:2000],
            packets_sent=packets_sent,
            details=details or {},
            duration_ms=duration_ms,
            resolved_ip=resolved_ip,
        )


class Measurement(SmokeModel):
    """A probe result stamped with who measured it, from where, and against what."""

    id: str = Field(default_factory=new_id)
    ts: datetime = Field(default_factory=utcnow)

    # --- who / where -------------------------------------------------------
    agent_id: str
    #: Human-readable site name, e.g. "seoul-idc" or "aws-ap-northeast-2".
    #: The whole point of the agent split: identical targets look different
    #: from different vantage points.
    agent_location: str = "unknown"
    #: Free-form vantage-point labels (region, isp, asn, rack, ...).
    agent_tags: dict[str, str] = Field(default_factory=dict)

    # --- what --------------------------------------------------------------
    #: Stable identifier of the configured target entry.
    target_name: str
    #: Slash-delimited group path, e.g. "/world/asia/kr" -- mirrors SmokePing's
    #: hierarchical menu and drives Grafana's variable drill-down.
    target_group: str = "/"
    #: The host/URL exactly as configured.
    target: str
    probe: str

    # --- outcome -----------------------------------------------------------
    success: bool
    error_type: ErrorType | None = None
    error_message: str | None = None

    latency_ms: float | None = None
    rtts_ms: list[float] = Field(default_factory=list)
    stats: RttStats | None = None
    packets_sent: int = 0
    packets_received: int = 0
    loss_pct: float | None = None

    resolved_ip: str | None = None
    ip_family: int | None = None

    details: dict[str, Any] = Field(default_factory=dict)
    hops: list[HopResult] = Field(default_factory=list)
    duration_ms: float | None = None

    @field_validator("target_group")
    @classmethod
    def _normalise_group(cls, value: str) -> str:
        value = "/" + value.strip("/")
        return value

    @model_validator(mode="after")
    def _derive_stats(self) -> Measurement:
        """Guarantee ``stats`` whenever there are samples to summarise.

        Making this an invariant of the model rather than of one constructor
        means the percentile columns are populated no matter how the object
        came to exist -- built by the scheduler, hand-rolled by a plugin, or
        deserialised from a spool file written by an older agent that did not
        send them.
        """
        if self.stats is None and self.rtts_ms:
            self.stats = RttStats.from_rtts(self.rtts_ms)
        if self.latency_ms is None and self.stats is not None:
            self.latency_ms = self.stats.median_ms
        if self.loss_pct is None and self.packets_sent > 0:
            lost = self.packets_sent - self.packets_received
            self.loss_pct = round(100.0 * lost / self.packets_sent, 4)
        return self

    @classmethod
    def from_probe_result(
        cls,
        result: ProbeResult,
        *,
        agent_id: str,
        agent_location: str,
        agent_tags: dict[str, str] | None = None,
        target_name: str,
        target_group: str,
        target: str,
        probe: str,
        ts: datetime | None = None,
    ) -> Measurement:
        """Enrich a probe result with vantage-point and target identity."""
        return cls(
            ts=ts or utcnow(),
            agent_id=agent_id,
            agent_location=agent_location,
            agent_tags=agent_tags or {},
            target_name=target_name,
            target_group=target_group,
            target=target,
            probe=probe,
            success=result.success,
            error_type=result.error_type,
            error_message=result.error_message,
            latency_ms=result.effective_latency_ms,
            rtts_ms=result.rtts_ms,
            stats=RttStats.from_rtts(result.rtts_ms),
            packets_sent=result.packets_sent,
            packets_received=result.packets_received,
            loss_pct=result.loss_pct,
            resolved_ip=result.resolved_ip,
            ip_family=_ip_family(result.resolved_ip),
            details=result.details,
            hops=result.hops,
            duration_ms=result.duration_ms,
        )


class MeasurementBatch(SmokeModel):
    """The ingest payload.  Agents ship many measurements per request."""

    protocol_version: int = PROTOCOL_VERSION
    agent_id: str
    agent_location: str = "unknown"
    agent_version: str | None = None
    sent_at: datetime = Field(default_factory=utcnow)
    measurements: list[Measurement]


class IngestResponse(SmokeModel):
    accepted: int
    rejected: int = 0
    #: Per-measurement complaints; the batch is still accepted.
    warnings: list[str] = Field(default_factory=list)


def _ip_family(ip: str | None) -> int | None:
    if not ip:
        return None
    if ":" in ip:
        return 6
    if ip.count(".") == 3:
        return 4
    return None
