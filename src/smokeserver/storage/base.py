"""Storage driver interface and the shared row-flattening logic.

Both drivers write the same logical model:

``measurements``
    One row per probe cycle.  Common columns for everything you filter or
    group by (agent, location, target, probe, latency, loss, resolved IP) plus
    a ``details`` JSON blob for the probe-specific payload.

``mtr_hops``
    One row per hop per mtr cycle, joined back by ``measurement_id``.  Hops get
    their own table because per-hop analysis has a completely different query
    shape -- you group by hop IP across thousands of cycles -- and unnesting an
    array on every query would make the Grafana panels unusable.

Keeping the flattening here rather than in each driver means the ClickHouse and
PostgreSQL schemas cannot drift apart.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from smokecommon.models import Measurement

#: Column order used by both drivers.  Keep in sync with the DDL in deploy/.
MEASUREMENT_COLUMNS: tuple[str, ...] = (
    "ts",
    "id",
    "agent_id",
    "agent_location",
    "agent_tags",
    "target_name",
    "target_group",
    "target",
    "probe",
    "success",
    "error_type",
    "error_message",
    "latency_ms",
    "rtts_ms",
    "rtt_min_ms",
    "rtt_avg_ms",
    "rtt_median_ms",
    "rtt_max_ms",
    "rtt_stddev_ms",
    "rtt_p95_ms",
    "jitter_ms",
    "packets_sent",
    "packets_received",
    "loss_pct",
    "resolved_ip",
    "ip_family",
    "duration_ms",
    "details",
)

HOP_COLUMNS: tuple[str, ...] = (
    "ts",
    "measurement_id",
    "agent_id",
    "agent_location",
    "target_name",
    "target_group",
    "target",
    "probe",
    "hop_no",
    "hop_host",
    "hop_ip",
    "loss_pct",
    "sent",
    "received",
    "last_ms",
    "avg_ms",
    "best_ms",
    "worst_ms",
    "stddev_ms",
    "asn",
    "is_destination",
    "path_signature",
)


class StorageError(RuntimeError):
    """Raised when the backing store cannot accept a write."""


class StorageDriver(ABC):
    """What smoke-server needs from a database."""

    #: Name used in config and in log lines.
    name: str = "base"

    @abstractmethod
    async def connect(self) -> None:
        """Open pools/clients.  Must be idempotent."""

    @abstractmethod
    async def close(self) -> None:
        """Release everything.  Must be safe to call twice."""

    @abstractmethod
    async def ensure_schema(self) -> None:
        """Create tables/views if missing.  Must be idempotent."""

    @abstractmethod
    async def write_measurements(self, measurements: list[Measurement]) -> int:
        """Persist a batch, returning the number of measurement rows written.

        Raise :class:`StorageError` if the batch was *not* durably stored --
        the server turns that into a 503 so the agent spools and retries
        rather than silently losing the data.
        """

    @abstractmethod
    async def health(self) -> bool:
        """Cheap liveness check used by ``/readyz``."""

    async def agents(self) -> list[dict[str, Any]]:
        """Recently seen agents.  Optional; the default is 'unsupported'."""
        return []

    async def __aenter__(self) -> StorageDriver:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# Flattening
# ---------------------------------------------------------------------------


def measurement_row(m: Measurement) -> dict[str, Any]:
    """Flatten a measurement into the ``measurements`` column set.

    The ``stats`` sub-object is expanded into real columns: percentile queries
    are the single most common thing a smoke dashboard does, and making Grafana
    dig them out of JSON on every refresh would be wasteful.
    """
    stats = m.stats
    return {
        "ts": m.ts,
        "id": m.id,
        "agent_id": m.agent_id,
        "agent_location": m.agent_location,
        "agent_tags": dict(m.agent_tags or {}),
        "target_name": m.target_name,
        "target_group": m.target_group,
        "target": m.target,
        "probe": m.probe,
        "success": 1 if m.success else 0,
        "error_type": str(m.error_type or ""),
        "error_message": (m.error_message or "")[:2000],
        "latency_ms": m.latency_ms,
        "rtts_ms": list(m.rtts_ms or []),
        "rtt_min_ms": stats.min_ms if stats else None,
        "rtt_avg_ms": stats.avg_ms if stats else None,
        "rtt_median_ms": stats.median_ms if stats else None,
        "rtt_max_ms": stats.max_ms if stats else None,
        "rtt_stddev_ms": stats.stddev_ms if stats else None,
        "rtt_p95_ms": stats.p95_ms if stats else None,
        "jitter_ms": stats.jitter_ms if stats else None,
        "packets_sent": int(m.packets_sent or 0),
        "packets_received": int(m.packets_received or 0),
        "loss_pct": m.loss_pct,
        "resolved_ip": m.resolved_ip or "",
        "ip_family": int(m.ip_family or 0),
        "duration_ms": m.duration_ms,
        "details": m.details or {},
    }


def hop_rows(m: Measurement) -> list[dict[str, Any]]:
    """Flatten a measurement's hops into ``mtr_hops`` rows."""
    if not m.hops:
        return []
    path_signature = str((m.details or {}).get("path_signature") or "")
    last_index = len(m.hops) - 1
    rows: list[dict[str, Any]] = []
    for index, hop in enumerate(m.hops):
        rows.append(
            {
                "ts": m.ts,
                "measurement_id": m.id,
                "agent_id": m.agent_id,
                "agent_location": m.agent_location,
                "target_name": m.target_name,
                "target_group": m.target_group,
                "target": m.target,
                "probe": m.probe,
                "hop_no": int(hop.hop_no),
                "hop_host": hop.host or "",
                "hop_ip": hop.ip or "",
                "loss_pct": hop.loss_pct,
                "sent": hop.sent,
                "received": hop.received,
                "last_ms": hop.last_ms,
                "avg_ms": hop.avg_ms,
                "best_ms": hop.best_ms,
                "worst_ms": hop.worst_ms,
                "stddev_ms": hop.stddev_ms,
                "asn": hop.asn or "",
                # Precomputed so "how does the endpoint behave" does not need a
                # correlated max(hop_no) subquery.
                "is_destination": 1 if index == last_index else 0,
                "path_signature": path_signature,
            }
        )
    return rows


def json_default(value: Any) -> Any:
    """JSON encoder fallback for values pydantic already normalised loosely."""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def dumps(value: Any) -> str:
    return json.dumps(value, default=json_default, ensure_ascii=False)
