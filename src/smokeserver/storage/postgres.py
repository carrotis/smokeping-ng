"""PostgreSQL storage driver (asyncpg).

The obvious choice when you already run Postgres and your volume is moderate:
a few hundred targets at 60 s is well under a million rows a day, which
Postgres handles comfortably with the indexes below.  Reach for ClickHouse when
you cross a few thousand rows/second or want months of raw retention.

Two Postgres-specific wins over the ClickHouse driver:

* **Idempotent ingest.**  ``PRIMARY KEY (ts, id)`` plus ``ON CONFLICT DO
  NOTHING`` means an agent replaying a spooled batch it had already delivered
  (the classic "response lost after the write committed" case) cannot create
  duplicates.
* **JSONB.**  ``details`` is queryable and indexable with a GIN index, so
  ad-hoc questions do not need a schema change.

Retention is not automatic -- Postgres has no TTL.  ``ensure_schema`` installs
a ``smokeping_purge(days)`` function; schedule it from cron or pg_cron (see the
README).  If you use TimescaleDB, convert the tables to hypertables and use its
retention policies instead.
"""

from __future__ import annotations

import json
from typing import Any

from smokecommon.logging import get_logger
from smokecommon.models import Measurement
from smokeserver.storage.base import (
    HOP_COLUMNS,
    MEASUREMENT_COLUMNS,
    StorageDriver,
    StorageError,
    hop_rows,
    measurement_row,
)

log = get_logger(__name__)


DDL_STATEMENTS: tuple[str, ...] = (
    """
CREATE TABLE IF NOT EXISTS measurements (
    ts               timestamptz      NOT NULL,
    id               text             NOT NULL,
    agent_id         text             NOT NULL,
    agent_location   text             NOT NULL DEFAULT 'unknown',
    agent_tags       jsonb            NOT NULL DEFAULT '{}'::jsonb,
    target_name      text             NOT NULL,
    target_group     text             NOT NULL DEFAULT '/',
    target           text             NOT NULL,
    probe            text             NOT NULL,
    success          boolean          NOT NULL,
    error_type       text             NOT NULL DEFAULT '',
    error_message    text             NOT NULL DEFAULT '',
    latency_ms       double precision,
    rtts_ms          double precision[] NOT NULL DEFAULT '{}',
    rtt_min_ms       double precision,
    rtt_avg_ms       double precision,
    rtt_median_ms    double precision,
    rtt_max_ms       double precision,
    rtt_stddev_ms    double precision,
    rtt_p95_ms       double precision,
    jitter_ms        double precision,
    packets_sent     integer          NOT NULL DEFAULT 0,
    packets_received integer          NOT NULL DEFAULT 0,
    loss_pct         real,
    resolved_ip      text             NOT NULL DEFAULT '',
    ip_family        smallint         NOT NULL DEFAULT 0,
    duration_ms      double precision,
    details          jsonb            NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (ts, id)
)
""",
    """
CREATE TABLE IF NOT EXISTS mtr_hops (
    ts             timestamptz NOT NULL,
    measurement_id text        NOT NULL,
    agent_id       text        NOT NULL,
    agent_location text        NOT NULL DEFAULT 'unknown',
    target_name    text        NOT NULL,
    target_group   text        NOT NULL DEFAULT '/',
    target         text        NOT NULL,
    probe          text        NOT NULL DEFAULT 'mtr',
    hop_no         smallint    NOT NULL,
    hop_host       text        NOT NULL DEFAULT '',
    hop_ip         text        NOT NULL DEFAULT '',
    loss_pct       real,
    sent           integer,
    received       integer,
    last_ms        double precision,
    avg_ms         double precision,
    best_ms        double precision,
    worst_ms       double precision,
    stddev_ms      double precision,
    asn            text        NOT NULL DEFAULT '',
    is_destination boolean     NOT NULL DEFAULT false,
    path_signature text        NOT NULL DEFAULT '',
    PRIMARY KEY (ts, measurement_id, hop_no)
)
""",
    # The dashboard access pattern: pick a vantage point and probe, then scan a
    # time range for one target.  Leading with agent_location matches how every
    # panel is filtered.
    """
CREATE INDEX IF NOT EXISTS measurements_location_probe_target_ts_idx
    ON measurements (agent_location, probe, target_name, ts DESC)
""",
    "CREATE INDEX IF NOT EXISTS measurements_ts_idx ON measurements (ts DESC)",
    """
CREATE INDEX IF NOT EXISTS measurements_resolved_ip_ts_idx
    ON measurements (resolved_ip, ts DESC) WHERE resolved_ip <> ''
""",
    """
CREATE INDEX IF NOT EXISTS measurements_failures_idx
    ON measurements (ts DESC) WHERE success = false
""",
    """
CREATE INDEX IF NOT EXISTS measurements_details_idx
    ON measurements USING gin (details jsonb_path_ops)
""",
    "CREATE INDEX IF NOT EXISTS mtr_hops_ip_ts_idx ON mtr_hops (hop_ip, ts DESC)",
    """
CREATE INDEX IF NOT EXISTS mtr_hops_target_ts_idx
    ON mtr_hops (agent_location, target_name, ts DESC)
""",
    # ------------------------------------------------------------- views ----
    """
CREATE OR REPLACE VIEW v_curl AS
SELECT
    ts, agent_id, agent_location, target_name, target_group, target,
    success, error_type, error_message, latency_ms, resolved_ip,
    (details->>'http_code')::int              AS http_code,
    details->>'http_version'                  AS http_version,
    details->>'url_effective'                 AS url_effective,
    details->>'content_type'                  AS content_type,
    (details->>'num_redirects')::int          AS num_redirects,
    (details->>'dns_ms')::double precision    AS dns_ms,
    (details->>'tcp_connect_ms')::double precision   AS tcp_connect_ms,
    (details->>'tls_handshake_ms')::double precision AS tls_handshake_ms,
    (details->>'request_sent_ms')::double precision  AS request_sent_ms,
    (details->>'ttfb_ms')::double precision          AS ttfb_ms,
    (details->>'server_processing_ms')::double precision AS server_processing_ms,
    (details->>'content_transfer_ms')::double precision  AS content_transfer_ms,
    (details->>'total_ms')::double precision         AS total_ms,
    (details->>'size_download_bytes')::bigint        AS size_download_bytes,
    (details->>'ssl_verify_result')::int             AS ssl_verify_result
FROM measurements
WHERE probe = 'curl'
""",
    """
CREATE OR REPLACE VIEW v_dig AS
SELECT
    ts, agent_id, agent_location, target_name, target_group, target,
    success, error_type, error_message, latency_ms,
    resolved_ip                               AS dns_server_ip,
    details->>'status'                        AS dns_status,
    details->>'query_type'                    AS query_type,
    (details->>'authoritative')::boolean      AS authoritative,
    (details->>'recursion_available')::boolean AS recursion_available,
    (details->>'truncated')::boolean          AS truncated,
    (details->>'answer_count')::int           AS answer_count,
    (details->>'ttl_min')::int                AS ttl_min,
    details->'answer_ips'                     AS answer_ips,
    details->'cname_chain'                    AS cname_chain,
    details->>'transport'                     AS transport
FROM measurements
WHERE probe = 'dig'
""",
    """
CREATE OR REPLACE VIEW v_mtr AS
SELECT
    ts, agent_id, agent_location, target_name, target_group, target,
    success, error_type, latency_ms,
    resolved_ip                                        AS destination_ip,
    details->>'path_signature'                         AS path_signature,
    (details->>'hop_count')::int                       AS hop_count,
    (details->>'silent_hops')::int                     AS silent_hops,
    (details->>'path_complete')::boolean               AS path_complete,
    (details->>'destination_loss_pct')::double precision AS destination_loss_pct,
    (details->>'destination_avg_ms')::double precision   AS destination_avg_ms,
    (details->>'destination_worst_ms')::double precision AS destination_worst_ms,
    details->'path'                                    AS path
FROM measurements
WHERE probe = 'mtr'
""",
    """
CREATE OR REPLACE VIEW v_ip_performance AS
SELECT
    ts, agent_id, agent_location, probe, target_name, target,
    resolved_ip, ip_family, success, latency_ms, loss_pct,
    rtt_median_ms, rtt_p95_ms, jitter_ms
FROM measurements
WHERE resolved_ip <> ''
""",
    # ---------------------------------------------------------- retention ---
    """
CREATE OR REPLACE FUNCTION smokeping_purge(retention_days integer)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
    removed bigint;
    cutoff  timestamptz := now() - make_interval(days => retention_days);
BEGIN
    DELETE FROM mtr_hops     WHERE ts < cutoff;
    DELETE FROM measurements WHERE ts < cutoff;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$
""",
)


class PostgresDriver(StorageDriver):
    """Writes measurements to PostgreSQL via an asyncpg pool."""

    name = "postgresql"

    def __init__(
        self,
        dsn: str,
        pool_min_size: int = 1,
        pool_max_size: int = 10,
        timeout: float = 30.0,
        retention_days: int = 90,
        statement_cache_size: int = 64,
    ) -> None:
        self.dsn = dsn
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self.timeout = timeout
        self.retention_days = retention_days
        self.statement_cache_size = statement_cache_size
        self._pool: Any = None

    # -- lifecycle ---------------------------------------------------------

    async def connect(self) -> None:
        if self._pool is not None:
            return
        try:
            import asyncpg
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise StorageError(
                "the postgresql driver needs asyncpg: pip install 'smokeping-py[postgres]'"
            ) from exc

        try:
            self._pool = await asyncpg.create_pool(
                self.dsn,
                min_size=self.pool_min_size,
                max_size=self.pool_max_size,
                command_timeout=self.timeout,
                # PgBouncer in transaction mode chokes on prepared statements;
                # a modest cache is a reasonable middle ground.
                statement_cache_size=self.statement_cache_size,
                init=_init_connection,
            )
        except Exception as exc:
            raise StorageError(f"cannot connect to PostgreSQL: {exc}") from exc

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    # -- schema ------------------------------------------------------------

    def ddl(self) -> list[str]:
        return [statement.strip() for statement in DDL_STATEMENTS]

    async def ensure_schema(self) -> None:
        if self._pool is None:
            raise StorageError("PostgreSQL driver is not connected")
        async with self._pool.acquire() as conn:
            for statement in self.ddl():
                await conn.execute(statement)
        log.info("postgresql schema ready")

    # -- writes ------------------------------------------------------------

    async def write_measurements(self, measurements: list[Measurement]) -> int:
        if not measurements:
            return 0
        if self._pool is None:
            raise StorageError("PostgreSQL driver is not connected")

        rows = [_measurement_tuple(m) for m in measurements]
        hops = [hop for m in measurements for hop in hop_rows(m)]
        hop_tuples = [_hop_tuple(h) for h in hops]

        try:
            async with self._pool.acquire() as conn, conn.transaction():
                await conn.executemany(MEASUREMENT_INSERT, rows)
                if hop_tuples:
                    await conn.executemany(HOP_INSERT, hop_tuples)
        except Exception as exc:
            raise StorageError(f"PostgreSQL write failed: {exc}") from exc

        return len(rows)

    # -- queries -----------------------------------------------------------

    async def health(self) -> bool:
        if self._pool is None:
            return False
        try:
            async with self._pool.acquire() as conn:
                return await conn.fetchval("SELECT 1") == 1
        except Exception:  # noqa: BLE001
            return False

    async def agents(self) -> list[dict[str, Any]]:
        if self._pool is None:
            raise StorageError("PostgreSQL driver is not connected")
        query = """
            SELECT agent_id,
                   min(agent_location)                     AS agent_location,
                   max(ts)                                 AS last_seen,
                   count(*)                                AS measurements_24h,
                   count(*) FILTER (WHERE NOT success)     AS failures_24h
            FROM measurements
            WHERE ts > now() - interval '1 day'
            GROUP BY agent_id
            ORDER BY agent_id
        """
        async with self._pool.acquire() as conn:
            records = await conn.fetch(query)
        return [dict(record) for record in records]

    async def purge(self, retention_days: int | None = None) -> int:
        """Delete rows older than the retention window."""
        if self._pool is None:
            raise StorageError("PostgreSQL driver is not connected")
        days = retention_days if retention_days is not None else self.retention_days
        async with self._pool.acquire() as conn:
            return int(await conn.fetchval("SELECT smokeping_purge($1)", days) or 0)


# ---------------------------------------------------------------------------
# SQL and row encoding
# ---------------------------------------------------------------------------


def _placeholders(count: int) -> str:
    return ", ".join(f"${i}" for i in range(1, count + 1))


# Only the column names -- module constants -- are interpolated; every value
# goes through an asyncpg $n placeholder.
MEASUREMENT_INSERT = (
    f"INSERT INTO measurements ({', '.join(MEASUREMENT_COLUMNS)}) "
    f"VALUES ({_placeholders(len(MEASUREMENT_COLUMNS))}) "
    # Idempotent replay: an agent re-sending a spooled batch it had already
    # delivered is a no-op rather than a duplicate row.
    "ON CONFLICT (ts, id) DO NOTHING"
)

HOP_INSERT = (
    f"INSERT INTO mtr_hops ({', '.join(HOP_COLUMNS)}) "
    f"VALUES ({_placeholders(len(HOP_COLUMNS))}) "
    "ON CONFLICT (ts, measurement_id, hop_no) DO NOTHING"
)


def _measurement_tuple(m: Measurement) -> tuple[Any, ...]:
    row = measurement_row(m)
    row["success"] = bool(row["success"])
    return tuple(row[column] for column in MEASUREMENT_COLUMNS)


def _hop_tuple(hop: dict[str, Any]) -> tuple[Any, ...]:
    row = dict(hop)
    row["is_destination"] = bool(row["is_destination"])
    return tuple(row[column] for column in HOP_COLUMNS)


async def _init_connection(conn: Any) -> None:
    """Teach asyncpg to pass dicts straight into jsonb columns."""
    for type_name in ("json", "jsonb"):
        await conn.set_type_codec(
            type_name,
            encoder=lambda value: json.dumps(value, default=str, ensure_ascii=False),
            decoder=json.loads,
            schema="pg_catalog",
        )
