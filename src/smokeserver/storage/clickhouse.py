"""ClickHouse storage driver, over the HTTP interface.

Why HTTP rather than the native protocol: it needs no compiled driver, works
through any proxy or load balancer, and ``JSONEachRow`` maps one-to-one onto
the pydantic models we already have.  For a workload of a few thousand rows per
second -- which is a *very* large SmokePing deployment -- the native protocol's
advantage is not worth the dependency.

Durability: inserts run with ``async_insert=1, wait_for_async_insert=1``.
ClickHouse batches concurrent small inserts server-side (which is what it wants
for MergeTree) while still not acknowledging until the data is committed, so a
201 from the agent's point of view really does mean "stored".
"""

from __future__ import annotations

from typing import Any

import httpx

from smokecommon.logging import get_logger
from smokecommon.models import Measurement
from smokeserver.storage.base import (
    StorageDriver,
    StorageError,
    dumps,
    hop_rows,
    measurement_row,
)

log = get_logger(__name__)

#: ClickHouse's canonical DateTime64(3) text format.  Sending this instead of
#: ISO-8601 avoids relying on `date_time_input_format=best_effort`.
_TS_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def _clickhouse_ts(value: Any) -> str:
    return value.strftime(_TS_FORMAT)[:-3]


DDL_STATEMENTS: tuple[str, ...] = (
    "CREATE DATABASE IF NOT EXISTS {db}",
    # ---------------------------------------------------------------- main --
    """
CREATE TABLE IF NOT EXISTS {db}.measurements
(
    ts               DateTime64(3, 'UTC'),
    id               String,
    agent_id         LowCardinality(String),
    agent_location   LowCardinality(String),
    agent_tags       Map(LowCardinality(String), String),
    target_name      LowCardinality(String),
    target_group     LowCardinality(String),
    target           String,
    probe            LowCardinality(String),
    success          UInt8,
    error_type       LowCardinality(String),
    error_message    String,
    latency_ms       Nullable(Float64),
    rtts_ms          Array(Float64),
    rtt_min_ms       Nullable(Float64),
    rtt_avg_ms       Nullable(Float64),
    rtt_median_ms    Nullable(Float64),
    rtt_max_ms       Nullable(Float64),
    rtt_stddev_ms    Nullable(Float64),
    rtt_p95_ms       Nullable(Float64),
    jitter_ms        Nullable(Float64),
    packets_sent     UInt16,
    packets_received UInt16,
    loss_pct         Nullable(Float32),
    resolved_ip      String,
    ip_family        UInt8,
    duration_ms      Nullable(Float64),
    details          String,

    INDEX idx_resolved_ip resolved_ip TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_target      target      TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
-- Location first: every dashboard filters by vantage point before anything
-- else, and it is the lowest-cardinality useful prefix.
ORDER BY (agent_location, agent_id, probe, target_name, ts)
TTL toDateTime(ts) + INTERVAL {retention_days} DAY
SETTINGS index_granularity = 8192
""",
    # ---------------------------------------------------------------- hops --
    """
CREATE TABLE IF NOT EXISTS {db}.mtr_hops
(
    ts             DateTime64(3, 'UTC'),
    measurement_id String,
    agent_id       LowCardinality(String),
    agent_location LowCardinality(String),
    target_name    LowCardinality(String),
    target_group   LowCardinality(String),
    target         String,
    probe          LowCardinality(String),
    hop_no         UInt8,
    hop_host       String,
    hop_ip         String,
    loss_pct       Nullable(Float32),
    sent           Nullable(UInt16),
    received       Nullable(UInt16),
    last_ms        Nullable(Float64),
    avg_ms         Nullable(Float64),
    best_ms        Nullable(Float64),
    worst_ms       Nullable(Float64),
    stddev_ms      Nullable(Float64),
    asn            String,
    is_destination UInt8,
    path_signature String,

    INDEX idx_hop_ip hop_ip TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (agent_location, target_name, ts, hop_no)
TTL toDateTime(ts) + INTERVAL {retention_days} DAY
SETTINGS index_granularity = 8192
""",
    # --------------------------------------------------------------- views --
    # Probe-specific views keep the base table generic while giving Grafana
    # real columns to point at.  They are free: ClickHouse expands them at
    # query time and the bloom-filter indexes still apply.
    """
CREATE OR REPLACE VIEW {db}.v_curl AS
SELECT
    ts, agent_id, agent_location, target_name, target_group, target,
    success, error_type, error_message, latency_ms, resolved_ip,
    toUInt16OrZero(JSONExtractString(details, 'http_code'))  AS http_code,
    JSONExtractString(details, 'http_version')               AS http_version,
    JSONExtractString(details, 'url_effective')              AS url_effective,
    JSONExtractString(details, 'content_type')               AS content_type,
    JSONExtractInt(details, 'num_redirects')                 AS num_redirects,
    JSONExtractFloat(details, 'dns_ms')                      AS dns_ms,
    JSONExtractFloat(details, 'tcp_connect_ms')              AS tcp_connect_ms,
    JSONExtractFloat(details, 'tls_handshake_ms')            AS tls_handshake_ms,
    JSONExtractFloat(details, 'request_sent_ms')             AS request_sent_ms,
    JSONExtractFloat(details, 'ttfb_ms')                     AS ttfb_ms,
    JSONExtractFloat(details, 'server_processing_ms')        AS server_processing_ms,
    JSONExtractFloat(details, 'content_transfer_ms')         AS content_transfer_ms,
    JSONExtractFloat(details, 'total_ms')                    AS total_ms,
    JSONExtractInt(details, 'size_download_bytes')           AS size_download_bytes,
    JSONExtractInt(details, 'ssl_verify_result')             AS ssl_verify_result
FROM {db}.measurements
WHERE probe = 'curl'
""",
    """
CREATE OR REPLACE VIEW {db}.v_dig AS
SELECT
    ts, agent_id, agent_location, target_name, target_group, target,
    success, error_type, error_message, latency_ms,
    resolved_ip                                              AS dns_server_ip,
    JSONExtractString(details, 'status')                     AS dns_status,
    JSONExtractString(details, 'query_type')                 AS query_type,
    JSONExtractBool(details, 'authoritative')                AS authoritative,
    JSONExtractBool(details, 'recursion_available')          AS recursion_available,
    JSONExtractBool(details, 'truncated')                    AS truncated,
    JSONExtractInt(details, 'answer_count')                  AS answer_count,
    JSONExtractInt(details, 'ttl_min')                       AS ttl_min,
    JSONExtract(details, 'answer_ips', 'Array(String)')      AS answer_ips,
    JSONExtract(details, 'cname_chain', 'Array(String)')     AS cname_chain,
    JSONExtractString(details, 'transport')                  AS transport
FROM {db}.measurements
WHERE probe = 'dig'
""",
    """
CREATE OR REPLACE VIEW {db}.v_mtr AS
SELECT
    ts, agent_id, agent_location, target_name, target_group, target,
    success, error_type, latency_ms, resolved_ip              AS destination_ip,
    JSONExtractString(details, 'path_signature')              AS path_signature,
    JSONExtractInt(details, 'hop_count')                      AS hop_count,
    JSONExtractInt(details, 'silent_hops')                    AS silent_hops,
    JSONExtractBool(details, 'path_complete')                 AS path_complete,
    JSONExtractFloat(details, 'destination_loss_pct')         AS destination_loss_pct,
    JSONExtractFloat(details, 'destination_avg_ms')           AS destination_avg_ms,
    JSONExtractFloat(details, 'destination_worst_ms')         AS destination_worst_ms,
    JSONExtract(details, 'path', 'Array(String)')             AS path
FROM {db}.measurements
WHERE probe = 'mtr'
""",
    # Per-(target, resolved IP) rollup: "which endpoint is slow" in one scan.
    """
CREATE OR REPLACE VIEW {db}.v_ip_performance AS
SELECT
    ts, agent_id, agent_location, probe, target_name, target,
    resolved_ip, ip_family, success, latency_ms, loss_pct,
    rtt_median_ms, rtt_p95_ms, jitter_ms
FROM {db}.measurements
WHERE resolved_ip != ''
""",
)


class ClickHouseDriver(StorageDriver):
    """Writes measurements to ClickHouse over HTTP."""

    name = "clickhouse"

    def __init__(
        self,
        url: str = "http://localhost:8123",
        database: str = "smokeping",
        user: str = "default",
        password: str = "",
        timeout: float = 30.0,
        retention_days: int = 90,
        async_insert: bool = True,
        verify_tls: bool = True,
    ) -> None:
        self.url = url.rstrip("/")
        self.database = database
        self.user = user
        self.password = password
        self.timeout = timeout
        self.retention_days = retention_days
        self.async_insert = async_insert
        self.verify_tls = verify_tls
        self._client: httpx.AsyncClient | None = None

    # -- lifecycle ---------------------------------------------------------

    async def connect(self) -> None:
        if self._client is not None:
            return
        self._client = httpx.AsyncClient(
            base_url=self.url,
            timeout=self.timeout,
            verify=self.verify_tls,
            headers={
                "X-ClickHouse-User": self.user,
                "X-ClickHouse-Key": self.password,
            },
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- schema ------------------------------------------------------------

    def ddl(self) -> list[str]:
        """The full DDL, rendered for this driver's database and retention."""
        return [
            statement.format(db=self.database, retention_days=self.retention_days).strip()
            for statement in DDL_STATEMENTS
        ]

    async def ensure_schema(self) -> None:
        for statement in self.ddl():
            await self._execute(statement)
        log.info(
            "clickhouse schema ready",
            extra={"database": self.database, "retention_days": self.retention_days},
        )

    # -- writes ------------------------------------------------------------

    async def write_measurements(self, measurements: list[Measurement]) -> int:
        if not measurements:
            return 0

        rows = [self._encode_measurement(m) for m in measurements]
        await self._insert("measurements", rows)

        hops = [hop for m in measurements for hop in hop_rows(m)]
        if hops:
            await self._insert("mtr_hops", [self._encode_hop(h) for h in hops])

        return len(rows)

    def _encode_measurement(self, m: Measurement) -> dict[str, Any]:
        row = measurement_row(m)
        row["ts"] = _clickhouse_ts(row["ts"])
        # `details` is a String column, so it has to arrive as JSON *text*, not
        # as a nested object.
        row["details"] = dumps(row["details"])
        return row

    @staticmethod
    def _encode_hop(hop: dict[str, Any]) -> dict[str, Any]:
        row = dict(hop)
        row["ts"] = _clickhouse_ts(row["ts"])
        return row

    async def _insert(self, table: str, rows: list[dict[str, Any]]) -> None:
        body = "\n".join(dumps(row) for row in rows).encode("utf-8")
        params: dict[str, str] = {
            "query": f"INSERT INTO {self.database}.{table} FORMAT JSONEachRow",
            # Never let a malformed field from one probe reject the whole batch
            # silently -- we want the error surfaced instead.
            "input_format_skip_unknown_fields": "0",
        }
        if self.async_insert:
            params["async_insert"] = "1"
            params["wait_for_async_insert"] = "1"

        await self._post(params, body, context=f"insert into {table} ({len(rows)} rows)")

    # -- queries -----------------------------------------------------------

    async def health(self) -> bool:
        try:
            text = await self._execute("SELECT 1", read=True)
        except StorageError:
            return False
        return text.strip() == "1"

    async def agents(self) -> list[dict[str, Any]]:
        # The only interpolated value is the database name from our own config
        # file, never anything that arrived over the network.
        query = f"""
            SELECT
                agent_id,
                any(agent_location) AS agent_location,
                max(ts)             AS last_seen,
                count()             AS measurements_24h,
                countIf(success = 0) AS failures_24h
            FROM {self.database}.measurements
            WHERE ts > now() - INTERVAL 1 DAY
            GROUP BY agent_id
            ORDER BY agent_id
            FORMAT JSONEachRow
        """
        text = await self._execute(query, read=True)
        import json as _json

        return [_json.loads(line) for line in text.splitlines() if line.strip()]

    # -- transport ---------------------------------------------------------

    async def _execute(self, statement: str, read: bool = False) -> str:
        return await self._post({}, statement.encode("utf-8"), context=statement[:80], read=read)

    async def _post(
        self,
        params: dict[str, str],
        body: bytes,
        context: str,
        read: bool = False,
    ) -> str:
        if self._client is None:
            raise StorageError("ClickHouse driver is not connected")
        try:
            response = await self._client.post("/", params=params, content=body)
        except httpx.HTTPError as exc:
            raise StorageError(f"ClickHouse request failed ({context}): {exc}") from exc

        if response.status_code >= 400:
            raise StorageError(
                f"ClickHouse rejected request ({context}): "
                f"HTTP {response.status_code}: {response.text[:500]}"
            )
        return response.text if read else ""
