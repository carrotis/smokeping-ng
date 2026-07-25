"""Storage: row flattening, ClickHouse encoding, and driver selection.

The ClickHouse driver is exercised through an ``httpx.MockTransport``, which
covers everything except ClickHouse itself: the URL, the query parameters, the
JSONEachRow body and the timestamp format.
"""

from __future__ import annotations

import json

import httpx
import pytest

from smokecommon.models import HopResult
from smokeserver.storage import HOP_COLUMNS, MEASUREMENT_COLUMNS, create_driver
from smokeserver.storage.base import StorageError, hop_rows, measurement_row
from smokeserver.storage.clickhouse import ClickHouseDriver
from smokeserver.storage.postgres import (
    HOP_INSERT,
    MEASUREMENT_INSERT,
    PostgresDriver,
    _hop_tuple,
    _measurement_tuple,
)

from conftest import make_measurement


class TestMeasurementRow:
    def test_has_exactly_the_declared_columns(self):
        # Guards against a column being added to the DDL but not the encoder.
        assert set(measurement_row(make_measurement())) == set(MEASUREMENT_COLUMNS)

    def test_stats_are_expanded_into_real_columns(self):
        row = measurement_row(make_measurement(rtts_ms=[10.0, 20.0, 30.0]))
        assert row["rtt_min_ms"] == 10.0
        assert row["rtt_max_ms"] == 30.0
        assert row["rtt_median_ms"] == 20.0
        assert row["rtt_avg_ms"] == 20.0
        assert row["jitter_ms"] is not None

    def test_missing_stats_become_nulls_not_zeros(self):
        # A failed probe has no latency; storing 0 ms would poison every
        # average on the dashboard.
        row = measurement_row(make_measurement(success=False, rtts_ms=[], latency_ms=None))
        assert row["rtt_median_ms"] is None
        assert row["latency_ms"] is None
        assert row["success"] == 0

    def test_error_message_is_truncated(self):
        row = measurement_row(make_measurement(error_message="x" * 5000))
        assert len(row["error_message"]) == 2000

    def test_none_ip_becomes_empty_string_not_null(self):
        # Keeps the column NOT NULL and makes `resolved_ip <> ''` filters work.
        row = measurement_row(make_measurement(resolved_ip=None))
        assert row["resolved_ip"] == ""


class TestHopRows:
    def test_no_hops_no_rows(self):
        assert hop_rows(make_measurement()) == []

    def test_columns_match_the_declaration(self):
        m = make_measurement(probe="mtr", hops=[HopResult(hop_no=1, ip="10.0.0.1")])
        assert set(hop_rows(m)[0]) == set(HOP_COLUMNS)

    def test_last_hop_is_flagged_as_the_destination(self):
        m = make_measurement(
            probe="mtr",
            details={"path_signature": "sig1"},
            hops=[
                HopResult(hop_no=1, ip="10.0.0.1", loss_pct=0.0, avg_ms=1.0),
                HopResult(hop_no=2, ip="10.0.0.2", loss_pct=0.0, avg_ms=5.0),
                HopResult(hop_no=3, ip="8.8.8.8", loss_pct=0.0, avg_ms=35.0),
            ],
        )
        rows = hop_rows(m)
        assert [r["is_destination"] for r in rows] == [0, 0, 1]

    def test_rows_inherit_the_measurement_identity(self):
        m = make_measurement(
            probe="mtr", agent_location="frankfurt", hops=[HopResult(hop_no=1, ip="10.0.0.1")]
        )
        row = hop_rows(m)[0]
        assert row["measurement_id"] == m.id
        assert row["agent_location"] == "frankfurt"
        assert row["ts"] == m.ts

    def test_silent_hop_keeps_its_position(self):
        m = make_measurement(
            probe="mtr",
            hops=[HopResult(hop_no=1, ip="10.0.0.1"), HopResult(hop_no=2, ip=None, loss_pct=100.0)],
        )
        rows = hop_rows(m)
        assert rows[1]["hop_ip"] == ""
        assert rows[1]["hop_no"] == 2


class TestDriverFactory:
    @pytest.mark.parametrize("alias", ["clickhouse", "ch", "ClickHouse"])
    def test_clickhouse_aliases(self, alias):
        assert create_driver(alias, {}).name == "clickhouse"

    @pytest.mark.parametrize("alias", ["postgresql", "postgres", "pg"])
    def test_postgres_aliases(self, alias):
        assert create_driver(alias, {"dsn": "postgresql://x"}).name == "postgresql"

    def test_unknown_driver_lists_the_options(self):
        with pytest.raises(StorageError, match="clickhouse"):
            create_driver("mysql", {})

    def test_options_reach_the_driver(self):
        driver = create_driver("clickhouse", {"database": "custom", "retention_days": 7})
        assert driver.database == "custom"
        assert driver.retention_days == 7


class TestClickHouseSchema:
    def test_ddl_renders_the_configured_database_and_retention(self):
        ddl = "\n".join(ClickHouseDriver(database="metrics", retention_days=30).ddl())
        assert "metrics.measurements" in ddl
        assert "INTERVAL 30 DAY" in ddl
        assert "{db}" not in ddl

    def test_ddl_creates_both_tables_and_the_probe_views(self):
        ddl = "\n".join(ClickHouseDriver().ddl())
        for expected in (
            "smokeping.measurements",
            "smokeping.mtr_hops",
            "smokeping.v_curl",
            "smokeping.v_dig",
            "smokeping.v_mtr",
            "smokeping.v_ip_performance",
        ):
            assert expected in ddl

    def test_order_by_leads_with_the_vantage_point(self):
        ddl = "\n".join(ClickHouseDriver().ddl())
        assert "ORDER BY (agent_location, agent_id, probe, target_name, ts)" in ddl


class TestClickHouseWrites:
    def make(self, handler, **kwargs):
        driver = ClickHouseDriver(**kwargs)
        driver._client = httpx.AsyncClient(
            base_url=driver.url, transport=httpx.MockTransport(handler)
        )
        return driver

    async def test_insert_uses_jsoneachrow(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["url"] = str(request.url)
            captured["body"] = request.content.decode()
            return httpx.Response(200, text="")

        driver = self.make(handler)
        written = await driver.write_measurements([make_measurement()])

        assert written == 1
        assert "INSERT+INTO+smokeping.measurements+FORMAT+JSONEachRow" in captured["url"].replace(
            "%20", "+"
        )
        assert "async_insert=1" in captured["url"]
        assert "wait_for_async_insert=1" in captured["url"]

    async def test_timestamp_uses_clickhouse_datetime64_format(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.setdefault("bodies", []).append(request.content.decode())
            return httpx.Response(200, text="")

        driver = self.make(handler)
        await driver.write_measurements([make_measurement()])

        row = json.loads(captured["bodies"][0].splitlines()[0])
        # "YYYY-MM-DD HH:MM:SS.mmm" -- not ISO, so no best_effort parsing needed.
        assert "T" not in row["ts"]
        assert len(row["ts"]) == 23
        assert row["ts"][10] == " "

    async def test_details_are_sent_as_a_json_string(self):
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.setdefault("bodies", []).append(request.content.decode())
            return httpx.Response(200, text="")

        driver = self.make(handler)
        await driver.write_measurements(
            [make_measurement(details={"http_code": 200, "nested": {"a": 1}})]
        )

        row = json.loads(captured["bodies"][0].splitlines()[0])
        # The column is String, so the value must arrive as text, not an object.
        assert isinstance(row["details"], str)
        assert json.loads(row["details"])["nested"] == {"a": 1}

    async def test_hops_go_to_their_own_table(self):
        bodies: list[tuple[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            bodies.append((str(request.url), request.content.decode()))
            return httpx.Response(200, text="")

        driver = self.make(handler)
        await driver.write_measurements(
            [
                make_measurement(
                    probe="mtr",
                    hops=[HopResult(hop_no=1, ip="10.0.0.1"), HopResult(hop_no=2, ip="8.8.8.8")],
                )
            ]
        )

        assert len(bodies) == 2
        assert "mtr_hops" in bodies[1][0]
        assert len(bodies[1][1].strip().splitlines()) == 2

    async def test_no_hop_request_when_there_are_no_hops(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, text="")

        driver = self.make(handler)
        await driver.write_measurements([make_measurement()])
        assert len(calls) == 1

    async def test_a_clickhouse_error_becomes_a_storage_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Code: 241. DB::Exception: Memory limit exceeded")

        driver = self.make(handler)
        with pytest.raises(StorageError, match="Memory limit"):
            await driver.write_measurements([make_measurement()])

    async def test_a_network_error_becomes_a_storage_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        driver = self.make(handler)
        with pytest.raises(StorageError, match="request failed"):
            await driver.write_measurements([make_measurement()])

    async def test_health_check(self):
        driver = self.make(lambda request: httpx.Response(200, text="1\n"))
        assert await driver.health() is True

        unhealthy = self.make(lambda request: httpx.Response(503, text="down"))
        assert await unhealthy.health() is False

    async def test_empty_batch_makes_no_request(self):
        calls = []
        driver = self.make(
            lambda request: (calls.append(1), httpx.Response(200, text=""))[1]
        )
        assert await driver.write_measurements([]) == 0
        assert calls == []

    async def test_writing_without_connect_is_a_clear_error(self):
        with pytest.raises(StorageError, match="not connected"):
            await ClickHouseDriver().write_measurements([make_measurement()])


class TestPostgresEncoding:
    def test_insert_columns_and_placeholders_line_up(self):
        assert MEASUREMENT_INSERT.count("$") == len(MEASUREMENT_COLUMNS)
        assert HOP_INSERT.count("$") == len(HOP_COLUMNS)

    def test_insert_is_idempotent_on_replay(self):
        # An agent re-sending a spooled batch it had already delivered must not
        # create duplicate rows.
        assert "ON CONFLICT (ts, id) DO NOTHING" in MEASUREMENT_INSERT
        assert "ON CONFLICT (ts, measurement_id, hop_no) DO NOTHING" in HOP_INSERT

    def test_tuple_order_matches_the_column_order(self):
        m = make_measurement()
        row = _measurement_tuple(m)
        assert len(row) == len(MEASUREMENT_COLUMNS)
        assert row[MEASUREMENT_COLUMNS.index("agent_location")] == "seoul"
        assert row[MEASUREMENT_COLUMNS.index("target")] == "8.8.8.8"

    def test_success_is_a_real_boolean_for_postgres(self):
        row = _measurement_tuple(make_measurement(success=True))
        assert row[MEASUREMENT_COLUMNS.index("success")] is True

    def test_hop_tuple_uses_a_boolean_destination_flag(self):
        m = make_measurement(probe="mtr", hops=[HopResult(hop_no=1, ip="8.8.8.8")])
        row = _hop_tuple(hop_rows(m)[0])
        assert row[HOP_COLUMNS.index("is_destination")] is True

    def test_ddl_declares_the_indexes_the_dashboards_need(self):
        ddl = "\n".join(PostgresDriver(dsn="").ddl())
        assert "measurements_location_probe_target_ts_idx" in ddl
        assert "measurements_resolved_ip_ts_idx" in ddl
        assert "USING gin (details jsonb_path_ops)" in ddl

    def test_ddl_defines_the_same_views_as_clickhouse(self):
        pg_ddl = "\n".join(PostgresDriver(dsn="").ddl())
        ch_ddl = "\n".join(ClickHouseDriver().ddl())
        for view in ("v_curl", "v_dig", "v_mtr", "v_ip_performance"):
            assert view in pg_ddl, f"{view} missing from postgres DDL"
            assert view in ch_ddl, f"{view} missing from clickhouse DDL"

    def test_ddl_installs_a_retention_function(self):
        assert "smokeping_purge" in "\n".join(PostgresDriver(dsn="").ddl())

    async def test_operations_without_a_pool_fail_clearly(self):
        driver = PostgresDriver(dsn="postgresql://nowhere/db")
        with pytest.raises(StorageError, match="not connected"):
            await driver.write_measurements([make_measurement()])
        assert await driver.health() is False
