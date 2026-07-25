"""Server ingest API, driven through ASGI with a fake storage driver.

The most important behaviour here is the failure contract: a storage outage
must return 503 (so the agent spools and retries) while a malformed payload
must return 400 (so the agent drops it instead of retrying forever).
"""

from __future__ import annotations

import gzip
from typing import Any

import httpx
import pytest

from smokecommon.models import Measurement, MeasurementBatch
from smokecommon.version import PROTOCOL_VERSION
from smokeserver.app import create_app
from smokeserver.config import ApiKeyConfig, AuthConfig, ServerSettings, StorageConfig
from smokeserver.storage.base import StorageDriver, StorageError, hop_rows

from conftest import make_measurement

API_KEY = "test-api-key"


class FakeDriver(StorageDriver):
    """In-memory driver so the API tests need no database."""

    name = "fake"

    def __init__(self) -> None:
        self.rows: list[Measurement] = []
        self.hops: list[dict[str, Any]] = []
        self.fail_with: Exception | None = None
        self.connected = False
        self.schema_calls = 0
        self.healthy = True

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.connected = False

    async def ensure_schema(self) -> None:
        self.schema_calls += 1

    async def write_measurements(self, measurements: list[Measurement]) -> int:
        if self.fail_with is not None:
            raise self.fail_with
        self.rows.extend(measurements)
        for m in measurements:
            self.hops.extend(hop_rows(m))
        return len(measurements)

    async def health(self) -> bool:
        return self.healthy

    async def agents(self) -> list[dict[str, Any]]:
        return [{"agent_id": "agent-1", "measurements_24h": len(self.rows)}]


def make_settings(**auth_overrides: Any) -> ServerSettings:
    return ServerSettings(
        auth=AuthConfig(
            keys=[ApiKeyConfig(key=API_KEY, label="test", agent_ids=["*"])],
            **auth_overrides,
        ),
        storage=StorageConfig(driver="fake", ensure_schema=True),
    )


@pytest.fixture
def driver() -> FakeDriver:
    return FakeDriver()


@pytest.fixture
async def client(driver):
    app = create_app(make_settings(), storage=driver)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        # Run the lifespan so connect()/ensure_schema() happen as in production.
        async with app.router.lifespan_context(app):
            yield c


def batch_payload(*measurements: Measurement, **overrides: Any) -> str:
    batch = MeasurementBatch(
        agent_id=overrides.pop("agent_id", "agent-1"),
        agent_location=overrides.pop("agent_location", "seoul"),
        measurements=list(measurements) or [make_measurement()],
        **overrides,
    )
    return batch.model_dump_json()


class TestIngest:
    async def test_accepts_a_valid_batch(self, client, driver):
        response = await client.post(
            "/api/v1/measurements",
            content=batch_payload(),
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 201
        assert response.json()["accepted"] == 1
        assert len(driver.rows) == 1

    async def test_stores_the_vantage_point(self, client, driver):
        await client.post(
            "/api/v1/measurements",
            content=batch_payload(make_measurement(agent_location="frankfurt")),
            headers={"X-API-Key": API_KEY},
        )
        assert driver.rows[0].agent_location == "frankfurt"

    async def test_accepts_gzip(self, client, driver):
        body = gzip.compress(batch_payload().encode("utf-8"))
        response = await client.post(
            "/api/v1/measurements",
            content=body,
            headers={"X-API-Key": API_KEY, "Content-Encoding": "gzip"},
        )
        assert response.status_code == 201
        assert len(driver.rows) == 1

    async def test_invalid_gzip_is_a_400(self, client):
        response = await client.post(
            "/api/v1/measurements",
            content=b"not actually gzip",
            headers={"X-API-Key": API_KEY, "Content-Encoding": "gzip"},
        )
        assert response.status_code == 400

    async def test_failed_measurements_are_stored_too(self, client, driver):
        # Recording failures is the whole point; they must not be filtered out.
        failed = make_measurement(
            success=False,
            error_type="timeout",
            error_message="ping exceeded 10s",
            latency_ms=None,
            rtts_ms=[],
            packets_received=0,
            loss_pct=100.0,
        )
        response = await client.post(
            "/api/v1/measurements",
            content=batch_payload(failed),
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 201
        assert driver.rows[0].success is False
        assert driver.rows[0].error_message == "ping exceeded 10s"

    async def test_mtr_hops_are_flattened(self, client, driver):
        from smokecommon.models import HopResult

        measurement = make_measurement(
            probe="mtr",
            details={"path_signature": "abc123"},
            hops=[
                HopResult(hop_no=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.2),
                HopResult(hop_no=2, ip="8.8.8.8", loss_pct=0.0, avg_ms=35.0),
            ],
        )
        await client.post(
            "/api/v1/measurements",
            content=batch_payload(measurement),
            headers={"X-API-Key": API_KEY},
        )
        assert len(driver.hops) == 2
        assert driver.hops[0]["hop_ip"] == "192.168.1.1"
        assert driver.hops[1]["is_destination"] == 1
        assert driver.hops[0]["path_signature"] == "abc123"

    async def test_empty_batch_is_accepted(self, client, driver):
        batch = MeasurementBatch(agent_id="agent-1", measurements=[])
        response = await client.post(
            "/api/v1/measurements",
            content=batch.model_dump_json(),
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 201
        assert response.json()["accepted"] == 0

    async def test_large_batch(self, client, driver):
        payload = batch_payload(*[make_measurement() for _ in range(200)])
        response = await client.post(
            "/api/v1/measurements", content=payload, headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 201
        assert len(driver.rows) == 200


class TestFailureContract:
    async def test_storage_failure_is_503_so_the_agent_spools(self, client, driver):
        driver.fail_with = StorageError("clickhouse is down")
        response = await client.post(
            "/api/v1/measurements",
            content=batch_payload(),
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 503
        assert response.headers.get("Retry-After")
        assert driver.rows == []

    async def test_malformed_json_is_400_so_the_agent_drops_it(self, client):
        response = await client.post(
            "/api/v1/measurements",
            content=b"{ not json",
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 400

    async def test_wrong_shape_is_400(self, client):
        response = await client.post(
            "/api/v1/measurements",
            content=b'{"agent_id": "a"}',  # no `measurements`
            headers={"X-API-Key": API_KEY},
        )
        assert response.status_code == 400

    async def test_future_protocol_version_is_rejected_with_a_clear_message(self, client):
        payload = batch_payload(protocol_version=PROTOCOL_VERSION + 5)
        response = await client.post(
            "/api/v1/measurements", content=payload, headers={"X-API-Key": API_KEY}
        )
        assert response.status_code == 400
        assert "upgrade smoke-server" in response.json()["detail"]

    async def test_oversized_payload_is_413(self, driver):
        settings = make_settings()
        settings.http.max_body_bytes = 100
        app = create_app(settings, storage=driver)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            async with app.router.lifespan_context(app):
                response = await c.post(
                    "/api/v1/measurements",
                    content=batch_payload(*[make_measurement() for _ in range(20)]),
                    headers={"X-API-Key": API_KEY},
                )
        assert response.status_code == 413


class TestAuth:
    async def test_missing_key_is_401(self, client):
        response = await client.post("/api/v1/measurements", content=batch_payload())
        assert response.status_code == 401

    async def test_wrong_key_is_401(self, client):
        response = await client.post(
            "/api/v1/measurements",
            content=batch_payload(),
            headers={"X-API-Key": "nope"},
        )
        assert response.status_code == 401

    async def test_agent_id_binding_is_enforced(self, driver):
        settings = ServerSettings(
            auth=AuthConfig(
                keys=[ApiKeyConfig(key=API_KEY, label="seoul", agent_ids=["seoul-1"])]
            ),
            storage=StorageConfig(driver="fake"),
        )
        app = create_app(settings, storage=driver)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            async with app.router.lifespan_context(app):
                allowed = await c.post(
                    "/api/v1/measurements",
                    content=batch_payload(agent_id="seoul-1"),
                    headers={"X-API-Key": API_KEY},
                )
                forged = await c.post(
                    "/api/v1/measurements",
                    content=batch_payload(agent_id="frankfurt-1"),
                    headers={"X-API-Key": API_KEY},
                )
        assert allowed.status_code == 201
        assert forged.status_code == 403


class TestOperationalEndpoints:
    async def test_healthz_needs_no_auth_and_no_database(self, client, driver):
        driver.healthy = False  # must not matter
        response = await client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["protocol_version"] == PROTOCOL_VERSION

    async def test_readyz_reflects_the_driver(self, client, driver):
        assert (await client.get("/readyz")).status_code == 200
        driver.healthy = False
        assert (await client.get("/readyz")).status_code == 503

    async def test_metrics_are_prometheus_text(self, client):
        await client.post(
            "/api/v1/measurements",
            content=batch_payload(),
            headers={"X-API-Key": API_KEY},
        )
        response = await client.get("/metrics")

        assert response.status_code == 200
        body = response.text
        assert "# TYPE smokeping_measurements_written_total counter" in body
        assert "smokeping_measurements_written_total 1" in body
        assert 'smokeping_agent_measurements_total{agent_id="agent-1"} 1' in body

    async def test_metrics_count_failed_probes_separately(self, client):
        await client.post(
            "/api/v1/measurements",
            content=batch_payload(make_measurement(success=False, error_type="timeout")),
            headers={"X-API-Key": API_KEY},
        )
        body = (await client.get("/metrics")).text
        assert "smokeping_measurements_failed_total 1" in body

    async def test_info(self, client):
        response = await client.get("/api/v1/info")
        assert response.status_code == 200
        assert response.json()["driver"] == "fake"

    async def test_agents_requires_auth(self, client):
        assert (await client.get("/api/v1/agents")).status_code == 401
        ok = await client.get("/api/v1/agents", headers={"X-API-Key": API_KEY})
        assert ok.status_code == 200
        assert ok.json()["agents"][0]["agent_id"] == "agent-1"

    async def test_request_id_is_echoed(self, client):
        response = await client.get("/healthz", headers={"X-Request-Id": "abc123"})
        assert response.headers["X-Request-Id"] == "abc123"

    async def test_request_id_is_generated_when_absent(self, client):
        assert (await client.get("/healthz")).headers["X-Request-Id"]


class TestLifespan:
    async def test_schema_is_applied_at_startup(self, driver):
        app = create_app(make_settings(), storage=driver)
        async with app.router.lifespan_context(app):
            assert driver.connected is True
            assert driver.schema_calls == 1
        assert driver.connected is False

    async def test_schema_can_be_left_to_a_migration_tool(self, driver):
        settings = make_settings()
        settings.storage.ensure_schema = False
        app = create_app(settings, storage=driver)
        async with app.router.lifespan_context(app):
            pass
        assert driver.schema_calls == 0
