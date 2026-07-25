"""End-to-end: probe -> scheduler -> shipper -> HTTP -> server -> storage.

Everything here is the real component except the probe (a deterministic double,
so the test needs no network) and the database (an in-memory driver).  In
particular the agent's HTTP client talks to the actual FastAPI app over ASGI,
so the wire format, gzip, authentication and the failure contract are all
exercised for real.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from smokeagent.config import parse_agent_config
from smokeagent.probes.base import Probe, ProbeTarget, register_probe
from smokeagent.scheduler import Scheduler
from smokeagent.shipper import Shipper
from smokeagent.spool import Spool
from smokecommon.errors import ErrorType
from smokecommon.models import HopResult, Measurement, ProbeResult
from smokeserver.app import create_app
from smokeserver.config import ApiKeyConfig, AuthConfig, ServerSettings, StorageConfig
from smokeserver.storage.base import StorageDriver, StorageError, hop_rows

API_KEY = "e2e-api-key"
AGENT_ID = "e2e-agent-01"


@register_probe
class E2EProbe(Probe):
    """Emits a fixed ping-like result, or an mtr-like one with hops."""

    name = "e2e"
    default_options = {"timeout": 1.0, "mode": "ping"}

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        if target.address == "unreachable.example":
            return ProbeResult.failure(
                ErrorType.TIMEOUT, "no reply within 10s", packets_sent=5
            )
        if self.options["mode"] == "mtr":
            return ProbeResult(
                success=True,
                latency_ms=35.4,
                packets_sent=5,
                packets_received=5,
                resolved_ip="8.8.8.8",
                details={"path_signature": "abc123def456", "hop_count": 3},
                hops=[
                    HopResult(hop_no=1, ip="192.168.1.1", loss_pct=0.0, avg_ms=1.3),
                    HopResult(hop_no=2, ip="10.20.30.40", loss_pct=0.0, avg_ms=12.5),
                    HopResult(hop_no=3, ip="8.8.8.8", loss_pct=0.0, avg_ms=35.4),
                ],
            )
        return ProbeResult(
            success=True,
            rtts_ms=[11.0, 12.0, 13.0, 14.0, 40.0],
            packets_sent=5,
            packets_received=5,
            resolved_ip="8.8.8.8",
            details={"command": "e2e"},
        )


class MemoryDriver(StorageDriver):
    name = "memory"

    def __init__(self) -> None:
        self.rows: list[Measurement] = []
        self.hops: list[dict[str, Any]] = []
        self.fail_with: Exception | None = None

    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def ensure_schema(self) -> None: ...
    async def health(self) -> bool:
        return self.fail_with is None

    async def write_measurements(self, measurements: list[Measurement]) -> int:
        if self.fail_with is not None:
            raise self.fail_with
        self.rows.extend(measurements)
        for m in measurements:
            self.hops.extend(hop_rows(m))
        return len(measurements)


def agent_config(targets: list[dict[str, Any]], **server_overrides: Any):
    return parse_agent_config(
        {
            "agent": {
                "id": AGENT_ID,
                "location": "seoul-idc",
                "tags": {"region": "kr", "isp": "kt"},
            },
            "server": {
                "url": "http://smoke-server",
                "api_key": API_KEY,
                "batch_max_size": 1000,
                "retry_initial_delay": 0.001,
                **server_overrides,
            },
            "targets": targets,
        },
        environ={},
    )


@pytest.fixture
def storage() -> MemoryDriver:
    return MemoryDriver()


@pytest.fixture
async def app(storage):
    settings = ServerSettings(
        auth=AuthConfig(
            keys=[ApiKeyConfig(key=API_KEY, label="e2e", agent_ids=[AGENT_ID])]
        ),
        storage=StorageConfig(driver="memory", ensure_schema=False),
    )
    application = create_app(settings, storage=storage)
    async with application.router.lifespan_context(application):
        yield application


def agent_client(app) -> httpx.AsyncClient:
    """An httpx client that speaks to the real server app over ASGI."""
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://smoke-server",
        headers={"X-API-Key": API_KEY, "X-Agent-Id": AGENT_ID},
    )


class TestHappyPath:
    async def test_a_measurement_survives_the_whole_pipeline(self, app, storage):
        config = agent_config([{"name": "dns", "host": "8.8.8.8", "probe": "e2e"}])
        shipper = Shipper(
            config=config.server, identity=config.agent, client=agent_client(app)
        )
        scheduler = Scheduler(config, sink=shipper)

        await scheduler._run_cycle(scheduler.build_jobs()[0])
        await shipper.flush()

        assert len(storage.rows) == 1
        stored = storage.rows[0]

        # Vantage point survived.
        assert stored.agent_id == AGENT_ID
        assert stored.agent_location == "seoul-idc"
        assert stored.agent_tags == {"region": "kr", "isp": "kt"}
        # Target identity survived.
        assert stored.target_name == "dns"
        assert stored.target == "8.8.8.8"
        assert stored.probe == "e2e"
        # The actual endpoint survived -- the headline requirement.
        assert stored.resolved_ip == "8.8.8.8"
        assert stored.ip_family == 4

    async def test_the_full_rtt_distribution_survives(self, app, storage):
        config = agent_config([{"name": "dns", "host": "8.8.8.8", "probe": "e2e"}])
        shipper = Shipper(
            config=config.server, identity=config.agent, client=agent_client(app)
        )
        scheduler = Scheduler(config, sink=shipper)

        await scheduler._run_cycle(scheduler.build_jobs()[0])
        await shipper.flush()

        stored = storage.rows[0]
        # Individual samples, not just a summary -- this is what makes the
        # smoke graph reproducible after the fact.
        assert stored.rtts_ms == [11.0, 12.0, 13.0, 14.0, 40.0]
        assert stored.stats is not None
        assert stored.stats.median_ms == 13.0
        assert stored.stats.max_ms == 40.0
        assert stored.stats.jitter_ms > 0
        assert stored.latency_ms == 13.0

    async def test_mtr_hops_reach_their_own_table(self, app, storage):
        config = agent_config(
            [
                {
                    "name": "path",
                    "host": "8.8.8.8",
                    "probe": "e2e",
                    "options": {"mode": "mtr"},
                }
            ]
        )
        shipper = Shipper(
            config=config.server, identity=config.agent, client=agent_client(app)
        )
        scheduler = Scheduler(config, sink=shipper)

        await scheduler._run_cycle(scheduler.build_jobs()[0])
        await shipper.flush()

        assert len(storage.rows) == 1
        assert len(storage.hops) == 3
        assert [h["hop_ip"] for h in storage.hops] == [
            "192.168.1.1",
            "10.20.30.40",
            "8.8.8.8",
        ]
        assert storage.hops[-1]["is_destination"] == 1
        # Route-change detection data made it through intact.
        assert storage.hops[0]["path_signature"] == "abc123def456"
        assert storage.hops[0]["agent_location"] == "seoul-idc"

    async def test_failures_are_stored_with_their_reason(self, app, storage):
        config = agent_config(
            [{"name": "dead", "host": "unreachable.example", "probe": "e2e"}]
        )
        shipper = Shipper(
            config=config.server, identity=config.agent, client=agent_client(app)
        )
        scheduler = Scheduler(config, sink=shipper)

        await scheduler._run_cycle(scheduler.build_jobs()[0])
        await shipper.flush()

        assert len(storage.rows) == 1
        stored = storage.rows[0]
        assert stored.success is False
        assert stored.error_type is ErrorType.TIMEOUT
        assert stored.error_message == "no reply within 10s"
        assert stored.loss_pct == 100.0

    async def test_a_whole_batch_of_targets(self, app, storage):
        config = agent_config(
            [
                {
                    "name": "kr",
                    "probe": "e2e",
                    "children": [
                        {"name": f"t{i}", "host": f"10.0.0.{i}"} for i in range(1, 11)
                    ],
                }
            ]
        )
        shipper = Shipper(
            config=config.server, identity=config.agent, client=agent_client(app)
        )
        scheduler = Scheduler(config, sink=shipper)

        for job in scheduler.build_jobs():
            await scheduler._run_cycle(job)
        await shipper.flush()

        assert len(storage.rows) == 10
        assert {r.target_group for r in storage.rows} == {"/kr"}


class TestOutageRecovery:
    async def test_a_storage_outage_spools_and_then_replays(self, app, storage, tmp_path):
        """The behaviour the whole design exists for.

        The server is up but the database is down: the server answers 503, the
        agent spools to disk, and when the database recovers the buffered
        measurements are delivered -- so the record of the outage is not itself
        destroyed by the outage.
        """
        config = agent_config([{"name": "dns", "host": "8.8.8.8", "probe": "e2e"}])
        spool = Spool(tmp_path, max_bytes=10 * 1024 * 1024)
        shipper = Shipper(
            config=config.server,
            identity=config.agent,
            spool=spool,
            client=agent_client(app),
        )
        scheduler = Scheduler(config, sink=shipper)
        job = scheduler.build_jobs()[0]

        # --- database down --------------------------------------------------
        storage.fail_with = StorageError("clickhouse unreachable")
        for _ in range(3):
            await scheduler._run_cycle(job)
            await shipper.flush()

        assert storage.rows == []
        assert spool.count() == 3
        assert shipper.stats.spooled == 3
        assert shipper.stats.dropped == 0

        # --- database back --------------------------------------------------
        storage.fail_with = None
        replayed = await shipper.replay_spool(max_files=10)

        assert replayed == 3
        assert spool.count() == 0
        assert len(storage.rows) == 3
        assert all(r.target_name == "dns" for r in storage.rows)

    async def test_a_rejected_payload_is_dropped_not_spooled_forever(
        self, app, storage, tmp_path
    ):
        # 400 means "this will never be accepted"; retrying would wedge the
        # queue behind a poison batch.
        config = agent_config([{"name": "dns", "host": "8.8.8.8", "probe": "e2e"}])
        spool = Spool(tmp_path)

        def reject(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"detail": "malformed batch"})

        shipper = Shipper(
            config=config.server,
            identity=config.agent,
            spool=spool,
            client=httpx.AsyncClient(
                transport=httpx.MockTransport(reject), base_url="http://smoke-server"
            ),
        )
        scheduler = Scheduler(config, sink=shipper)
        await scheduler._run_cycle(scheduler.build_jobs()[0])
        await shipper.flush()

        assert spool.count() == 0
        assert shipper.stats.dropped == 1


class TestSecurityBoundary:
    async def test_an_agent_cannot_write_as_another_location(self, app, storage):
        # The key is bound to AGENT_ID; forging a different one must fail, or
        # the location dimension would be meaningless.
        config = agent_config([{"name": "dns", "host": "8.8.8.8", "probe": "e2e"}])
        config.agent.id = "somebody-elses-agent"

        shipper = Shipper(
            config=config.server, identity=config.agent, client=agent_client(app)
        )
        scheduler = Scheduler(config, sink=shipper)
        await scheduler._run_cycle(scheduler.build_jobs()[0])
        await shipper.flush()

        assert storage.rows == []
        # 403 is in the poison set, so the agent drops rather than retries.
        assert shipper.stats.dropped == 1

    async def test_a_wrong_key_is_rejected(self, app, storage):
        config = agent_config([{"name": "dns", "host": "8.8.8.8", "probe": "e2e"}])
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://smoke-server",
            headers={"X-API-Key": "wrong-key", "X-Agent-Id": AGENT_ID},
        )
        shipper = Shipper(config=config.server, identity=config.agent, client=client)
        scheduler = Scheduler(config, sink=shipper)

        await scheduler._run_cycle(scheduler.build_jobs()[0])
        await shipper.flush()

        assert storage.rows == []


class TestCompression:
    async def test_a_large_batch_is_gzipped_and_still_understood(self, app, storage):
        config = agent_config(
            [
                {
                    "name": "big",
                    "probe": "e2e",
                    "children": [
                        {"name": f"t{i}", "host": f"10.0.0.{i}"} for i in range(1, 51)
                    ],
                }
            ],
            compress_threshold_bytes=1,  # force gzip
        )
        shipper = Shipper(
            config=config.server, identity=config.agent, client=agent_client(app)
        )
        scheduler = Scheduler(config, sink=shipper)

        for job in scheduler.build_jobs():
            await scheduler._run_cycle(job)
        await shipper.flush()

        assert len(storage.rows) == 50
        assert shipper.stats.shipped == 50
