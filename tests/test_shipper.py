"""Shipper: batching, retry, and the spool-on-failure contract.

All HTTP goes through an ``httpx.MockTransport``, so these run in
milliseconds and cover the failure paths that are hard to reproduce for real.
"""

from __future__ import annotations

import gzip
import json

import httpx
import pytest

from smokeagent.config import AgentIdentity, ServerConfig
from smokeagent.shipper import Shipper
from smokeagent.spool import Spool

from conftest import make_measurement

IDENTITY = AgentIdentity(id="agent-1", location="seoul", tags={"region": "kr"})


def server_config(**overrides):
    defaults = {
        "url": "https://smoke.example.com",
        "api_key": "test-key",
        "batch_max_size": 3,
        "batch_max_seconds": 60.0,
        "max_retries": 3,
        # Keep the suite fast; the backoff maths itself is not what we assert.
        "retry_initial_delay": 0.001,
        "retry_backoff": 1.0,
        "compress_threshold_bytes": 10_000_000,  # off unless a test wants it
    }
    defaults.update(overrides)
    return ServerConfig(**defaults)


class Recorder:
    """Captures requests and replays a scripted sequence of responses."""

    def __init__(self, *statuses: int) -> None:
        self.statuses = list(statuses) or [201]
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        status = self.statuses[min(len(self.requests) - 1, len(self.statuses) - 1)]
        return httpx.Response(status, json={"accepted": 0})

    @property
    def bodies(self) -> list[dict]:
        out = []
        for request in self.requests:
            content = request.content
            if request.headers.get("Content-Encoding") == "gzip":
                content = gzip.decompress(content)
            out.append(json.loads(content))
        return out


def make_shipper(recorder: Recorder, config: ServerConfig, spool: Spool | None = None) -> Shipper:
    client = httpx.AsyncClient(
        base_url=config.url,
        transport=httpx.MockTransport(recorder),
        headers={"X-API-Key": config.api_key, "X-Agent-Id": IDENTITY.id},
    )
    return Shipper(config=config, identity=IDENTITY, spool=spool, client=client)


class TestBatching:
    async def test_buffers_until_the_size_threshold(self):
        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=3))

        await shipper.submit([make_measurement(), make_measurement()])
        assert recorder.requests == []

        await shipper.submit(make_measurement())
        assert len(recorder.requests) == 1
        assert len(recorder.bodies[0]["measurements"]) == 3

    async def test_explicit_flush_sends_a_partial_batch(self):
        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=100))

        await shipper.submit(make_measurement())
        assert recorder.requests == []
        assert await shipper.flush() is True
        assert len(recorder.requests) == 1

    async def test_flushing_an_empty_buffer_sends_nothing(self):
        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config())
        assert await shipper.flush() is True
        assert recorder.requests == []


class TestPayload:
    async def test_envelope_carries_the_vantage_point(self):
        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=1))
        await shipper.submit(make_measurement())

        body = recorder.bodies[0]
        assert body["agent_id"] == "agent-1"
        assert body["agent_location"] == "seoul"
        assert body["protocol_version"] >= 1
        assert body["agent_version"]

    async def test_api_key_header_is_sent(self):
        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=1))
        await shipper.submit(make_measurement())
        assert recorder.requests[0].headers["X-API-Key"] == "test-key"

    async def test_large_payloads_are_gzipped(self):
        recorder = Recorder(201)
        shipper = make_shipper(
            recorder, server_config(batch_max_size=1, compress_threshold_bytes=10)
        )
        await shipper.submit(make_measurement())

        assert recorder.requests[0].headers["Content-Encoding"] == "gzip"
        # The recorder decompresses, so this also proves the body is valid gzip.
        assert recorder.bodies[0]["agent_id"] == "agent-1"

    async def test_small_payloads_are_not_gzipped(self):
        recorder = Recorder(201)
        shipper = make_shipper(
            recorder, server_config(batch_max_size=1, compress_threshold_bytes=10_000_000)
        )
        await shipper.submit(make_measurement())
        assert "Content-Encoding" not in recorder.requests[0].headers


class TestRetries:
    async def test_retries_a_5xx_then_succeeds(self):
        recorder = Recorder(503, 503, 201)
        shipper = make_shipper(recorder, server_config(batch_max_size=1, max_retries=3))

        await shipper.submit(make_measurement())
        assert len(recorder.requests) == 3
        assert shipper.stats.shipped == 1
        assert shipper.stats.failed_attempts == 2

    async def test_gives_up_after_max_retries_and_spools(self, tmp_path):
        recorder = Recorder(503)
        spool = Spool(tmp_path)
        shipper = make_shipper(recorder, server_config(batch_max_size=1, max_retries=2), spool)

        await shipper.submit(make_measurement())
        assert len(recorder.requests) == 2
        assert shipper.stats.spooled == 1
        assert spool.count() == 1

    async def test_a_400_is_dropped_not_retried(self, tmp_path):
        # The server has said this payload will never be accepted; retrying it
        # forever would wedge the queue behind a poison batch.
        recorder = Recorder(400)
        spool = Spool(tmp_path)
        shipper = make_shipper(recorder, server_config(batch_max_size=1, max_retries=5), spool)

        await shipper.submit(make_measurement())
        assert len(recorder.requests) == 1
        assert shipper.stats.dropped == 1
        assert spool.count() == 0

    async def test_a_401_is_spooled_not_dropped(self, tmp_path):
        # A key rotation mid-flight should not lose data.
        recorder = Recorder(401)
        spool = Spool(tmp_path)
        shipper = make_shipper(recorder, server_config(batch_max_size=1, max_retries=1), spool)

        await shipper.submit(make_measurement())
        assert spool.count() == 1
        assert shipper.stats.dropped == 0

    async def test_network_errors_are_retried(self, tmp_path):
        attempts = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise httpx.ConnectError("connection refused", request=request)
            return httpx.Response(201, json={"accepted": 1})

        client = httpx.AsyncClient(
            base_url="https://smoke.example.com", transport=httpx.MockTransport(handler)
        )
        shipper = Shipper(
            config=server_config(batch_max_size=1, max_retries=3),
            identity=IDENTITY,
            client=client,
        )
        await shipper.submit(make_measurement())

        assert attempts["n"] == 2
        assert shipper.stats.shipped == 1

    async def test_no_spool_configured_counts_as_dropped(self):
        recorder = Recorder(503)
        shipper = make_shipper(recorder, server_config(batch_max_size=1, max_retries=1))
        await shipper.submit(make_measurement())
        assert shipper.stats.dropped == 1


class TestSpoolReplay:
    async def test_spooled_batches_are_replayed_after_recovery(self, tmp_path):
        spool = Spool(tmp_path)
        spool.append([make_measurement(target_name="from-outage")])

        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=1), spool)
        replayed = await shipper.replay_spool(max_files=5)

        assert replayed == 1
        assert spool.count() == 0
        assert recorder.bodies[0]["measurements"][0]["target_name"] == "from-outage"

    async def test_a_successful_live_flush_also_drains_the_spool(self, tmp_path):
        spool = Spool(tmp_path)
        spool.append([make_measurement(target_name="old")])

        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=1), spool)
        await shipper.submit(make_measurement(target_name="new"))

        # One request for the live batch, one for the replayed spool file.
        assert len(recorder.requests) == 2
        assert spool.count() == 0

    async def test_replay_stops_while_the_server_is_still_down(self, tmp_path):
        spool = Spool(tmp_path)
        for i in range(3):
            spool.append([make_measurement(target_name=f"b{i}")])

        recorder = Recorder(503)
        shipper = make_shipper(recorder, server_config(), spool)
        assert await shipper.replay_spool(max_files=3) == 0
        # Files stay put for the next attempt, and we did not hammer the server.
        assert spool.count() == 3
        assert len(recorder.requests) == 1

    async def test_poisoned_spool_file_is_discarded(self, tmp_path):
        spool = Spool(tmp_path)
        spool.append([make_measurement()])

        recorder = Recorder(400)
        shipper = make_shipper(recorder, server_config(), spool)
        await shipper.replay_spool(max_files=1)

        assert spool.count() == 0
        assert shipper.stats.dropped == 1


class TestLifecycle:
    async def test_stop_drains_the_buffer(self, tmp_path):
        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=1000))
        await shipper.submit(make_measurement())

        await shipper.stop(drain=True)
        assert len(recorder.requests) == 1

    async def test_stop_without_drain_spools_instead_of_losing_data(self, tmp_path):
        recorder = Recorder(201)
        spool = Spool(tmp_path)
        shipper = make_shipper(recorder, server_config(batch_max_size=1000), spool)
        await shipper.submit(make_measurement())

        await shipper.stop(drain=False)
        assert recorder.requests == []
        assert spool.count() == 1

    async def test_submitting_nothing_is_a_no_op(self):
        recorder = Recorder(201)
        shipper = make_shipper(recorder, server_config(batch_max_size=1))
        await shipper.submit([])
        assert recorder.requests == []


@pytest.mark.parametrize("status", [500, 502, 503, 429])
async def test_transient_statuses_are_retried(status, tmp_path):
    recorder = Recorder(status)
    spool = Spool(tmp_path)
    shipper = make_shipper(recorder, server_config(batch_max_size=1, max_retries=2), spool)
    await shipper.submit(make_measurement())
    assert len(recorder.requests) == 2
    assert spool.count() == 1
