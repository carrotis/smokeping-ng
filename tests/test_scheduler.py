"""Scheduler: job building, batching and one-shot runs.

The timing loop itself is not unit-tested against wall-clock sleeps -- that
would make the suite slow and flaky.  Instead the tests drive ``_run_cycle``
directly, which is where all the interesting logic lives.
"""

from __future__ import annotations

from typing import Any

import pytest

from smokeagent.config import parse_agent_config
from smokeagent.probes.base import Probe, ProbeTarget, register_probe, registered_probes
from smokeagent.scheduler import Scheduler, run_once
from smokecommon.errors import ErrorType
from smokecommon.models import Measurement, ProbeResult


class CollectingSink:
    """Stands in for the Shipper."""

    def __init__(self) -> None:
        self.measurements: list[Measurement] = []

    async def submit(self, measurements: Measurement | list[Measurement]) -> None:
        if isinstance(measurements, Measurement):
            self.measurements.append(measurements)
        else:
            self.measurements.extend(measurements)


@register_probe
class FakeProbe(Probe):
    """Deterministic probe so scheduler tests never touch the network."""

    name = "fake"
    description = "test double"
    default_options = {"timeout": 1.0, "latency": 42.0}

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        if "bad" in target.address:
            return ProbeResult.failure(ErrorType.UNREACHABLE, f"cannot reach {target.address}")
        return ProbeResult(
            success=True,
            rtts_ms=[float(self.options["latency"])],
            packets_sent=1,
            packets_received=1,
            resolved_ip="203.0.113.1",
        )


@register_probe
class FakeBatchProbe(FakeProbe):
    """Batch-capable double, to exercise job grouping."""

    name = "fakebatch"
    supports_batch = True
    default_options = {"timeout": 1.0, "latency": 7.0, "max_batch": 3}
    #: Records how many targets each invocation received.
    calls: list[int] = []

    async def probe_many(self, targets: list[ProbeTarget]) -> dict[str, ProbeResult]:
        type(self).calls.append(len(targets))
        return {
            t.name: ProbeResult(
                success=True,
                rtts_ms=[float(self.options["latency"])],
                packets_sent=1,
                packets_received=1,
                resolved_ip="203.0.113.9",
            )
            for t in targets
        }


def build_config(targets: list[dict[str, Any]], **extra: Any):
    raw = {
        "agent": {"id": "agent-1", "location": "seoul", "tags": {"region": "kr"}},
        "server": {"url": "https://s.example", "api_key": "k"},
        "targets": targets,
        **extra,
    }
    return parse_agent_config(raw, environ={})


class TestJobBuilding:
    def test_one_job_per_non_batch_target(self):
        cfg = build_config(
            [
                {"name": "a", "host": "1.1.1.1", "probe": "fake"},
                {"name": "b", "host": "8.8.8.8", "probe": "fake"},
            ]
        )
        jobs = Scheduler(cfg, CollectingSink()).build_jobs()
        assert len(jobs) == 2
        assert all(not j.batched for j in jobs)

    def test_batch_probe_groups_targets_into_one_job(self):
        cfg = build_config(
            [
                {"name": n, "host": f"10.0.0.{i}", "probe": "fakebatch"}
                for i, n in enumerate(["a", "b"], start=1)
            ]
        )
        jobs = Scheduler(cfg, CollectingSink()).build_jobs()
        assert len(jobs) == 1
        assert jobs[0].batched is True
        assert len(jobs[0].targets) == 2

    def test_different_intervals_cannot_share_a_batch(self):
        cfg = build_config(
            [
                {"name": "a", "host": "10.0.0.1", "probe": "fakebatch", "interval": 30},
                {"name": "b", "host": "10.0.0.2", "probe": "fakebatch", "interval": 60},
            ]
        )
        jobs = Scheduler(cfg, CollectingSink()).build_jobs()
        assert len(jobs) == 2

    def test_different_options_cannot_share_a_batch(self):
        cfg = build_config(
            [
                {"name": "a", "host": "10.0.0.1", "probe": "fakebatch", "options": {"latency": 1}},
                {"name": "b", "host": "10.0.0.2", "probe": "fakebatch", "options": {"latency": 2}},
            ]
        )
        assert len(Scheduler(cfg, CollectingSink()).build_jobs()) == 2

    def test_max_batch_splits_large_groups(self):
        cfg = build_config(
            [
                {"name": f"t{i}", "host": f"10.0.0.{i}", "probe": "fakebatch"}
                for i in range(1, 8)
            ]
        )
        jobs = Scheduler(cfg, CollectingSink()).build_jobs()
        # max_batch is 3, so 7 targets -> 3 + 3 + 1
        assert sorted(len(j.targets) for j in jobs) == [1, 3, 3]

    def test_batching_can_be_disabled(self):
        cfg = build_config(
            [
                {"name": "a", "host": "10.0.0.1", "probe": "fakebatch"},
                {"name": "b", "host": "10.0.0.2", "probe": "fakebatch"},
            ],
            scheduler={"enable_batching": False},
        )
        jobs = Scheduler(cfg, CollectingSink()).build_jobs()
        assert len(jobs) == 2
        assert all(not j.batched for j in jobs)

    def test_disabled_targets_get_no_job(self):
        cfg = build_config(
            [
                {"name": "a", "host": "1.1.1.1", "probe": "fake"},
                {"name": "b", "host": "8.8.8.8", "probe": "fake", "enabled": False},
            ]
        )
        jobs = Scheduler(cfg, CollectingSink()).build_jobs()
        assert len(jobs) == 1
        assert jobs[0].targets[0].name == "a"

    def test_unknown_probe_is_a_clear_error(self):
        cfg = build_config([{"name": "a", "host": "1.1.1.1", "probe": "nosuchprobe"}])
        with pytest.raises(KeyError, match="unknown probe"):
            Scheduler(cfg, CollectingSink()).build_jobs()

    def test_invalid_probe_options_fail_at_build_time(self):
        cfg = build_config(
            [{"name": "a", "host": "1.1.1.1", "probe": "ping", "options": {"count": 0}}]
        )
        with pytest.raises(ValueError, match="count"):
            Scheduler(cfg, CollectingSink()).build_jobs()


class TestPreflight:
    def test_reports_missing_binaries(self, monkeypatch):
        cfg = build_config([{"name": "a", "host": "1.1.1.1", "probe": "mtr"}])
        monkeypatch.setattr(registered_probes()["mtr"], "is_available", classmethod(lambda cls: False))
        problems = Scheduler(cfg, CollectingSink()).preflight()
        assert len(problems) == 1
        assert "mtr" in problems[0]

    def test_silent_when_everything_is_available(self):
        cfg = build_config([{"name": "a", "host": "1.1.1.1", "probe": "fake"}])
        assert Scheduler(cfg, CollectingSink()).preflight() == []


class TestCycles:
    async def test_cycle_produces_an_enriched_measurement(self):
        cfg = build_config(
            [
                {
                    "name": "kt",
                    "probe": "fake",
                    "children": [{"name": "dns", "host": "168.126.63.1"}],
                }
            ]
        )
        sink = CollectingSink()
        scheduler = Scheduler(cfg, sink)
        await scheduler._run_cycle(scheduler.build_jobs()[0])

        assert len(sink.measurements) == 1
        m = sink.measurements[0]
        assert m.agent_id == "agent-1"
        assert m.agent_location == "seoul"
        assert m.agent_tags == {"region": "kr"}
        assert m.target_name == "dns"
        assert m.target_group == "/kt"
        assert m.target == "168.126.63.1"
        assert m.probe == "fake"
        assert m.latency_ms == 42.0
        assert m.resolved_ip == "203.0.113.1"

    async def test_failures_are_recorded_not_dropped(self):
        cfg = build_config([{"name": "bad", "host": "bad.example", "probe": "fake"}])
        sink = CollectingSink()
        scheduler = Scheduler(cfg, sink)
        await scheduler._run_cycle(scheduler.build_jobs()[0])

        assert len(sink.measurements) == 1
        assert sink.measurements[0].success is False
        assert sink.measurements[0].error_type is ErrorType.UNREACHABLE
        assert scheduler.stats.failures == 1

    async def test_all_targets_in_a_batch_share_one_timestamp(self):
        # One cycle is one moment in time; per-target timestamps would make
        # cross-target comparison at the same instant impossible.
        cfg = build_config(
            [
                {"name": "a", "host": "10.0.0.1", "probe": "fakebatch"},
                {"name": "b", "host": "10.0.0.2", "probe": "fakebatch"},
            ]
        )
        sink = CollectingSink()
        scheduler = Scheduler(cfg, sink)
        await scheduler._run_cycle(scheduler.build_jobs()[0])

        assert len(sink.measurements) == 2
        assert len({m.ts for m in sink.measurements}) == 1

    async def test_batch_probe_is_invoked_once_for_the_whole_group(self):
        FakeBatchProbe.calls.clear()
        cfg = build_config(
            [
                {"name": "a", "host": "10.0.0.1", "probe": "fakebatch"},
                {"name": "b", "host": "10.0.0.2", "probe": "fakebatch"},
                {"name": "c", "host": "10.0.0.3", "probe": "fakebatch"},
            ]
        )
        sink = CollectingSink()
        scheduler = Scheduler(cfg, sink)
        await scheduler._run_cycle(scheduler.build_jobs()[0])

        assert FakeBatchProbe.calls == [3]
        assert len(sink.measurements) == 3

    async def test_stats_are_tracked(self):
        cfg = build_config(
            [
                {"name": "a", "host": "1.1.1.1", "probe": "fake"},
                {"name": "bad", "host": "bad.example", "probe": "fake"},
            ]
        )
        sink = CollectingSink()
        scheduler = Scheduler(cfg, sink)
        for job in scheduler.build_jobs():
            await scheduler._run_cycle(job)

        assert scheduler.stats.cycles == 2
        assert scheduler.stats.measurements == 2
        assert scheduler.stats.successes == 1
        assert scheduler.stats.failures == 1


class TestRunOnce:
    async def test_returns_probe_result_and_measurement(self):
        cfg = build_config([{"name": "a", "host": "1.1.1.1", "probe": "fake"}])
        outcome = await run_once(cfg, cfg.targets[0])

        assert outcome.result.success is True
        assert outcome.measurement.agent_location == "seoul"
        assert outcome.measurement.target == "1.1.1.1"

    async def test_option_overrides_reach_the_probe(self):
        cfg = build_config(
            [{"name": "a", "host": "1.1.1.1", "probe": "fake", "options": {"latency": 99.0}}]
        )
        outcome = await run_once(cfg, cfg.targets[0])
        assert outcome.measurement.latency_ms == 99.0
