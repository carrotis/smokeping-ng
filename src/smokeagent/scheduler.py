"""The measurement loop.

One asyncio task per job, where a job is either a single target or -- for
batch-capable probes like fping -- a group of targets that share a probe, an
interval and a set of options.

Three things this gets right that a naive ``while True: sleep(interval)`` does
not:

* **No drift.**  Ticks are computed from a fixed epoch (``start + n*interval``)
  rather than by sleeping ``interval`` after each run, so a probe that takes
  3 s does not slowly push a 60 s target out to 63 s.
* **Jitter and stagger.**  Without them, 300 targets configured at 60 s all
  fire on the same second, producing a sawtooth of CPU and a synchronised
  burst of ICMP that itself distorts the measurement.
* **Overrun handling.**  If a cycle outlives its interval the scheduler skips
  to the next future tick instead of queueing an ever-growing backlog.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from smokeagent.config import AgentConfig, TargetSpec
from smokeagent.probes.base import Probe, ProbeTarget, get_probe_class
from smokecommon.logging import bind_context, get_logger
from smokecommon.models import Measurement, ProbeResult, utcnow

log = get_logger(__name__)


class MeasurementSink(Protocol):
    """Anything that accepts finished measurements (the Shipper, or a test double)."""

    async def submit(self, measurements: Measurement | list[Measurement]) -> None: ...


@dataclass
class SchedulerStats:
    cycles: int = 0
    measurements: int = 0
    successes: int = 0
    failures: int = 0
    overruns: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {**self.__dict__}


@dataclass
class Job:
    """A probe instance plus the targets it measures on one shared cycle."""

    probe: Probe
    targets: list[TargetSpec]
    interval: float
    batched: bool

    @property
    def name(self) -> str:
        if self.batched:
            return f"{self.probe.name}[{len(self.targets)} targets]"
        return self.targets[0].key


class Scheduler:
    """Runs every configured job until stopped."""

    def __init__(
        self,
        config: AgentConfig,
        sink: MeasurementSink,
        *,
        clock: Any = None,
    ) -> None:
        self.config = config
        self.sink = sink
        # Injectable for tests; must expose monotonic() and sleep().
        self._loop_time = clock or time.monotonic
        self.stats = SchedulerStats()
        self.jobs: list[Job] = []
        self._tasks: list[asyncio.Task[None]] = []
        self._stop = asyncio.Event()
        self._semaphore = asyncio.Semaphore(
            max(1, config.scheduler.max_concurrent_probes)
        )

    # -- setup -------------------------------------------------------------

    def build_jobs(self) -> list[Job]:
        """Turn the config's flat target list into runnable jobs.

        Targets are grouped when the probe supports batching *and* they agree
        on interval and options -- otherwise one process could not serve them
        all with the same command line.
        """
        enabled = [t for t in self.config.targets if t.enabled]
        skipped = len(self.config.targets) - len(enabled)
        if skipped:
            log.info("skipping disabled targets", extra={"count": skipped})

        groups: dict[tuple[str, str], list[TargetSpec]] = {}
        singles: list[TargetSpec] = []

        for target in enabled:
            probe_cls = get_probe_class(target.probe)
            if self.config.scheduler.enable_batching and probe_cls.supports_batch:
                signature = (
                    f"{target.probe}|{target.interval}|"
                    f"{json.dumps(target.options, sort_keys=True, default=str)}"
                )
                groups.setdefault((target.probe, signature), []).append(target)
            else:
                singles.append(target)

        jobs: list[Job] = []
        for (probe_name, _), targets in groups.items():
            probe_cls = get_probe_class(probe_name)
            probe = probe_cls(targets[0].options)
            probe.validate()
            max_batch = int(probe.options.get("max_batch", 200) or 200)
            for chunk in _chunks(targets, max_batch):
                jobs.append(
                    Job(
                        probe=probe_cls(chunk[0].options),
                        targets=chunk,
                        interval=chunk[0].interval,
                        batched=len(chunk) > 1,
                    )
                )

        for target in singles:
            probe = get_probe_class(target.probe)(target.options)
            probe.validate()
            jobs.append(Job(probe=probe, targets=[target], interval=target.interval, batched=False))

        self.jobs = jobs
        return jobs

    def preflight(self) -> list[str]:
        """Report probes whose binary is missing, without refusing to start.

        A missing ``mtr`` should not stop the other 299 targets from being
        measured -- but the operator needs to know, loudly, at startup.
        """
        problems: list[str] = []
        for probe_name in {t.probe for t in self.config.targets if t.enabled}:
            probe_cls = get_probe_class(probe_name)
            if not probe_cls.is_available():
                problems.append(
                    f"probe {probe_name!r} requires the {probe_cls.required_binary!r} "
                    "binary, which is not on PATH"
                )
        return problems

    # -- running -----------------------------------------------------------

    async def run(self) -> None:
        """Start every job and block until :meth:`stop` is called."""
        if not self.jobs:
            self.build_jobs()

        self._stop.clear()
        self._tasks = [
            asyncio.create_task(self._run_job(job), name=f"job:{job.name}") for job in self.jobs
        ]
        log.info(
            "scheduler started",
            extra={
                "jobs": len(self.jobs),
                "targets": sum(len(j.targets) for j in self.jobs),
                "max_concurrent": self.config.scheduler.max_concurrent_probes,
            },
        )
        try:
            await self._stop.wait()
        finally:
            await self._cancel_tasks()

    async def stop(self) -> None:
        self._stop.set()

    async def _cancel_tasks(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        self._tasks = []

    async def _run_job(self, job: Job) -> None:
        interval = max(1.0, job.interval)
        jitter_fraction = max(0.0, min(1.0, self.config.scheduler.jitter))

        if self.config.scheduler.stagger_start:
            # Spread first runs across the whole interval so a restart does not
            # replay the thundering herd we just avoided.
            await asyncio.sleep(random.uniform(0, interval))  # noqa: S311

        epoch = self._loop_time()
        tick = 0
        while not self._stop.is_set():
            started = self._loop_time()
            try:
                await self._run_cycle(job)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("job cycle failed", extra={"job": job.name})

            elapsed = self._loop_time() - started
            if elapsed > interval:
                self.stats.overruns += 1
                log.warning(
                    "cycle overran its interval",
                    extra={"job": job.name, "elapsed_s": round(elapsed, 2), "interval_s": interval},
                )

            tick += 1
            next_at = epoch + tick * interval
            now = self._loop_time()
            if next_at <= now:
                # We fell behind; skip to the next tick that is still ahead
                # rather than firing back-to-back to "catch up".
                missed = int((now - next_at) // interval) + 1
                tick += missed
                next_at = epoch + tick * interval

            sleep_for = next_at - now
            if jitter_fraction:
                sleep_for += random.uniform(0, interval * jitter_fraction)  # noqa: S311

            try:
                await asyncio.wait_for(self._stop.wait(), timeout=max(0.0, sleep_for))
                return
            except TimeoutError:
                continue

    async def _run_cycle(self, job: Job) -> None:
        probe_targets = [_to_probe_target(t) for t in job.targets]
        ts = utcnow()

        async with self._semaphore:
            if job.batched or len(probe_targets) > 1:
                results = await job.probe.run_many(probe_targets)
            else:
                results = {probe_targets[0].name: await job.probe.run(probe_targets[0])}

        measurements = [
            self._to_measurement(spec, results[spec.key], ts)
            for spec in job.targets
            if spec.key in results
        ]

        self.stats.cycles += 1
        self.stats.measurements += len(measurements)
        self.stats.successes += sum(1 for m in measurements if m.success)
        self.stats.failures += sum(1 for m in measurements if not m.success)

        for measurement in measurements:
            if measurement.success:
                log.debug(
                    "measurement",
                    extra={
                        "probe": measurement.probe,
                        "target": measurement.target,
                        "latency_ms": measurement.latency_ms,
                        "loss_pct": measurement.loss_pct,
                        "resolved_ip": measurement.resolved_ip,
                    },
                )
            else:
                # Failures are the point of the tool; log them at INFO so they
                # are visible without turning on debug for everything.
                log.info(
                    "measurement failed",
                    extra={
                        "probe": measurement.probe,
                        "target": measurement.target,
                        "error_type": measurement.error_type,
                        "error": measurement.error_message,
                    },
                )

        await self.sink.submit(measurements)

    def _to_measurement(
        self, spec: TargetSpec, result: ProbeResult, ts: Any
    ) -> Measurement:
        with bind_context(target=spec.host, probe=spec.probe):
            return Measurement.from_probe_result(
                result,
                agent_id=self.config.agent.id,
                agent_location=self.config.agent.location,
                agent_tags=self.config.agent.tags,
                target_name=spec.name,
                target_group=spec.group,
                target=spec.host,
                probe=spec.probe,
                ts=ts,
            )


@dataclass(slots=True)
class OneShotResult:
    """Return type of :func:`run_once`, used by ``smoke-agent test``."""

    spec: TargetSpec
    result: ProbeResult
    measurement: Measurement = field(repr=False)


async def run_once(config: AgentConfig, spec: TargetSpec) -> OneShotResult:
    """Run a single target once and return everything about it.

    Backs the ``smoke-agent test`` subcommand: measure one target, print the
    full result, ship nothing.
    """
    probe = get_probe_class(spec.probe)(spec.options)
    probe.validate()
    result = await probe.run(_to_probe_target(spec))
    measurement = Measurement.from_probe_result(
        result,
        agent_id=config.agent.id,
        agent_location=config.agent.location,
        agent_tags=config.agent.tags,
        target_name=spec.name,
        target_group=spec.group,
        target=spec.host,
        probe=spec.probe,
    )
    return OneShotResult(spec=spec, result=result, measurement=measurement)


def _to_probe_target(spec: TargetSpec) -> ProbeTarget:
    # ProbeTarget.name must be unique within a batch, so use the full key.
    return ProbeTarget(
        name=spec.key, address=spec.host, group=spec.group, options=spec.options
    )


def _chunks(items: list[TargetSpec], size: int) -> list[list[TargetSpec]]:
    return [items[i : i + size] for i in range(0, len(items), max(1, size))]
