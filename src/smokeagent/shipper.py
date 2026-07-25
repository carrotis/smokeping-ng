"""Batching, retrying, spooling transport from agent to server.

Measurements are queued in memory and flushed when either threshold trips:
``batch_max_size`` measurements, or ``batch_max_seconds`` since the oldest one
arrived.  Batching matters -- a 300-target agent on a 60s interval produces 5
measurements/second, and one HTTP request each would be pure overhead.

Failure handling is deliberately asymmetric:

* network errors, 5xx, 429 -- retried with exponential backoff, then spooled to
  disk for later replay;
* 401/403 -- spooled (a key rotation mid-flight should not lose data) and
  logged loudly;
* 400/413/422 -- *dropped*.  The server has told us the payload is unacceptable;
  retrying it forever would wedge the queue behind a poison batch.
"""

from __future__ import annotations

import asyncio
import gzip
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from smokeagent.config import AgentIdentity, ServerConfig
from smokeagent.spool import Spool
from smokecommon.logging import get_logger
from smokecommon.models import Measurement, MeasurementBatch
from smokecommon.version import __version__

log = get_logger(__name__)

INGEST_PATH = "/api/v1/measurements"

#: Server responses that mean "this payload will never be accepted".
_POISON_STATUSES = frozenset({400, 404, 413, 422})


@dataclass
class ShipperStats:
    queued: int = 0
    shipped: int = 0
    batches_sent: int = 0
    failed_attempts: int = 0
    spooled: int = 0
    replayed: int = 0
    dropped: int = 0
    last_success_ts: float | None = None
    last_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {**self.__dict__}


@dataclass
class Shipper:
    """Owns the outbound queue, the HTTP client and the spool."""

    config: ServerConfig
    identity: AgentIdentity
    spool: Spool | None = None
    client: httpx.AsyncClient | None = None

    _buffer: list[Measurement] = field(default_factory=list, init=False)
    _oldest_ts: float | None = field(default=None, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)
    _flush_task: asyncio.Task[None] | None = field(default=None, init=False)
    _stopping: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    stats: ShipperStats = field(default_factory=ShipperStats, init=False)

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self.client is None:
            verify: Any = self.config.ca_bundle or self.config.verify_tls
            self.client = httpx.AsyncClient(
                base_url=self.config.url.rstrip("/"),
                timeout=self.config.timeout,
                verify=verify,
                headers={
                    "User-Agent": f"smoke-agent/{__version__}",
                    "X-API-Key": self.config.api_key,
                    "X-Agent-Id": self.identity.id,
                    "Content-Type": "application/json",
                },
                # One agent talks to one server; a small pool is plenty and
                # keeps connections warm between flushes.
                limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            )
        if self.spool is None and self.config.spool_dir:
            self.spool = Spool(self.config.spool_dir, self.config.spool_max_bytes)
        self._stopping.clear()
        if self._flush_task is None:
            self._flush_task = asyncio.create_task(self._flush_loop(), name="shipper-flush")

    async def stop(self, drain: bool = True) -> None:
        """Stop the flush loop, optionally shipping whatever is still queued."""
        self._stopping.set()
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None

        if drain:
            await self.flush(force=True)
        elif self._buffer and self.spool is not None:
            self.spool.append(self._buffer)
            self._buffer.clear()

        if self.client is not None:
            await self.client.aclose()
            self.client = None

    async def __aenter__(self) -> Shipper:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    # -- queueing ----------------------------------------------------------

    async def submit(self, measurements: Measurement | list[Measurement]) -> None:
        """Queue measurements, flushing immediately if the batch is full."""
        items = [measurements] if isinstance(measurements, Measurement) else list(measurements)
        if not items:
            return
        async with self._lock:
            if self._oldest_ts is None:
                self._oldest_ts = time.monotonic()
            self._buffer.extend(items)
            self.stats.queued = len(self._buffer)
            should_flush = len(self._buffer) >= self.config.batch_max_size
        if should_flush:
            await self.flush()

    async def _flush_loop(self) -> None:
        """Time-based flushing, plus opportunistic spool replay when idle."""
        # Check several times per window so the age threshold is honoured
        # closely without busy-looping.
        tick = max(0.5, self.config.batch_max_seconds / 4)
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=tick)
                return
            except TimeoutError:
                pass

            try:
                async with self._lock:
                    age = time.monotonic() - self._oldest_ts if self._oldest_ts else 0.0
                    due = bool(self._buffer) and age >= self.config.batch_max_seconds
                if due:
                    await self.flush()
                else:
                    await self.replay_spool(max_files=1)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("shipper flush loop error")

    # -- sending -----------------------------------------------------------

    async def flush(self, force: bool = False) -> bool:
        """Ship the current buffer.  Returns True if the server accepted it."""
        async with self._lock:
            if not self._buffer:
                return True
            batch, self._buffer = self._buffer, []
            self._oldest_ts = None
            self.stats.queued = 0

        ok = await self._send_with_retries(batch)
        if ok:
            # A successful send means connectivity is back; take the chance to
            # push some backlog while the path is known-good.
            await self.replay_spool(max_files=3 if not force else 100)
        return ok

    async def _send_with_retries(self, measurements: list[Measurement]) -> bool:
        attempts = max(1, self.config.max_retries)
        delay = max(0.0, self.config.retry_initial_delay)
        last_error = "unknown"

        for attempt in range(1, attempts + 1):
            outcome, detail = await self._send_once(measurements)
            if outcome == "ok":
                self.stats.shipped += len(measurements)
                self.stats.batches_sent += 1
                self.stats.last_success_ts = time.time()
                self.stats.last_error = None
                log.info(
                    "shipped batch",
                    extra={"count": len(measurements), "attempt": attempt},
                )
                return True

            self.stats.failed_attempts += 1
            last_error = detail

            if outcome == "poison":
                self.stats.dropped += len(measurements)
                self.stats.last_error = detail
                log.error(
                    "server rejected batch permanently, dropping",
                    extra={"count": len(measurements), "detail": detail},
                )
                return False

            if attempt < attempts:
                # Full jitter: without it, every agent behind a shared outage
                # retries in lockstep and hammers the server on recovery.
                sleep_for = random.uniform(0, delay)  # noqa: S311 - not cryptographic
                log.warning(
                    "ship failed, retrying",
                    extra={"attempt": attempt, "detail": detail, "sleep_s": round(sleep_for, 2)},
                )
                await asyncio.sleep(sleep_for)
                delay *= self.config.retry_backoff

        self.stats.last_error = last_error
        self._spool(measurements, reason=last_error)
        return False

    async def _send_once(self, measurements: list[Measurement]) -> tuple[str, str]:
        """One HTTP attempt.  Returns ``(outcome, detail)``.

        Outcome is ``ok`` | ``retry`` | ``poison``.
        """
        if self.client is None:
            return "retry", "shipper not started"

        batch = MeasurementBatch(
            agent_id=self.identity.id,
            agent_location=self.identity.location,
            agent_version=__version__,
            measurements=measurements,
        )
        body = batch.model_dump_json().encode("utf-8")
        headers: dict[str, str] = {}
        if len(body) >= self.config.compress_threshold_bytes:
            body = gzip.compress(body, compresslevel=6)
            headers["Content-Encoding"] = "gzip"

        try:
            response = await self.client.post(INGEST_PATH, content=body, headers=headers)
        except httpx.HTTPError as exc:
            return "retry", f"{type(exc).__name__}: {exc}"

        if response.is_success:
            return "ok", ""
        detail = f"HTTP {response.status_code}: {response.text[:300]}"
        if response.status_code in _POISON_STATUSES:
            return "poison", detail
        return "retry", detail

    def _spool(self, measurements: list[Measurement], reason: str) -> None:
        if self.spool is None:
            self.stats.dropped += len(measurements)
            log.error(
                "no spool configured, dropping measurements",
                extra={"count": len(measurements), "reason": reason},
            )
            return
        self.spool.append(measurements)
        self.stats.spooled += len(measurements)

    # -- spool replay ------------------------------------------------------

    async def replay_spool(self, max_files: int = 1) -> int:
        """Push spooled batches back to the server.  Returns files replayed."""
        if self.spool is None or self.client is None:
            return 0

        replayed = 0
        for _ in range(max_files):
            entry = self.spool.peek_oldest()
            if entry is None:
                break
            path, measurements = entry
            outcome, detail = await self._send_once(measurements)
            if outcome == "ok":
                self.spool.remove(path)
                self.stats.replayed += len(measurements)
                self.stats.shipped += len(measurements)
                replayed += 1
                log.info(
                    "replayed spooled batch",
                    extra={"file": path.name, "count": len(measurements)},
                )
            elif outcome == "poison":
                self.spool.remove(path)
                self.stats.dropped += len(measurements)
                log.error(
                    "dropping poisoned spool file",
                    extra={"file": path.name, "detail": detail},
                )
            else:
                # Still down.  Leave the file in place and stop trying; the
                # next successful live flush will pick it back up.
                break
        return replayed
