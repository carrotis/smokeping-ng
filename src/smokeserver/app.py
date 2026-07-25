"""smoke-server HTTP application (FastAPI).

Endpoints
---------
``POST /api/v1/measurements``  ingest a batch (authenticated)
``GET  /healthz``              liveness, no auth, never touches the database
``GET  /readyz``               readiness, pings the storage driver
``GET  /metrics``              Prometheus text exposition of ingest counters
``GET  /api/v1/info``          version and active driver
``GET  /api/v1/agents``        recently seen agents (authenticated)

Ingest is **synchronous**: the response is only sent once the storage driver
has confirmed the write.  That is the whole contract that makes the agent's
spool work -- a 503 means "not stored, please retry", and the agent buffers to
disk instead of dropping data.  Acking before the write would turn every server
restart into silent data loss.
"""

from __future__ import annotations

import gzip
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from smokecommon.logging import bind_context, get_logger
from smokecommon.models import IngestResponse, MeasurementBatch
from smokecommon.version import PROTOCOL_VERSION, __version__
from smokeserver.auth import Authenticator, AuthError
from smokeserver.config import ServerSettings
from smokeserver.storage import StorageDriver, StorageError, create_driver

log = get_logger(__name__)


@dataclass
class IngestMetrics:
    """In-process counters, exposed at ``/metrics``."""

    batches_received: int = 0
    batches_rejected: int = 0
    measurements_written: int = 0
    measurements_failed_probe: int = 0
    hops_written: int = 0
    auth_failures: int = 0
    storage_errors: int = 0
    write_seconds_total: float = 0.0
    started_at: float = field(default_factory=time.time)
    by_agent: dict[str, int] = field(default_factory=dict)

    def render_prometheus(self) -> str:
        lines = [
            "# HELP smokeping_server_uptime_seconds Seconds since the server started.",
            "# TYPE smokeping_server_uptime_seconds gauge",
            f"smokeping_server_uptime_seconds {time.time() - self.started_at:.3f}",
            "# HELP smokeping_batches_received_total Ingest batches accepted.",
            "# TYPE smokeping_batches_received_total counter",
            f"smokeping_batches_received_total {self.batches_received}",
            "# HELP smokeping_batches_rejected_total Ingest batches rejected.",
            "# TYPE smokeping_batches_rejected_total counter",
            f"smokeping_batches_rejected_total {self.batches_rejected}",
            "# HELP smokeping_measurements_written_total Measurement rows stored.",
            "# TYPE smokeping_measurements_written_total counter",
            f"smokeping_measurements_written_total {self.measurements_written}",
            "# HELP smokeping_measurements_failed_total Stored measurements whose probe failed.",
            "# TYPE smokeping_measurements_failed_total counter",
            f"smokeping_measurements_failed_total {self.measurements_failed_probe}",
            "# HELP smokeping_hops_written_total mtr hop rows stored.",
            "# TYPE smokeping_hops_written_total counter",
            f"smokeping_hops_written_total {self.hops_written}",
            "# HELP smokeping_auth_failures_total Rejected authentication attempts.",
            "# TYPE smokeping_auth_failures_total counter",
            f"smokeping_auth_failures_total {self.auth_failures}",
            "# HELP smokeping_storage_errors_total Failed storage writes.",
            "# TYPE smokeping_storage_errors_total counter",
            f"smokeping_storage_errors_total {self.storage_errors}",
            "# HELP smokeping_write_seconds_total Cumulative time spent writing to storage.",
            "# TYPE smokeping_write_seconds_total counter",
            f"smokeping_write_seconds_total {self.write_seconds_total:.6f}",
            "# HELP smokeping_agent_measurements_total Measurements stored, per agent.",
            "# TYPE smokeping_agent_measurements_total counter",
        ]
        for agent_id, count in sorted(self.by_agent.items()):
            safe = agent_id.replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'smokeping_agent_measurements_total{{agent_id="{safe}"}} {count}')
        return "\n".join(lines) + "\n"


def create_app(
    settings: ServerSettings,
    storage: StorageDriver | None = None,
) -> FastAPI:
    """Build the ASGI app.

    ``storage`` can be injected so tests run against a fake driver without a
    database.
    """
    driver = storage or create_driver(settings.storage.driver, settings.storage.options)
    authenticator = Authenticator(settings.auth)
    metrics = IngestMetrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await driver.connect()
        if settings.storage.ensure_schema:
            await driver.ensure_schema()
        log.info(
            "server ready",
            extra={
                "driver": driver.name,
                "api_keys": len(authenticator),
                "anonymous": settings.auth.allow_anonymous,
            },
        )
        try:
            yield
        finally:
            await driver.close()

    app = FastAPI(
        title="smoke-server",
        version=__version__,
        description="Ingest API for smokeping-py agents.",
        lifespan=lifespan,
        root_path=settings.http.root_path,
    )
    app.state.settings = settings
    app.state.storage = driver
    app.state.authenticator = authenticator
    app.state.metrics = metrics

    # -- middleware --------------------------------------------------------

    @app.middleware("http")
    async def request_context(request: Request, call_next: Any) -> Response:
        request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex[:12]
        started = time.perf_counter()
        with bind_context(request_id=request_id):
            try:
                response = await call_next(request)
            except Exception:
                log.exception(
                    "unhandled error",
                    extra={"path": request.url.path, "method": request.method},
                )
                return JSONResponse(
                    {"detail": "internal server error", "request_id": request_id},
                    status_code=500,
                )
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            # Health checks fire constantly; logging them buries real traffic.
            if request.url.path not in ("/healthz", "/readyz", "/metrics"):
                log.info(
                    "request",
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "status": response.status_code,
                        "duration_ms": round(elapsed_ms, 2),
                    },
                )
            response.headers["X-Request-Id"] = request_id
            return response

    # -- ingest ------------------------------------------------------------

    @app.post("/api/v1/measurements", response_model=IngestResponse, status_code=201)
    async def ingest(request: Request) -> Response:
        try:
            principal = authenticator.authenticate(
                request.headers.get(settings.auth.header_name)
            )
        except AuthError as exc:
            metrics.auth_failures += 1
            log.warning(
                "auth failed",
                extra={"detail": str(exc), "client": _client_host(request)},
            )
            return JSONResponse({"detail": str(exc)}, status_code=exc.status_code)

        raw = await request.body()
        if len(raw) > settings.http.max_body_bytes:
            metrics.batches_rejected += 1
            return JSONResponse(
                {"detail": f"payload exceeds max_body_bytes={settings.http.max_body_bytes}"},
                status_code=413,
            )

        if request.headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError) as exc:
                metrics.batches_rejected += 1
                return JSONResponse({"detail": f"invalid gzip body: {exc}"}, status_code=400)

        try:
            batch = MeasurementBatch.model_validate_json(raw)
        except Exception as exc:  # noqa: BLE001 - pydantic raises ValidationError
            metrics.batches_rejected += 1
            # 400, not 503: this payload will never become valid, and the agent
            # must drop it rather than retry it forever.
            return JSONResponse(
                {"detail": f"malformed batch: {str(exc)[:600]}"}, status_code=400
            )

        try:
            authenticator.authorize_agent(principal, batch.agent_id)
        except AuthError as exc:
            metrics.auth_failures += 1
            return JSONResponse({"detail": str(exc)}, status_code=exc.status_code)

        if batch.protocol_version > PROTOCOL_VERSION:
            metrics.batches_rejected += 1
            return JSONResponse(
                {
                    "detail": (
                        f"batch protocol_version={batch.protocol_version} is newer than "
                        f"this server's {PROTOCOL_VERSION}; upgrade smoke-server"
                    )
                },
                status_code=400,
            )

        if not batch.measurements:
            return JSONResponse(IngestResponse(accepted=0).model_dump(), status_code=201)

        started = time.perf_counter()
        try:
            written = await driver.write_measurements(batch.measurements)
        except StorageError as exc:
            metrics.storage_errors += 1
            log.error(
                "storage write failed",
                extra={
                    "agent_id": batch.agent_id,
                    "count": len(batch.measurements),
                    "detail": str(exc)[:500],
                },
            )
            # 503 tells the agent to spool and retry -- data is not lost.
            return JSONResponse(
                {"detail": "storage unavailable, retry later"},
                status_code=503,
                headers={"Retry-After": "10"},
            )

        elapsed = time.perf_counter() - started
        hop_count = sum(len(m.hops) for m in batch.measurements)
        failed = sum(1 for m in batch.measurements if not m.success)

        metrics.batches_received += 1
        metrics.measurements_written += written
        metrics.measurements_failed_probe += failed
        metrics.hops_written += hop_count
        metrics.write_seconds_total += elapsed
        metrics.by_agent[batch.agent_id] = metrics.by_agent.get(batch.agent_id, 0) + written

        log.info(
            "ingested batch",
            extra={
                "agent_id": batch.agent_id,
                "agent_location": batch.agent_location,
                "measurements": written,
                "failed_probes": failed,
                "hops": hop_count,
                "write_ms": round(elapsed * 1000, 2),
                "principal": principal.label,
            },
        )
        return JSONResponse(
            IngestResponse(accepted=written).model_dump(), status_code=201
        )

    # -- operational endpoints --------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        """Liveness only.  Must not touch the database, or a database blip
        would make Kubernetes restart a perfectly healthy server."""
        return {
            "status": "ok",
            "version": __version__,
            "protocol_version": PROTOCOL_VERSION,
        }

    @app.get("/readyz")
    async def readyz() -> Response:
        healthy = await driver.health()
        return JSONResponse(
            {"status": "ok" if healthy else "unavailable", "driver": driver.name},
            status_code=200 if healthy else 503,
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    async def prometheus_metrics() -> Response:
        return PlainTextResponse(
            metrics.render_prometheus(), media_type="text/plain; version=0.0.4"
        )

    @app.get("/api/v1/info")
    async def info() -> dict[str, Any]:
        return {
            "version": __version__,
            "protocol_version": PROTOCOL_VERSION,
            "driver": driver.name,
            "anonymous_ingest": settings.auth.allow_anonymous,
            "metrics": {
                "batches_received": metrics.batches_received,
                "measurements_written": metrics.measurements_written,
            },
        }

    @app.get("/api/v1/agents")
    async def agents(request: Request) -> Response:
        try:
            authenticator.authenticate(request.headers.get(settings.auth.header_name))
        except AuthError as exc:
            metrics.auth_failures += 1
            return JSONResponse({"detail": str(exc)}, status_code=exc.status_code)
        try:
            return JSONResponse({"agents": _jsonable(await driver.agents())})
        except StorageError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=503)

    return app


def _client_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _jsonable(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Datetimes from the drivers are not JSON-serialisable on their own."""
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append(
            {
                key: (value.isoformat() if hasattr(value, "isoformat") else value)
                for key, value in row.items()
            }
        )
    return out
