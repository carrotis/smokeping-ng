# smoke-server image
#
# No probe binaries here -- the server only receives, authenticates and stores.
FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

FROM base AS build

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /wheels

FROM base AS runtime

RUN groupadd --system --gid 10002 smoke && \
    useradd --system --uid 10002 --gid smoke --home /var/lib/smoke-server smoke && \
    mkdir -p /etc/smokeping

COPY --from=build /wheels /wheels
# Both storage drivers, so one image serves either backend.
RUN pip install --no-cache-dir "$(echo /wheels/*.whl)[server,postgres,clickhouse]" && \
    rm -rf /wheels

USER smoke
WORKDIR /var/lib/smoke-server

EXPOSE 8080

# /healthz deliberately does not touch the database: a database blip should
# not make the orchestrator restart a perfectly healthy server. Use /readyz
# for load-balancer readiness instead.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["smoke-server"]
CMD ["run", "-c", "/etc/smokeping/server.yaml"]
