# smoke-agent image
#
# Ships the probe binaries, because an agent without them is useless: ping,
# fping, dig, curl and mtr all come from the distro.  The `nc` probe is
# implemented natively on asyncio and needs nothing installed.
FROM python:3.12-slim-bookworm AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        iputils-ping \
        fping \
        dnsutils \
        curl \
        mtr-tiny \
        ca-certificates \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------
# Debian's iputils-ping and mtr-tiny use unprivileged ICMP datagram sockets
# where the kernel allows it, but that requires net.ipv4.ping_group_range to
# include the container's GID.  Granting the two binaries CAP_NET_RAW as a file
# capability is the portable answer and keeps the *process* unprivileged --
# strictly better than running the whole agent as root.
RUN setcap cap_net_raw+ep /usr/bin/ping 2>/dev/null || true && \
    setcap cap_net_raw+ep /usr/bin/mtr-packet 2>/dev/null || true && \
    setcap cap_net_raw+ep /usr/bin/fping 2>/dev/null || true

FROM base AS build

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /wheels

FROM base AS runtime

RUN groupadd --system --gid 10001 smoke && \
    useradd --system --uid 10001 --gid smoke --home /var/lib/smoke-agent smoke && \
    mkdir -p /var/lib/smoke-agent/spool /etc/smokeping && \
    chown -R smoke:smoke /var/lib/smoke-agent

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

USER smoke
WORKDIR /var/lib/smoke-agent

VOLUME ["/var/lib/smoke-agent/spool"]

# The agent has no listening port, so health is "can it parse its config and
# find its probe binaries".
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD smoke-agent check -c /etc/smokeping/agent.yaml >/dev/null || exit 1

ENTRYPOINT ["smoke-agent"]
CMD ["run", "-c", "/etc/smokeping/agent.yaml"]
