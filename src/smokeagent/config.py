"""Agent configuration.

The target tree deliberately mirrors SmokePing's hierarchical ``Targets``
section: nodes nest, and ``probe`` / ``interval`` / ``options`` are inherited
by children unless overridden.  That keeps a 400-target config readable and
lets you retune a whole region by editing one line.

::

    targets:
      - name: kr
        title: Korea
        probe: ping             # inherited by everything below
        interval: 60
        children:
          - name: kt-dns
            host: 168.126.63.1
          - name: naver
            host: https://www.naver.com
            probe: curl          # override
            options: { expect_status: [200] }
          - name: sk-broadband
            host: 210.220.163.82
            probes: [ping, mtr]  # one target, two measurements

Every leaf that has a ``host`` becomes a measured target.  Intermediate nodes
may also carry a ``host`` -- exactly like SmokePing, where a menu entry can be
a target in its own right.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smokecommon.configfile import ConfigError, deep_merge, load_config_file

#: Applied when a target does not specify one.
DEFAULT_INTERVAL_S = 60.0

#: Environment overrides, applied after the file is read.  These exist so a
#: container can be configured without templating the YAML.
ENV_OVERRIDES = {
    "SMOKE_AGENT_ID": ("agent", "id"),
    "SMOKE_AGENT_LOCATION": ("agent", "location"),
    "SMOKE_SERVER_URL": ("server", "url"),
    "SMOKE_API_KEY": ("server", "api_key"),
    "SMOKE_LOG_LEVEL": ("logging", "level"),
    "SMOKE_LOG_FORMAT": ("logging", "format"),
}


@dataclass(slots=True)
class AgentIdentity:
    id: str
    location: str = "unknown"
    tags: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ServerConfig:
    url: str
    api_key: str
    #: HTTP timeout for one ship attempt.
    timeout: float = 15.0
    verify_tls: bool = True
    #: Path to a CA bundle for a private PKI.
    ca_bundle: str | None = None
    #: Flush when this many measurements are queued...
    batch_max_size: int = 200
    #: ...or when the oldest has waited this long.
    batch_max_seconds: float = 10.0
    #: Retry envelope for one flush attempt.
    max_retries: int = 4
    #: First backoff delay, seconds.  Actual sleeps are uniform(0, delay).
    retry_initial_delay: float = 1.0
    retry_backoff: float = 1.5
    #: gzip payloads above this size.
    compress_threshold_bytes: int = 4096
    #: Disk buffer used when the server is unreachable.  None disables it.
    spool_dir: str | None = None
    spool_max_bytes: int = 256 * 1024 * 1024


@dataclass(slots=True)
class SchedulerConfig:
    #: Ceiling on simultaneously running probes, to bound CPU and fd usage.
    max_concurrent_probes: int = 50
    #: Random fraction of the interval added to each cycle so 300 targets on a
    #: 60s interval do not all fire on the same second.
    jitter: float = 0.1
    #: Spread the *first* run of each target across its interval.
    stagger_start: bool = True
    #: Group batch-capable probes (fping) into shared invocations.
    enable_batching: bool = True


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"


@dataclass(slots=True)
class TargetSpec:
    """One measured (target, probe) pair with fully resolved options."""

    #: Leaf name, e.g. "kt-dns".
    name: str
    #: Slash path of ancestors, e.g. "/kr".
    group: str
    #: Address/URL handed to the probe.
    host: str
    probe: str
    interval: float
    options: dict[str, Any] = field(default_factory=dict)
    title: str | None = None
    #: Disable without deleting.
    enabled: bool = True

    @property
    def key(self) -> str:
        """Globally unique identifier: group path + name + probe."""
        base = f"{self.group.rstrip('/')}/{self.name}"
        return f"{base}#{self.probe}"

    def __str__(self) -> str:  # pragma: no cover
        return self.key


@dataclass(slots=True)
class AgentConfig:
    agent: AgentIdentity
    server: ServerConfig
    targets: list[TargetSpec]
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    probe_defaults: dict[str, dict[str, Any]] = field(default_factory=dict)
    plugin_dirs: list[str] = field(default_factory=list)

    def targets_by_probe(self) -> dict[str, list[TargetSpec]]:
        grouped: dict[str, list[TargetSpec]] = {}
        for target in self.targets:
            grouped.setdefault(target.probe, []).append(target)
        return grouped


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_agent_config(path: str | Path, environ: dict[str, str] | None = None) -> AgentConfig:
    raw = load_config_file(path, environ)
    return parse_agent_config(raw, environ)


def parse_agent_config(
    raw: dict[str, Any], environ: dict[str, str] | None = None
) -> AgentConfig:
    """Validate a raw config mapping into an :class:`AgentConfig`."""
    raw = _apply_env_overrides(raw, environ if environ is not None else dict(os.environ))

    agent_section = raw.get("agent") or {}
    if not isinstance(agent_section, dict):
        raise ConfigError("`agent` must be a mapping")

    identity = AgentIdentity(
        # Falling back to the hostname means a container works with no config
        # at all, but a stable explicit id survives re-scheduling.
        id=str(agent_section.get("id") or socket.gethostname()),
        location=str(agent_section.get("location") or "unknown"),
        tags={str(k): str(v) for k, v in (agent_section.get("tags") or {}).items()},
    )

    server_section = raw.get("server") or {}
    if not server_section.get("url"):
        raise ConfigError("`server.url` is required (e.g. https://smoke.example.com)")
    if not server_section.get("api_key"):
        raise ConfigError("`server.api_key` is required")
    server = _build_dataclass(ServerConfig, server_section, "server")

    scheduler = _build_dataclass(SchedulerConfig, raw.get("scheduler") or {}, "scheduler")
    logging_cfg = _build_dataclass(LoggingConfig, raw.get("logging") or {}, "logging")

    probe_defaults = raw.get("probe_defaults") or {}
    if not isinstance(probe_defaults, dict):
        raise ConfigError("`probe_defaults` must be a mapping of probe name -> options")

    target_nodes = raw.get("targets")
    if not target_nodes:
        raise ConfigError("`targets` is empty -- the agent would have nothing to measure")
    if not isinstance(target_nodes, list):
        raise ConfigError("`targets` must be a list of nodes")

    inherited = {
        "probe": raw.get("default_probe"),
        "interval": raw.get("default_interval", DEFAULT_INTERVAL_S),
        "options": {},
        "enabled": True,
    }
    targets: list[TargetSpec] = []
    for node in target_nodes:
        targets.extend(_walk_target(node, parent_path=[], inherited=inherited))

    _check_unique(targets)
    _apply_probe_defaults(targets, probe_defaults)

    return AgentConfig(
        agent=identity,
        server=server,
        targets=targets,
        scheduler=scheduler,
        logging=logging_cfg,
        probe_defaults=probe_defaults,
        plugin_dirs=[str(p) for p in (raw.get("plugin_dirs") or [])],
    )


def _walk_target(
    node: Any, parent_path: list[str], inherited: dict[str, Any]
) -> list[TargetSpec]:
    """Recursively flatten one config node into concrete target specs."""
    if not isinstance(node, dict):
        raise ConfigError(f"target node must be a mapping, got {type(node).__name__}: {node!r}")

    name = node.get("name")
    if not name:
        raise ConfigError(f"target node at /{'/'.join(parent_path)} is missing `name`")
    name = str(name)
    if "/" in name:
        raise ConfigError(f"target name {name!r} must not contain '/' (it builds the group path)")

    # Resolve this node's settings against what it inherited.
    probes = node.get("probes")
    if probes is None:
        single = node.get("probe", inherited.get("probe"))
        probes = [single] if single else []
    if not isinstance(probes, list):
        raise ConfigError(f"{name}: `probes` must be a list")

    current = {
        "probe": probes[0] if len(probes) == 1 else inherited.get("probe"),
        "interval": float(node.get("interval", inherited["interval"])),
        "options": deep_merge(inherited["options"], node.get("options") or {}),
        "enabled": bool(node.get("enabled", inherited["enabled"])),
    }

    specs: list[TargetSpec] = []
    host = node.get("host")
    if host:
        if not probes:
            raise ConfigError(
                f"target {name!r} has a host but no probe; set `probe` on it or an ancestor"
            )
        group = "/" + "/".join(parent_path) if parent_path else "/"
        for probe_name in probes:
            specs.append(
                TargetSpec(
                    name=name,
                    group=group,
                    host=str(host),
                    probe=str(probe_name),
                    interval=current["interval"],
                    # Per-probe options may be nested under the probe name so a
                    # multi-probe target can tune each one separately.
                    options=deep_merge(
                        current["options"], (node.get(str(probe_name)) or {})
                    ),
                    title=node.get("title"),
                    enabled=current["enabled"],
                )
            )

    children = node.get("children") or []
    if children and not isinstance(children, list):
        raise ConfigError(f"{name}: `children` must be a list")
    for child in children:
        specs.extend(
            _walk_target(child, parent_path=[*parent_path, name], inherited=current)
        )

    if not host and not children:
        raise ConfigError(f"target {name!r} has neither `host` nor `children`")
    return specs


def _check_unique(targets: list[TargetSpec]) -> None:
    seen: dict[str, TargetSpec] = {}
    for target in targets:
        existing = seen.get(target.key)
        if existing is not None:
            raise ConfigError(
                f"duplicate target {target.key!r}: {existing.host} and {target.host}. "
                "Target names must be unique within their group, per probe."
            )
        seen[target.key] = target


def _apply_probe_defaults(
    targets: list[TargetSpec], probe_defaults: dict[str, Any]
) -> None:
    """Fold ``probe_defaults`` under each target's own options.

    Precedence, lowest first: probe class defaults -> ``probe_defaults`` ->
    inherited group options -> target options.  The class defaults are applied
    later, when the probe object is constructed.
    """
    for target in targets:
        defaults = probe_defaults.get(target.probe) or {}
        if not isinstance(defaults, dict):
            raise ConfigError(f"probe_defaults.{target.probe} must be a mapping")
        target.options = deep_merge(defaults, target.options)


def _apply_env_overrides(
    raw: dict[str, Any], environ: dict[str, str]
) -> dict[str, Any]:
    result = {k: (dict(v) if isinstance(v, dict) else v) for k, v in raw.items()}
    for env_name, (section, key) in ENV_OVERRIDES.items():
        value = environ.get(env_name)
        if value:
            result.setdefault(section, {})
            if not isinstance(result[section], dict):
                raise ConfigError(f"`{section}` must be a mapping")
            result[section][key] = value
    return result


def _build_dataclass(cls: type, data: dict[str, Any], section: str) -> Any:
    """Instantiate a config dataclass, rejecting unknown keys.

    A typo'd key silently doing nothing is one of the classic monitoring
    outages, so unknown keys are a hard error with the valid set listed.
    """
    if not isinstance(data, dict):
        raise ConfigError(f"`{section}` must be a mapping")
    valid = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    unknown = set(data) - valid
    if unknown:
        raise ConfigError(
            f"unknown key(s) in `{section}`: {sorted(unknown)}. Valid keys: {sorted(valid)}"
        )
    try:
        return cls(**data)
    except TypeError as exc:
        raise ConfigError(f"`{section}`: {exc}") from exc
