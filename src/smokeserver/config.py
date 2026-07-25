"""smoke-server configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from smokecommon.configfile import ConfigError, load_config_file

ENV_OVERRIDES = {
    "SMOKE_SERVER_HOST": ("http", "host"),
    "SMOKE_SERVER_PORT": ("http", "port"),
    "SMOKE_STORAGE_DRIVER": ("storage", "driver"),
    "SMOKE_LOG_LEVEL": ("logging", "level"),
    "SMOKE_LOG_FORMAT": ("logging", "format"),
}


@dataclass(slots=True)
class HttpConfig:
    host: str = "0.0.0.0"  # noqa: S104 - a monitoring ingest is meant to be reachable
    port: int = 8080
    #: Reject payloads above this size before parsing them.
    max_body_bytes: int = 32 * 1024 * 1024
    #: Trust X-Forwarded-For (only enable behind a proxy you control).
    proxy_headers: bool = False
    root_path: str = ""


@dataclass(slots=True)
class ApiKeyConfig:
    """One credential.

    Supply either ``key`` (plaintext, usually via ``${SMOKE_API_KEY}``) or
    ``key_sha256`` (the hex digest), so a config file that lands in git does
    not have to contain a live secret.
    """

    key: str | None = None
    key_sha256: str | None = None
    label: str = "default"
    #: Agent ids this key may write as.  ``["*"]`` allows any.
    agent_ids: list[str] = field(default_factory=lambda: ["*"])
    enabled: bool = True


@dataclass(slots=True)
class AuthConfig:
    keys: list[ApiKeyConfig] = field(default_factory=list)
    header_name: str = "X-API-Key"
    #: Accept unauthenticated ingest.  Only sane on a private network.
    allow_anonymous: bool = False


@dataclass(slots=True)
class StorageConfig:
    driver: str = "clickhouse"
    #: Driver-specific keyword arguments; see the driver classes.
    options: dict[str, Any] = field(default_factory=dict)
    #: Run DDL at startup.  Turn off if a migration tool owns the schema.
    ensure_schema: bool = True


@dataclass(slots=True)
class LoggingConfig:
    level: str = "INFO"
    format: str = "json"


@dataclass(slots=True)
class ServerSettings:
    http: HttpConfig = field(default_factory=HttpConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_server_config(
    path: str | Path, environ: dict[str, str] | None = None
) -> ServerSettings:
    return parse_server_config(load_config_file(path, environ), environ)


def parse_server_config(
    raw: dict[str, Any], environ: dict[str, str] | None = None
) -> ServerSettings:
    raw = _apply_env_overrides(raw, environ if environ is not None else dict(os.environ))

    http = _build(HttpConfig, raw.get("http") or {}, "http")

    auth_section = raw.get("auth") or {}
    if not isinstance(auth_section, dict):
        raise ConfigError("`auth` must be a mapping")
    keys = [
        _build(ApiKeyConfig, entry, f"auth.keys[{index}]")
        for index, entry in enumerate(auth_section.get("keys") or [])
    ]
    auth = AuthConfig(
        keys=keys,
        header_name=str(auth_section.get("header_name", "X-API-Key")),
        allow_anonymous=bool(auth_section.get("allow_anonymous", False)),
    )
    if not auth.keys and not auth.allow_anonymous:
        raise ConfigError(
            "no API keys configured and auth.allow_anonymous is false -- "
            "the server would reject every agent"
        )
    for index, key in enumerate(auth.keys):
        # A disabled entry is a placeholder (commonly `key: ${SMOKE_API_KEY:-}`
        # for a dev credential that is not injected in production), so it is
        # allowed to carry no secret at all.
        if key.enabled and not key.key and not key.key_sha256:
            raise ConfigError(f"auth.keys[{index}] needs either `key` or `key_sha256`")

    if not any(k.enabled for k in auth.keys) and not auth.allow_anonymous:
        raise ConfigError(
            "every configured API key is disabled and auth.allow_anonymous is "
            "false -- the server would reject every agent"
        )

    storage_section = raw.get("storage") or {}
    if not isinstance(storage_section, dict):
        raise ConfigError("`storage` must be a mapping")
    driver = str(storage_section.get("driver", "clickhouse"))
    # Options may be nested under the driver name (readable when you keep
    # settings for both backends in one file) or given flat under `options`.
    options = storage_section.get("options")
    if options is None:
        options = storage_section.get(driver) or storage_section.get(
            {"postgresql": "postgres"}.get(driver, driver)
        )
    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise ConfigError("`storage.options` must be a mapping")

    storage = StorageConfig(
        driver=driver,
        options=options,
        ensure_schema=bool(storage_section.get("ensure_schema", True)),
    )

    logging_cfg = _build(LoggingConfig, raw.get("logging") or {}, "logging")
    return ServerSettings(http=http, auth=auth, storage=storage, logging=logging_cfg)


def _apply_env_overrides(raw: dict[str, Any], environ: dict[str, str]) -> dict[str, Any]:
    result = {k: (dict(v) if isinstance(v, dict) else v) for k, v in raw.items()}
    for env_name, (section, key) in ENV_OVERRIDES.items():
        value = environ.get(env_name)
        if value:
            section_data = result.setdefault(section, {})
            if not isinstance(section_data, dict):
                raise ConfigError(f"`{section}` must be a mapping")
            section_data[key] = int(value) if key == "port" else value
    return result


def _build(cls: type, data: dict[str, Any], section: str) -> Any:
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
