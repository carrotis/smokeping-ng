"""Configuration file loading for both daemons.

YAML and TOML are both accepted, picked by file extension.  String values go
through shell-style environment interpolation so secrets never have to live in
the file itself::

    api_key: ${SMOKE_API_KEY}
    dsn: ${CLICKHOUSE_DSN:-http://localhost:8123}
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

#: ${NAME} or ${NAME:-fallback}
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class ConfigError(ValueError):
    """Raised for anything wrong with a config file: syntax, type, semantics."""


def interpolate_env(value: str, environ: dict[str, str] | None = None) -> str:
    """Expand ``${VAR}`` / ``${VAR:-default}`` references in ``value``.

    An unset variable with no default raises, rather than silently expanding
    to an empty string -- a blank API key that "works" until the first request
    is much worse than a startup crash.
    """
    env = environ if environ is not None else dict(os.environ)

    def _replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        if name in env:
            return env[name]
        if default is not None:
            return default
        raise ConfigError(
            f"environment variable {name!r} referenced in config is not set "
            f"(use ${{{name}:-default}} to make it optional)"
        )

    return _ENV_PATTERN.sub(_replace, value)


def _walk(node: Any, environ: dict[str, str] | None) -> Any:
    if isinstance(node, str):
        return interpolate_env(node, environ)
    if isinstance(node, dict):
        return {k: _walk(v, environ) for k, v in node.items()}
    if isinstance(node, list):
        return [_walk(v, environ) for v in node]
    return node


def load_config_file(path: str | Path, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Parse a YAML or TOML config file into a plain dict."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")

    suffix = p.suffix.lower()
    raw = p.read_bytes()
    try:
        if suffix == ".toml":
            data = tomllib.loads(raw.decode("utf-8"))
        elif suffix in (".yaml", ".yml"):
            data = yaml.safe_load(raw.decode("utf-8"))
        else:
            raise ConfigError(f"unsupported config extension {suffix!r} (use .yaml, .yml or .toml)")
    except (yaml.YAMLError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"could not parse {p}: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: top level must be a mapping, got {type(data).__name__}")

    return _walk(data, environ)


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` onto ``base``, returning a new dict.

    Used for probe defaults -> group -> target option inheritance.  Lists are
    replaced wholesale, not concatenated: a target that overrides
    ``expect_status`` means *only* those statuses, not "the group's plus mine".
    """
    result = dict(base)
    for key, value in override.items():
        existing = result.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            result[key] = deep_merge(existing, value)
        else:
            result[key] = value
    return result
