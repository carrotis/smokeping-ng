"""Server configuration parsing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from smokecommon.configfile import ConfigError
from smokeserver.config import parse_server_config

MINIMAL = {"auth": {"keys": [{"key": "k", "label": "a"}]}}


class TestDefaults:
    def test_sensible_defaults(self):
        settings = parse_server_config(MINIMAL, environ={})
        assert settings.http.port == 8080
        assert settings.storage.driver == "clickhouse"
        assert settings.storage.ensure_schema is True
        assert settings.logging.format == "json"

    def test_env_overrides(self):
        settings = parse_server_config(
            MINIMAL, environ={"SMOKE_SERVER_PORT": "9999", "SMOKE_STORAGE_DRIVER": "postgresql"}
        )
        assert settings.http.port == 9999
        assert settings.storage.driver == "postgresql"


class TestAuthSection:
    def test_keys_are_parsed(self):
        settings = parse_server_config(
            {"auth": {"keys": [{"key": "k", "label": "seoul", "agent_ids": ["seoul-1"]}]}},
            environ={},
        )
        assert settings.auth.keys[0].label == "seoul"
        assert settings.auth.keys[0].agent_ids == ["seoul-1"]

    def test_no_keys_and_no_anonymous_is_rejected(self):
        # Otherwise the server starts happily and rejects every agent.
        with pytest.raises(ConfigError, match="reject every agent"):
            parse_server_config({"auth": {"keys": []}}, environ={})

    def test_anonymous_alone_is_allowed(self):
        settings = parse_server_config({"auth": {"allow_anonymous": True}}, environ={})
        assert settings.auth.allow_anonymous is True

    def test_enabled_key_without_a_secret_is_rejected(self):
        with pytest.raises(ConfigError, match="needs either"):
            parse_server_config({"auth": {"keys": [{"label": "oops"}]}}, environ={})

    def test_disabled_placeholder_key_needs_no_secret(self):
        # A common pattern: `key: ${SMOKE_API_KEY:-}` for a dev credential
        # that is simply not injected in production.
        settings = parse_server_config(
            {
                "auth": {
                    "keys": [
                        {"key": "real", "label": "prod"},
                        {"key": "", "label": "dev", "enabled": False},
                    ]
                }
            },
            environ={},
        )
        assert len(settings.auth.keys) == 2

    def test_all_keys_disabled_is_rejected(self):
        with pytest.raises(ConfigError, match="disabled"):
            parse_server_config(
                {"auth": {"keys": [{"key": "k", "enabled": False}]}}, environ={}
            )


class TestStorageSection:
    def test_options_nested_under_the_driver_name(self):
        settings = parse_server_config(
            {
                **MINIMAL,
                "storage": {
                    "driver": "clickhouse",
                    "clickhouse": {"database": "metrics"},
                    "postgresql": {"dsn": "postgresql://unused"},
                },
            },
            environ={},
        )
        # Only the active driver's block is used.
        assert settings.storage.options == {"database": "metrics"}

    def test_flat_options_block(self):
        settings = parse_server_config(
            {**MINIMAL, "storage": {"driver": "postgresql", "options": {"dsn": "postgresql://x"}}},
            environ={},
        )
        assert settings.storage.options == {"dsn": "postgresql://x"}

    def test_postgres_block_can_be_spelled_postgres(self):
        settings = parse_server_config(
            {**MINIMAL, "storage": {"driver": "postgresql", "postgres": {"dsn": "postgresql://y"}}},
            environ={},
        )
        assert settings.storage.options == {"dsn": "postgresql://y"}

    def test_missing_storage_section_uses_defaults(self):
        settings = parse_server_config(MINIMAL, environ={})
        assert settings.storage.options == {}


class TestUnknownKeys:
    def test_typo_in_http_is_a_hard_error(self):
        with pytest.raises(ConfigError, match="prot"):
            parse_server_config({**MINIMAL, "http": {"prot": 8080}}, environ={})


class TestExampleConfig:
    """The shipped example is the first thing anyone copies, so it is loaded
    end to end -- through the real file loader, including env interpolation."""

    ENV = {
        "SMOKE_KEY_SEOUL_SHA256": "a" * 64,
        "SMOKE_KEY_FRANKFURT_SHA256": "b" * 64,
    }

    @property
    def path(self) -> Path:
        return Path(__file__).resolve().parents[1] / "config" / "server.example.yaml"

    def load(self):
        from smokeserver.config import load_server_config

        if not self.path.exists():
            pytest.skip("example config not present")
        return load_server_config(self.path, environ=self.ENV)

    def test_the_shipped_example_parses(self):
        settings = self.load()
        assert settings.storage.driver == "clickhouse"
        assert settings.storage.options["database"] == "smokeping"
        assert any(k.label == "seoul-idc" for k in settings.auth.keys)

    def test_it_is_valid_yaml(self):
        if not self.path.exists():
            pytest.skip("example config not present")
        assert isinstance(yaml.safe_load(self.path.read_text(encoding="utf-8")), dict)

    def test_the_example_builds_a_working_authenticator(self):
        from smokeserver.auth import Authenticator

        settings = self.load()
        # The disabled dev key must not be loaded as a credential.
        assert len(Authenticator(settings.auth)) == 2

    def test_the_example_keys_are_bound_to_specific_agents(self):
        settings = self.load()
        enabled = [k for k in settings.auth.keys if k.enabled]
        assert all(k.agent_ids != ["*"] for k in enabled), (
            "the example should demonstrate agent-id binding, not wildcards"
        )
