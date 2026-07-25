"""Agent config: the SmokePing-style hierarchical target tree."""

from __future__ import annotations

import copy
import textwrap

import pytest
import yaml

from smokeagent.config import load_agent_config, parse_agent_config
from smokecommon.configfile import ConfigError, deep_merge, interpolate_env

BASE = {
    "agent": {"id": "agent-1", "location": "seoul", "tags": {"region": "kr"}},
    "server": {"url": "https://smoke.example.com", "api_key": "secret"},
}


def config(targets, **extra):
    """A fresh, deep-copied config so a test that mutates it cannot leak."""
    return {**copy.deepcopy(BASE), "targets": targets, **extra}


class TestIdentity:
    def test_reads_identity(self):
        cfg = parse_agent_config(
            config([{"name": "a", "host": "1.1.1.1", "probe": "ping"}]), environ={}
        )
        assert cfg.agent.id == "agent-1"
        assert cfg.agent.location == "seoul"
        assert cfg.agent.tags == {"region": "kr"}

    def test_defaults_agent_id_to_the_hostname(self):
        raw = config([{"name": "a", "host": "1.1.1.1", "probe": "ping"}])
        raw["agent"] = {}
        cfg = parse_agent_config(raw, environ={})
        assert cfg.agent.id

    def test_env_overrides_win(self):
        cfg = parse_agent_config(
            config([{"name": "a", "host": "1.1.1.1", "probe": "ping"}]),
            environ={"SMOKE_AGENT_LOCATION": "frankfurt", "SMOKE_API_KEY": "from-env"},
        )
        assert cfg.agent.location == "frankfurt"
        assert cfg.server.api_key == "from-env"

    def test_missing_server_url_is_rejected(self):
        raw = config([{"name": "a", "host": "1.1.1.1", "probe": "ping"}])
        raw["server"] = {"api_key": "x"}
        with pytest.raises(ConfigError, match=r"server\.url"):
            parse_agent_config(raw, environ={})

    def test_unknown_server_key_is_rejected_with_the_valid_set(self):
        raw = config([{"name": "a", "host": "1.1.1.1", "probe": "ping"}])
        raw["server"]["batch_max_sizee"] = 10
        with pytest.raises(ConfigError, match="batch_max_sizee"):
            parse_agent_config(raw, environ={})


class TestTargetTree:
    def test_flat_target(self):
        cfg = parse_agent_config(
            config([{"name": "dns", "host": "8.8.8.8", "probe": "ping"}]), environ={}
        )
        assert len(cfg.targets) == 1
        target = cfg.targets[0]
        assert target.name == "dns"
        assert target.group == "/"
        assert target.probe == "ping"
        assert target.key == "/dns#ping"

    def test_children_build_the_group_path(self):
        cfg = parse_agent_config(
            config(
                [
                    {
                        "name": "kr",
                        "probe": "ping",
                        "children": [
                            {
                                "name": "seoul",
                                "children": [{"name": "kt", "host": "168.126.63.1"}],
                            }
                        ],
                    }
                ]
            ),
            environ={},
        )
        assert len(cfg.targets) == 1
        assert cfg.targets[0].group == "/kr/seoul"
        assert cfg.targets[0].key == "/kr/seoul/kt#ping"

    def test_probe_and_interval_are_inherited(self):
        cfg = parse_agent_config(
            config(
                [
                    {
                        "name": "kr",
                        "probe": "ping",
                        "interval": 30,
                        "children": [
                            {"name": "a", "host": "1.1.1.1"},
                            {"name": "b", "host": "8.8.8.8", "interval": 120},
                        ],
                    }
                ]
            ),
            environ={},
        )
        by_name = {t.name: t for t in cfg.targets}
        assert by_name["a"].probe == "ping"
        assert by_name["a"].interval == 30.0
        assert by_name["b"].interval == 120.0

    def test_child_can_override_the_probe(self):
        cfg = parse_agent_config(
            config(
                [
                    {
                        "name": "web",
                        "probe": "ping",
                        "children": [
                            {"name": "site", "host": "https://example.com", "probe": "curl"}
                        ],
                    }
                ]
            ),
            environ={},
        )
        assert cfg.targets[0].probe == "curl"

    def test_options_merge_deeply_down_the_tree(self):
        cfg = parse_agent_config(
            config(
                [
                    {
                        "name": "kr",
                        "probe": "ping",
                        "options": {"count": 10, "interval": 0.3},
                        "children": [{"name": "a", "host": "1.1.1.1", "options": {"count": 20}}],
                    }
                ]
            ),
            environ={},
        )
        assert cfg.targets[0].options == {"count": 20, "interval": 0.3}

    def test_a_node_can_be_both_a_target_and_a_parent(self):
        # SmokePing allows a menu entry to be a target in its own right.
        cfg = parse_agent_config(
            config(
                [
                    {
                        "name": "gw",
                        "host": "10.0.0.1",
                        "probe": "ping",
                        "children": [{"name": "behind", "host": "10.0.1.5"}],
                    }
                ]
            ),
            environ={},
        )
        keys = {t.key for t in cfg.targets}
        assert keys == {"/gw#ping", "/gw/behind#ping"}

    def test_multiple_probes_on_one_target(self):
        cfg = parse_agent_config(
            config([{"name": "isp", "host": "1.1.1.1", "probes": ["ping", "mtr"]}]),
            environ={},
        )
        assert {t.probe for t in cfg.targets} == {"ping", "mtr"}
        assert {t.key for t in cfg.targets} == {"/isp#ping", "/isp#mtr"}

    def test_per_probe_option_blocks_for_a_multi_probe_target(self):
        cfg = parse_agent_config(
            config(
                [
                    {
                        "name": "isp",
                        "host": "1.1.1.1",
                        "probes": ["ping", "mtr"],
                        "options": {"timeout": 30},
                        "mtr": {"count": 10},
                    }
                ]
            ),
            environ={},
        )
        by_probe = {t.probe: t for t in cfg.targets}
        assert by_probe["mtr"].options == {"timeout": 30, "count": 10}
        assert by_probe["ping"].options == {"timeout": 30}

    def test_disabled_targets_are_kept_but_flagged(self):
        cfg = parse_agent_config(
            config([{"name": "a", "host": "1.1.1.1", "probe": "ping", "enabled": False}]),
            environ={},
        )
        assert cfg.targets[0].enabled is False

    def test_disabled_is_inherited_by_children(self):
        cfg = parse_agent_config(
            config(
                [
                    {
                        "name": "maintenance",
                        "probe": "ping",
                        "enabled": False,
                        "children": [{"name": "a", "host": "1.1.1.1"}],
                    }
                ]
            ),
            environ={},
        )
        assert cfg.targets[0].enabled is False


class TestProbeDefaults:
    def test_defaults_sit_underneath_target_options(self):
        cfg = parse_agent_config(
            config(
                [{"name": "a", "host": "1.1.1.1", "probe": "ping", "options": {"count": 3}}],
                probe_defaults={"ping": {"count": 10, "interval": 0.5}},
            ),
            environ={},
        )
        assert cfg.targets[0].options == {"count": 3, "interval": 0.5}

    def test_defaults_apply_when_the_target_says_nothing(self):
        cfg = parse_agent_config(
            config(
                [{"name": "a", "host": "1.1.1.1", "probe": "ping"}],
                probe_defaults={"ping": {"count": 10}},
            ),
            environ={},
        )
        assert cfg.targets[0].options == {"count": 10}


class TestErrors:
    def test_empty_targets(self):
        with pytest.raises(ConfigError, match="nothing to measure"):
            parse_agent_config(config([]), environ={})

    def test_target_without_a_probe(self):
        with pytest.raises(ConfigError, match="no probe"):
            parse_agent_config(config([{"name": "a", "host": "1.1.1.1"}]), environ={})

    def test_target_without_host_or_children(self):
        with pytest.raises(ConfigError, match="neither"):
            parse_agent_config(config([{"name": "a", "probe": "ping"}]), environ={})

    def test_missing_name(self):
        with pytest.raises(ConfigError, match="name"):
            parse_agent_config(config([{"host": "1.1.1.1", "probe": "ping"}]), environ={})

    def test_slash_in_name_is_rejected(self):
        with pytest.raises(ConfigError, match="must not contain"):
            parse_agent_config(
                config([{"name": "a/b", "host": "1.1.1.1", "probe": "ping"}]), environ={}
            )

    def test_duplicate_targets_in_the_same_group(self):
        with pytest.raises(ConfigError, match="duplicate"):
            parse_agent_config(
                config(
                    [
                        {"name": "a", "host": "1.1.1.1", "probe": "ping"},
                        {"name": "a", "host": "8.8.8.8", "probe": "ping"},
                    ]
                ),
                environ={},
            )

    def test_same_name_in_different_groups_is_fine(self):
        cfg = parse_agent_config(
            config(
                [
                    {"name": "kr", "probe": "ping", "children": [{"name": "gw", "host": "1.1.1.1"}]},
                    {"name": "jp", "probe": "ping", "children": [{"name": "gw", "host": "8.8.8.8"}]},
                ]
            ),
            environ={},
        )
        assert len(cfg.targets) == 2


class TestFileLoading:
    def test_yaml_round_trip(self, tmp_path):
        path = tmp_path / "agent.yaml"
        path.write_text(
            textwrap.dedent(
                """
                agent:
                  id: edge-01
                  location: busan
                server:
                  url: https://smoke.example.com
                  api_key: ${TEST_KEY}
                targets:
                  - name: kt
                    host: 168.126.63.1
                    probe: ping
                """
            ),
            encoding="utf-8",
        )
        cfg = load_agent_config(path, environ={"TEST_KEY": "from-env"})
        assert cfg.server.api_key == "from-env"
        assert cfg.agent.location == "busan"

    def test_toml_is_accepted(self, tmp_path):
        path = tmp_path / "agent.toml"
        path.write_text(
            textwrap.dedent(
                """
                [agent]
                id = "edge-02"
                location = "tokyo"

                [server]
                url = "https://smoke.example.com"
                api_key = "k"

                [[targets]]
                name = "dns"
                host = "8.8.8.8"
                probe = "ping"
                """
            ),
            encoding="utf-8",
        )
        cfg = load_agent_config(path, environ={})
        assert cfg.agent.location == "tokyo"
        assert cfg.targets[0].host == "8.8.8.8"

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            load_agent_config(tmp_path / "nope.yaml")

    def test_bad_yaml(self, tmp_path):
        path = tmp_path / "bad.yaml"
        path.write_text("targets: [\n  - broken", encoding="utf-8")
        with pytest.raises(ConfigError, match="could not parse"):
            load_agent_config(path, environ={})

    def test_unsupported_extension(self, tmp_path):
        path = tmp_path / "agent.ini"
        path.write_text("x=1", encoding="utf-8")
        with pytest.raises(ConfigError, match="unsupported config extension"):
            load_agent_config(path, environ={})

    def test_example_config_is_valid(self):
        # The shipped example must actually work -- it is the first thing
        # anyone copies.  Loaded through the real file path so that env
        # interpolation is exercised too.
        from pathlib import Path

        example = Path(__file__).resolve().parents[1] / "config" / "agent.example.yaml"
        if not example.exists():
            pytest.skip("example config not present")

        assert isinstance(yaml.safe_load(example.read_text(encoding="utf-8")), dict)
        cfg = load_agent_config(example, environ={"SMOKE_API_KEY": "test-key"})

        assert cfg.server.api_key == "test-key"
        assert len(cfg.targets) > 10
        # Every probe the README advertises appears in the example.
        assert {"ping", "fping", "dig", "curl", "nc", "mtr"} <= {t.probe for t in cfg.targets}

    def test_example_config_builds_runnable_jobs(self):
        # Parsing is not enough: every probe's options must also pass its own
        # validate(), which is where a bad count/timeout combination surfaces.
        from pathlib import Path

        from smokeagent.scheduler import Scheduler

        example = Path(__file__).resolve().parents[1] / "config" / "agent.example.yaml"
        if not example.exists():
            pytest.skip("example config not present")

        cfg = load_agent_config(example, environ={"SMOKE_API_KEY": "test-key"})

        class NullSink:
            async def submit(self, measurements):
                return None

        jobs = Scheduler(cfg, NullSink()).build_jobs()
        assert jobs
        # The three fping targets share options and interval, so they batch.
        assert any(job.batched for job in jobs)


class TestEnvInterpolation:
    def test_simple_substitution(self):
        assert interpolate_env("${FOO}", {"FOO": "bar"}) == "bar"

    def test_default_value(self):
        assert interpolate_env("${FOO:-fallback}", {}) == "fallback"

    def test_set_value_beats_the_default(self):
        assert interpolate_env("${FOO:-fallback}", {"FOO": "real"}) == "real"

    def test_missing_without_default_raises(self):
        # Silently expanding to "" would ship an agent with a blank API key.
        with pytest.raises(ConfigError, match="not set"):
            interpolate_env("${MISSING}", {})

    def test_embedded_in_a_longer_string(self):
        assert interpolate_env("https://${HOST}/api", {"HOST": "x.example"}) == "https://x.example/api"


class TestDeepMerge:
    def test_nested_dicts_merge(self):
        assert deep_merge({"a": {"x": 1, "y": 2}}, {"a": {"y": 3}}) == {"a": {"x": 1, "y": 3}}

    def test_lists_are_replaced_not_concatenated(self):
        # "expect_status: [200]" on a target means only 200, not the group's
        # statuses plus 200.
        assert deep_merge({"s": [1, 2]}, {"s": [3]}) == {"s": [3]}

    def test_inputs_are_not_mutated(self):
        base = {"a": {"x": 1}}
        deep_merge(base, {"a": {"y": 2}})
        assert base == {"a": {"x": 1}}
