"""Probe registry and the plugin loading mechanism.

The "add a probe by dropping a file in a directory" promise is a headline
feature, so it gets a real end-to-end test rather than a mocked one.
"""

from __future__ import annotations

import textwrap

import pytest

from smokeagent.probes.base import (
    BUILTIN_MODULES,
    Probe,
    ProbeTarget,
    get_probe_class,
    load_builtin_probes,
    load_plugin_dir,
    registered_probes,
)
from smokecommon.models import ProbeResult

PLUGIN_SOURCE = textwrap.dedent(
    '''
    """A probe supplied by an operator, not shipped with the agent."""

    from smokeagent.probes.base import Probe, ProbeTarget, register_probe
    from smokecommon.models import ProbeResult


    @register_probe
    class SyntheticProbe(Probe):
        name = "synthetic"
        description = "always reports a fixed latency"
        default_options = {"timeout": 1.0, "latency_ms": 3.5}

        async def probe(self, target: ProbeTarget) -> ProbeResult:
            return ProbeResult(
                success=True,
                rtts_ms=[float(self.options["latency_ms"])],
                packets_sent=1,
                packets_received=1,
                resolved_ip="203.0.113.55",
            )
    '''
)

BROKEN_PLUGIN_SOURCE = "this is not valid python ((("


class TestBuiltins:
    def test_all_required_probes_are_registered(self):
        load_builtin_probes()
        registry = registered_probes()
        for name in ("ping", "fping", "dig", "curl", "nc", "mtr"):
            assert name in registry, f"{name} probe is missing"

    def test_tcp_and_udp_aliases_exist(self):
        load_builtin_probes()
        assert {"tcp", "udp"} <= set(registered_probes())

    def test_every_builtin_module_is_listed(self):
        assert len(BUILTIN_MODULES) == 6

    def test_probes_declare_their_binary(self):
        load_builtin_probes()
        registry = registered_probes()
        assert registry["mtr"].required_binary == "mtr"
        assert registry["fping"].required_binary == "fping"
        # nc is implemented natively, so it needs nothing installed.
        assert registry["nc"].required_binary is None

    def test_unknown_probe_error_lists_what_is_available(self):
        load_builtin_probes()
        with pytest.raises(KeyError) as exc:
            get_probe_class("does-not-exist")
        assert "ping" in str(exc.value)


class TestOptionResolution:
    def test_class_defaults_apply_when_unset(self):
        from smokeagent.probes.ping import PingProbe

        assert PingProbe().options["count"] == PingProbe.default_options["count"]

    def test_passed_options_override_defaults(self):
        from smokeagent.probes.ping import PingProbe

        assert PingProbe({"count": 42}).options["count"] == 42

    def test_subclass_defaults_beat_parent_defaults(self):
        from smokeagent.probes.nc import NcProbe, UdpProbe

        assert NcProbe().options["protocol"] == "tcp"
        assert UdpProbe().options["protocol"] == "udp"
        # ...while still inheriting everything the parent declared.
        assert "read_timeout" in UdpProbe().options


class TestPluginDirectory:
    def test_loads_a_dropped_in_probe(self, tmp_path):
        (tmp_path / "synthetic.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
        loaded = load_plugin_dir(tmp_path)

        assert len(loaded) == 1
        assert "synthetic" in registered_probes()

    async def test_a_loaded_plugin_actually_runs(self, tmp_path):
        (tmp_path / "synthetic.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
        load_plugin_dir(tmp_path)

        probe = get_probe_class("synthetic")()
        result = await probe.run(ProbeTarget(name="t", address="anything"))

        assert isinstance(result, ProbeResult)
        assert result.success is True
        assert result.rtts_ms == [3.5]
        assert result.resolved_ip == "203.0.113.55"

    async def test_plugin_options_are_honoured(self, tmp_path):
        (tmp_path / "synthetic.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
        load_plugin_dir(tmp_path)

        probe = get_probe_class("synthetic")({"latency_ms": 99.0})
        result = await probe.run(ProbeTarget(name="t", address="x"))
        assert result.rtts_ms == [99.0]

    def test_a_broken_plugin_does_not_stop_the_agent(self, tmp_path, caplog):
        # One bad file must not take down 300 working targets.
        (tmp_path / "broken.py").write_text(BROKEN_PLUGIN_SOURCE, encoding="utf-8")
        (tmp_path / "working.py").write_text(PLUGIN_SOURCE, encoding="utf-8")

        loaded = load_plugin_dir(tmp_path)
        assert len(loaded) == 1
        assert "synthetic" in registered_probes()

    def test_underscore_files_are_skipped(self, tmp_path):
        (tmp_path / "_helpers.py").write_text("raise RuntimeError('should not import')")
        assert load_plugin_dir(tmp_path) == []

    def test_missing_directory_is_a_warning_not_a_crash(self, tmp_path):
        assert load_plugin_dir(tmp_path / "nope") == []


class TestRegistration:
    def test_a_probe_without_a_name_is_rejected(self):
        from smokeagent.probes.base import register_probe

        class Nameless(Probe):
            async def probe(self, target):  # pragma: no cover
                return ProbeResult(success=True)

        with pytest.raises(ValueError, match="non-empty `name`"):
            register_probe(Nameless)

    def test_is_available_reflects_path(self, monkeypatch):
        from smokeagent.probes.mtr import MtrProbe

        monkeypatch.setattr("smokeagent.probes.base.which", lambda binary: None)
        assert MtrProbe.is_available() is False

        monkeypatch.setattr("smokeagent.probes.base.which", lambda binary: "/usr/bin/mtr")
        assert MtrProbe.is_available() is True
