"""fping probe: batch measurement of many targets in one process."""

from __future__ import annotations

import pytest

from smokeagent.probes.base import ProbeTarget
from smokeagent.probes.fping import FpingProbe
from smokecommon.errors import ErrorType

from conftest import make_output

# Real `fping -C 5 -q` output.  The -C table goes to stderr.
FPING_C_TABLE = """8.8.8.8    : 12.3 11.9 12.1 12.0 11.8
1.1.1.1    : 8.1 - 8.3 8.2 -
192.0.2.1  : - - - - -
"""


def targets(*pairs):
    return [ProbeTarget(name=name, address=address) for name, address in pairs]


class TestBatchParsing:
    def test_parses_every_address(self):
        probe = FpingProbe({"count": 5})
        results = probe.parse_batch(
            make_output(stderr=FPING_C_TABLE), ["8.8.8.8", "1.1.1.1", "192.0.2.1"]
        )
        assert set(results) == {"8.8.8.8", "1.1.1.1", "192.0.2.1"}

    def test_clean_target(self):
        probe = FpingProbe({"count": 5})
        result = probe.parse_batch(make_output(stderr=FPING_C_TABLE), ["8.8.8.8"])["8.8.8.8"]

        assert result.success is True
        assert result.rtts_ms == [12.3, 11.9, 12.1, 12.0, 11.8]
        assert result.packets_sent == 5
        assert result.packets_received == 5
        assert result.loss_pct == 0.0
        assert result.resolved_ip == "8.8.8.8"

    def test_partial_loss_dashes_are_dropped_from_the_samples(self):
        probe = FpingProbe({"count": 5})
        result = probe.parse_batch(make_output(stderr=FPING_C_TABLE), ["1.1.1.1"])["1.1.1.1"]

        assert result.success is True
        assert result.rtts_ms == [8.1, 8.3, 8.2]
        assert result.packets_received == 3
        assert result.loss_pct == 40.0

    def test_total_loss_is_a_failure(self):
        probe = FpingProbe({"count": 5})
        result = probe.parse_batch(make_output(stderr=FPING_C_TABLE), ["192.0.2.1"])["192.0.2.1"]

        assert result.success is False
        assert result.error_type is ErrorType.PACKET_LOSS
        assert result.packets_received == 0
        # Still attributed to the address, so the failure shows up per-IP.
        assert result.resolved_ip == "192.0.2.1"

    def test_reads_the_table_from_stdout_too(self):
        # fping builds disagree about which stream the -C table lands on.
        probe = FpingProbe({"count": 5})
        results = probe.parse_batch(make_output(stdout=FPING_C_TABLE), ["8.8.8.8"])
        assert results["8.8.8.8"].rtts_ms


class TestBatchExecution:
    async def test_resolves_names_and_maps_results_back(self, monkeypatch):
        # Names are resolved in-agent so `resolved_ip` is exact and the
        # output-to-target mapping is unambiguous.
        async def fake_resolve(self, host):
            return {"a.example": "8.8.8.8", "b.example": "1.1.1.1"}[host]

        async def fake_run(argv, timeout, **kwargs):
            assert "8.8.8.8" in argv and "1.1.1.1" in argv
            return make_output(stderr=FPING_C_TABLE, argv=argv)

        monkeypatch.setattr(FpingProbe, "_resolve", fake_resolve)
        monkeypatch.setattr("smokeagent.probes.fping.run_command", fake_run)

        probe = FpingProbe({"count": 5})
        results = await probe.probe_many(targets(("a", "a.example"), ("b", "b.example")))

        assert results["a"].resolved_ip == "8.8.8.8"
        assert results["a"].rtts_ms == [12.3, 11.9, 12.1, 12.0, 11.8]
        assert results["b"].resolved_ip == "1.1.1.1"
        assert results["b"].packets_received == 3

    async def test_two_targets_sharing_an_address_both_get_results(self, monkeypatch):
        async def fake_resolve(self, host):
            return "8.8.8.8"

        async def fake_run(argv, timeout, **kwargs):
            return make_output(stderr=FPING_C_TABLE, argv=argv)

        monkeypatch.setattr(FpingProbe, "_resolve", fake_resolve)
        monkeypatch.setattr("smokeagent.probes.fping.run_command", fake_run)

        results = await FpingProbe({"count": 5}).probe_many(
            targets(("primary", "dns.google"), ("alias", "8.8.8.8"))
        )
        assert results["primary"].rtts_ms == results["alias"].rtts_ms
        # Separate objects, so downstream mutation cannot bleed across targets.
        assert results["primary"] is not results["alias"]

    async def test_unresolvable_target_fails_without_taking_down_the_batch(self, monkeypatch):
        async def fake_resolve(self, host):
            if host == "bad.invalid":
                raise OSError("Name or service not known")
            return "8.8.8.8"

        async def fake_run(argv, timeout, **kwargs):
            return make_output(stderr=FPING_C_TABLE, argv=argv)

        monkeypatch.setattr(FpingProbe, "_resolve", fake_resolve)
        monkeypatch.setattr("smokeagent.probes.fping.run_command", fake_run)

        results = await FpingProbe({"count": 5}).probe_many(
            targets(("good", "dns.google"), ("bad", "bad.invalid"))
        )
        assert results["good"].success is True
        assert results["bad"].success is False
        assert results["bad"].error_type is ErrorType.DNS_FAILURE

    async def test_address_missing_from_output_is_reported(self, monkeypatch):
        async def fake_resolve(self, host):
            return "203.0.113.9"

        async def fake_run(argv, timeout, **kwargs):
            return make_output(stderr=FPING_C_TABLE, argv=argv)

        monkeypatch.setattr(FpingProbe, "_resolve", fake_resolve)
        monkeypatch.setattr("smokeagent.probes.fping.run_command", fake_run)

        results = await FpingProbe({"count": 5}).probe_many(targets(("x", "ghost.example")))
        assert results["x"].success is False
        assert results["x"].error_type is ErrorType.PARSE_ERROR

    async def test_empty_batch(self):
        assert await FpingProbe().probe_many([]) == {}


class TestCommandConstruction:
    def test_intervals_and_timeouts_are_milliseconds(self):
        argv = FpingProbe({"count": 5, "interval": 0.25, "packet_timeout": 1.5}).build_argv(
            ["8.8.8.8"]
        )
        assert argv[argv.index("-p") + 1] == "250"
        assert argv[argv.index("-t") + 1] == "1500"
        assert argv[argv.index("-C") + 1] == "5"

    def test_no_retries_or_backoff(self):
        # We want a clean sample of the link, not fping's reachability logic.
        argv = FpingProbe().build_argv(["8.8.8.8"])
        assert argv[argv.index("-r") + 1] == "0"
        assert argv[argv.index("-B") + 1] == "1"

    def test_all_addresses_are_appended(self):
        argv = FpingProbe().build_argv(["1.1.1.1", "8.8.8.8"])
        assert argv[-2:] == ["1.1.1.1", "8.8.8.8"]


class TestProbeMetadata:
    def test_declares_batch_support(self):
        assert FpingProbe.supports_batch is True

    def test_validation_rejects_an_impossible_cycle(self):
        with pytest.raises(ValueError, match="too short"):
            FpingProbe({"count": 100, "interval": 1.0, "timeout": 10.0}).validate()
