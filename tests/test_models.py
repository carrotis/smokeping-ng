"""Tests for the shared wire models and statistics."""

from __future__ import annotations

import math

import pytest

from smokecommon.errors import ErrorType, classify_stderr
from smokecommon.models import Measurement, ProbeResult, RttStats, percentile

from conftest import make_measurement


class TestPercentile:
    def test_median_of_odd_length(self):
        assert percentile([1.0, 2.0, 3.0], 0.5) == 2.0

    def test_median_of_even_length_interpolates(self):
        assert percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 2.5

    def test_extremes(self):
        values = [5.0, 10.0, 15.0]
        assert percentile(values, 0.0) == 5.0
        assert percentile(values, 1.0) == 15.0

    def test_single_value(self):
        assert percentile([7.5], 0.95) == 7.5

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            percentile([], 0.5)


class TestRttStats:
    def test_computes_full_summary(self):
        stats = RttStats.from_rtts([10.0, 20.0, 30.0, 40.0])
        assert stats is not None
        assert stats.min_ms == 10.0
        assert stats.max_ms == 40.0
        assert stats.avg_ms == 25.0
        assert stats.median_ms == 25.0
        # Population stddev of [10,20,30,40] is sqrt(125).
        assert stats.stddev_ms == pytest.approx(math.sqrt(125.0))

    def test_jitter_is_mean_successive_difference(self):
        # Differences are 10, 10, 10 -> jitter 10.  Order matters here, so this
        # also proves we are not sorting before computing jitter.
        stats = RttStats.from_rtts([10.0, 20.0, 30.0, 40.0])
        assert stats is not None
        assert stats.jitter_ms == pytest.approx(10.0)

    def test_jitter_sees_ordering(self):
        steady = RttStats.from_rtts([10.0, 11.0, 10.0, 11.0])
        spiky = RttStats.from_rtts([10.0, 50.0, 10.0, 50.0])
        assert steady is not None and spiky is not None
        assert spiky.jitter_ms > steady.jitter_ms

    def test_single_sample_has_zero_jitter(self):
        stats = RttStats.from_rtts([12.0])
        assert stats is not None
        assert stats.jitter_ms == 0.0
        assert stats.stddev_ms == 0.0

    def test_empty_returns_none(self):
        assert RttStats.from_rtts([]) is None


class TestProbeResult:
    def test_loss_pct(self):
        result = ProbeResult(success=True, packets_sent=10, packets_received=7)
        assert result.loss_pct == 30.0

    def test_loss_pct_is_none_without_packets(self):
        assert ProbeResult(success=True).loss_pct is None

    def test_effective_latency_falls_back_to_median(self):
        result = ProbeResult(success=True, rtts_ms=[10.0, 20.0, 60.0])
        assert result.effective_latency_ms == 20.0

    def test_explicit_latency_wins(self):
        result = ProbeResult(success=True, rtts_ms=[10.0, 20.0], latency_ms=99.0)
        assert result.effective_latency_ms == 99.0

    def test_failure_helper_truncates_long_messages(self):
        result = ProbeResult.failure(ErrorType.TIMEOUT, "x" * 5000)
        assert result.success is False
        assert result.error_type is ErrorType.TIMEOUT
        assert len(result.error_message or "") == 2000


class TestMeasurement:
    def test_from_probe_result_carries_vantage_point(self, probe_result):
        m = Measurement.from_probe_result(
            probe_result,
            agent_id="agent-7",
            agent_location="frankfurt",
            agent_tags={"region": "eu"},
            target_name="cloudflare",
            target_group="/eu/dns",
            target="1.1.1.1",
            probe="ping",
        )
        assert m.agent_location == "frankfurt"
        assert m.agent_tags == {"region": "eu"}
        assert m.target_group == "/eu/dns"
        assert m.latency_ms == 20.0
        assert m.stats is not None and m.stats.p95_ms == pytest.approx(29.0)
        assert m.ip_family == 4

    def test_ipv6_family_detected(self, probe_result):
        probe_result.resolved_ip = "2606:4700:4700::1111"
        m = Measurement.from_probe_result(
            probe_result,
            agent_id="a",
            agent_location="l",
            target_name="t",
            target_group="/",
            target="x",
            probe="ping",
        )
        assert m.ip_family == 6

    @pytest.mark.parametrize(
        ("given", "expected"),
        [("kr/seoul", "/kr/seoul"), ("/kr/seoul/", "/kr/seoul"), ("", "/"), ("/", "/")],
    )
    def test_group_is_normalised(self, given, expected):
        assert make_measurement(target_group=given).target_group == expected

    def test_round_trips_through_json(self):
        original = make_measurement(details={"nested": {"a": [1, 2, 3]}})
        restored = Measurement.model_validate_json(original.model_dump_json())
        assert restored.details == original.details
        assert restored.ts == original.ts
        assert restored.id == original.id

    def test_unknown_fields_are_ignored_for_forward_compatibility(self):
        # A newer agent sending a field this server does not know must not 400.
        payload = make_measurement().model_dump(mode="json")
        payload["some_future_field"] = {"anything": True}
        restored = Measurement.model_validate(payload)
        assert restored.target == "8.8.8.8"


class TestClassifyStderr:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("curl: (6) Could not resolve host: nope.invalid", ErrorType.DNS_FAILURE),
            ("ping: connect: Network is unreachable", ErrorType.UNREACHABLE),
            ("connect: Connection refused", ErrorType.CONNECT_FAILED),
            ("SSL certificate problem: self signed", ErrorType.TLS_ERROR),
            ("operation timed out", ErrorType.TIMEOUT),
        ],
    )
    def test_maps_known_messages(self, text, expected):
        assert classify_stderr(text) is expected

    def test_falls_back_to_default(self):
        assert classify_stderr("something weird") is ErrorType.TOOL_ERROR
        assert (
            classify_stderr("something weird", default=ErrorType.PARSE_ERROR)
            is ErrorType.PARSE_ERROR
        )
