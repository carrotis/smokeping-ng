"""mtr probe: per-hop path data, the third 'rich data' requirement."""

from __future__ import annotations

import json

from smokeagent.probes.mtr import (
    MtrProbe,
    parse_mtr_json,
    parse_mtr_report,
    path_signature,
)
from smokecommon.errors import ErrorType

from conftest import make_output

MTR_JSON = json.dumps(
    {
        "report": {
            "mtr": {
                "src": "agent-seoul",
                "dst": "8.8.8.8",
                "tos": 0,
                "tests": 5,
                "psize": "64",
                "bitpattern": "0x00",
            },
            "hubs": [
                {
                    "count": 1,
                    "host": "192.168.1.1",
                    "Loss%": 0.0,
                    "Snt": 5,
                    "Last": 1.2,
                    "Avg": 1.3,
                    "Best": 1.1,
                    "Wrst": 1.6,
                    "StDev": 0.2,
                },
                {
                    "count": 2,
                    "host": "???",
                    "Loss%": 100.0,
                    "Snt": 5,
                    "Last": 0.0,
                    "Avg": 0.0,
                    "Best": 0.0,
                    "Wrst": 0.0,
                    "StDev": 0.0,
                },
                {
                    "count": 3,
                    "host": "10.20.30.40",
                    "Loss%": 20.0,
                    "Snt": 5,
                    "Last": 12.1,
                    "Avg": 12.5,
                    "Best": 11.8,
                    "Wrst": 14.0,
                    "StDev": 0.8,
                },
                {
                    "count": 4,
                    "host": "8.8.8.8",
                    "Loss%": 20.0,
                    "Snt": 5,
                    "Last": 35.0,
                    "Avg": 35.4,
                    "Best": 34.8,
                    "Wrst": 36.9,
                    "StDev": 0.9,
                },
            ],
        }
    }
)

MTR_REPORT_TEXT = """Start: 2026-07-25T12:00:00+0900
HOST: agent-seoul                 Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 192.168.1.1                0.0%     5    1.2   1.3   1.1   1.6   0.2
  2.|-- ???                       100.0%     5    0.0   0.0   0.0   0.0   0.0
  3.|-- 10.20.30.40               20.0%     5   12.1  12.5  11.8  14.0   0.8
  4.|-- 8.8.8.8                   20.0%     5   35.0  35.4  34.8  36.9   0.9
"""

MTR_UNREACHABLE = json.dumps(
    {
        "report": {
            "mtr": {"src": "a", "dst": "192.0.2.1", "tests": 5},
            "hubs": [
                {"count": 1, "host": "192.168.1.1", "Loss%": 0.0, "Snt": 5, "Avg": 1.3},
                {"count": 2, "host": "???", "Loss%": 100.0, "Snt": 5, "Avg": 0.0},
                {"count": 3, "host": "???", "Loss%": 100.0, "Snt": 5, "Avg": 0.0},
            ],
        }
    }
)


class TestJsonParsing:
    def test_every_hop_is_captured(self):
        hops = parse_mtr_json(MTR_JSON)
        assert hops is not None
        assert len(hops) == 4
        assert [h.hop_no for h in hops] == [1, 2, 3, 4]

    def test_hop_metrics(self):
        hops = parse_mtr_json(MTR_JSON)
        assert hops is not None
        third = hops[2]
        assert third.ip == "10.20.30.40"
        assert third.loss_pct == 20.0
        assert third.sent == 5
        assert third.received == 4
        assert third.avg_ms == 12.5
        assert third.best_ms == 11.8
        assert third.worst_ms == 14.0
        assert third.stddev_ms == 0.8

    def test_silent_hops_have_no_ip(self):
        hops = parse_mtr_json(MTR_JSON)
        assert hops is not None
        assert hops[1].ip is None
        assert hops[1].host is None
        assert hops[1].loss_pct == 100.0

    def test_returns_none_for_non_json(self):
        assert parse_mtr_json("HOST: something") is None
        assert parse_mtr_json("{not json") is None


class TestReportParsing:
    def test_text_report_matches_the_json_parse(self):
        json_hops = parse_mtr_json(MTR_JSON)
        text_hops = parse_mtr_report(MTR_REPORT_TEXT)
        assert json_hops is not None

        assert len(text_hops) == len(json_hops)
        for a, b in zip(text_hops, json_hops, strict=True):
            assert a.hop_no == b.hop_no
            assert a.ip == b.ip
            assert a.loss_pct == b.loss_pct
            assert a.avg_ms == b.avg_ms

    def test_ignores_headers(self):
        assert parse_mtr_report("Start: 2026\nHOST: x  Loss%  Snt\n") == []


class TestPathSignature:
    def test_stable_across_calls(self):
        hops = parse_mtr_json(MTR_JSON)
        assert hops is not None
        assert path_signature(hops) == path_signature(hops)

    def test_changes_when_the_route_changes(self):
        hops = parse_mtr_json(MTR_JSON)
        assert hops is not None
        rerouted = [h.model_copy(deep=True) for h in hops]
        rerouted[2].ip = "10.99.99.99"
        assert path_signature(hops) != path_signature(rerouted)

    def test_silent_hops_do_not_cause_phantom_flaps(self):
        # An ICMP-rate-limiting router drops in and out of the table on its
        # own; including it would make every other cycle look like a reroute.
        hops = parse_mtr_json(MTR_JSON)
        assert hops is not None
        without_silent = [h for h in hops if h.ip is not None]
        assert path_signature(hops) == path_signature(without_silent)


class TestResultAssembly:
    def build(self, raw=MTR_JSON, address="8.8.8.8", destination_ip="8.8.8.8", **options):
        probe = MtrProbe({"count": 5, **options})
        return probe.build_result(make_output(raw), parse_mtr_json(raw), address, destination_ip)

    def test_successful_path(self):
        result = self.build()

        assert result.success is True
        assert result.latency_ms == 35.4
        assert result.resolved_ip == "8.8.8.8"
        assert len(result.hops) == 4
        assert result.packets_sent == 5
        assert result.packets_received == 4

    def test_details_carry_the_whole_path(self):
        result = self.build()

        assert result.details["path"] == ["192.168.1.1", "???", "10.20.30.40", "8.8.8.8"]
        assert result.details["hop_count"] == 4
        assert result.details["silent_hops"] == 1
        assert result.details["path_complete"] is True
        assert result.details["destination_ip"] == "8.8.8.8"
        assert result.details["destination_worst_ms"] == 36.9

    def test_worst_hop_finds_where_loss_starts(self):
        # Hop 2 shows 100% loss but later hops recover -- that is ICMP rate
        # limiting, not a problem.  Hop 3's 20% persists to the destination.
        result = self.build()

        assert result.details["worst_hop"]["hop_no"] == 3
        assert result.details["worst_hop"]["ip"] == "10.20.30.40"

    def test_destination_never_replies(self):
        result = self.build(MTR_UNREACHABLE, address="192.0.2.1", destination_ip="192.0.2.1")

        assert result.success is False
        assert result.error_type is ErrorType.UNREACHABLE
        assert result.details["path_complete"] is False
        # The partial path is still stored -- it shows how far traffic got.
        assert len(result.hops) == 3

    def test_max_loss_pct_threshold(self):
        result = self.build(max_loss_pct=10.0)

        assert result.success is False
        assert result.error_type is ErrorType.PACKET_LOSS
        assert "20.0% loss" in (result.error_message or "")

    def test_timeout(self):
        result = MtrProbe().build_result(make_output(timed_out=True), None, "8.8.8.8", "8.8.8.8")
        assert result.success is False
        assert result.error_type is ErrorType.TIMEOUT

    def test_no_hops_parsed(self):
        result = MtrProbe().build_result(
            make_output(stderr="mtr: Failure to start ICMP session: Operation not permitted",
                        returncode=1),
            [],
            "8.8.8.8",
            "8.8.8.8",
        )
        assert result.success is False
        assert result.error_type in (ErrorType.PARSE_ERROR, ErrorType.TOOL_ERROR)


class TestTraceTruncation:
    """The last row of an mtr table is only the destination if it *is* the
    destination. Getting this wrong attributes the target's latency to a
    random transit router."""

    def build(self, destination_ip, max_hops=30):
        probe = MtrProbe({"count": 5, "max_hops": max_hops})
        return probe.build_result(
            make_output(MTR_JSON), parse_mtr_json(MTR_JSON), "1.1.1.1", destination_ip
        )

    def test_a_truncated_trace_is_not_reported_as_complete(self):
        # The trace's last hop is 8.8.8.8, but we were aiming at 1.1.1.1.
        result = self.build(destination_ip="1.1.1.1")

        assert result.success is False
        assert result.error_type is ErrorType.UNREACHABLE
        assert result.details["path_complete"] is False

    def test_latency_is_not_attributed_to_a_transit_hop(self):
        result = self.build(destination_ip="1.1.1.1")

        assert result.latency_ms is None
        assert result.details["destination_avg_ms"] is None
        assert result.details["destination_loss_pct"] is None
        # But the hop that did answer is still recorded, for diagnosis.
        assert result.details["last_responding_ip"] == "8.8.8.8"

    def test_resolved_ip_is_the_target_not_the_last_hop(self):
        # Per-IP dashboards must group by what we aimed at.
        result = self.build(destination_ip="1.1.1.1")
        assert result.resolved_ip == "1.1.1.1"

    def test_hitting_max_hops_is_called_out(self):
        result = self.build(destination_ip="1.1.1.1", max_hops=4)

        assert result.details["truncated_at_max_hops"] is True
        assert "max_hops=4" in (result.error_message or "")

    def test_a_short_dead_path_is_not_blamed_on_max_hops(self):
        result = self.build(destination_ip="1.1.1.1", max_hops=30)

        assert result.details["truncated_at_max_hops"] is False
        assert "never replied" in (result.error_message or "")

    def test_the_full_hop_table_is_kept_either_way(self):
        result = self.build(destination_ip="1.1.1.1")
        assert len(result.hops) == 4
        assert result.details["path_signature"]


class TestCommandConstruction:
    def test_json_mode_by_default(self):
        argv = MtrProbe({"count": 7}).build_argv("8.8.8.8")
        assert "--json" in argv
        assert argv[argv.index("-c") + 1] == "7"
        assert argv[-1] == "8.8.8.8"

    def test_numeric_output_unless_names_requested(self):
        assert "-n" in MtrProbe().build_argv("8.8.8.8")
        assert "-n" not in MtrProbe({"resolve_names": True}).build_argv("8.8.8.8")

    def test_tcp_mode_needs_a_port(self):
        argv = MtrProbe({"protocol": "tcp", "port": 443}).build_argv("example.com")
        assert "-T" in argv
        assert argv[argv.index("-P") + 1] == "443"

    def test_report_fallback_mode(self):
        argv = MtrProbe().build_argv("8.8.8.8", json_output=False)
        assert "--report" in argv
        assert "--json" not in argv


class TestValidation:
    def test_tcp_without_port_is_rejected(self):
        import pytest

        with pytest.raises(ValueError, match="requires `port`"):
            MtrProbe({"protocol": "tcp"}).validate()

    def test_unknown_protocol_is_rejected(self):
        import pytest

        with pytest.raises(ValueError, match="icmp, udp or tcp"):
            MtrProbe({"protocol": "sctp"}).validate()
