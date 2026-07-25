"""ping probe: command construction and output parsing.

The output samples are verbatim from the real binaries, including the Korean
Windows sample -- ``ping.exe`` is localised at the OS level and ignores
``LC_ALL``, so the parser has to survive it.
"""

from __future__ import annotations

import pytest

from smokeagent.probes.base import ProbeTarget
from smokeagent.probes.ping import PingProbe
from smokecommon.errors import ErrorType

from conftest import make_output

LINUX_OK = """PING google.com (142.250.196.110) 56(84) bytes of data.
64 bytes from 142.250.196.110: icmp_seq=1 ttl=118 time=35.2 ms
64 bytes from 142.250.196.110: icmp_seq=2 ttl=118 time=34.9 ms
64 bytes from 142.250.196.110: icmp_seq=3 ttl=118 time=35.1 ms

--- google.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 34.912/35.067/35.211/0.122 ms
"""

LINUX_PARTIAL_LOSS = """PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=1.20 ms
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=1.31 ms

--- 10.0.0.1 ping statistics ---
4 packets transmitted, 2 received, 50% packet loss, time 3050ms
rtt min/avg/max/mdev = 1.201/1.255/1.310/0.054 ms
"""

LINUX_TOTAL_LOSS = """PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.

--- 192.0.2.1 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4098ms
"""

LINUX_DNS_FAILURE = "ping: nope.invalid: Name or service not known\n"

WINDOWS_OK = """
Pinging google.com [142.250.196.110] with 32 bytes of data:
Reply from 142.250.196.110: bytes=32 time=35ms TTL=115
Reply from 142.250.196.110: bytes=32 time=34ms TTL=115
Request timed out.
Reply from 142.250.196.110: bytes=32 time<1ms TTL=115

Ping statistics for 142.250.196.110:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 34ms, Maximum = 35ms, Average = 34ms
"""

# Korean Windows 11.  Note the summary line at the bottom: three "ms" values on
# one line, none of them a real sample.
WINDOWS_KOREAN = """
8.8.8.8에 대한 Ping 8.8.8.8 32바이트 데이터 사용:
8.8.8.8의 응답: 바이트=32 시간=38ms TTL=115
8.8.8.8의 응답: 바이트=32 시간=37ms TTL=115

8.8.8.8에 대한 Ping 통계:
    패킷: 보냄 = 2, 받음 = 2, 손실 = 0 (0% 손실),
왕복 시간(밀리초):
    최소 = 37ms, 최대 = 38ms, 평균 = 37ms
"""


class TestParsing:
    def test_linux_success(self):
        probe = PingProbe({"count": 3})
        result = probe.parse(make_output(LINUX_OK), expected_count=3)

        assert result.success is True
        assert result.rtts_ms == [35.2, 34.9, 35.1]
        assert result.packets_sent == 3
        assert result.packets_received == 3
        assert result.loss_pct == 0.0
        assert result.resolved_ip == "142.250.196.110"
        assert result.details["ttl"] == 118

    def test_linux_ignores_the_rtt_summary_line(self):
        # `rtt min/avg/max/mdev = 34.912/... ms` must not become a sample.
        result = PingProbe({"count": 3}).parse(make_output(LINUX_OK), expected_count=3)
        assert len(result.rtts_ms) == 3

    def test_partial_loss_is_still_a_success(self):
        # This is exactly the signal SmokePing exists to show, so it must be
        # recorded as a measurement rather than thrown away as an error.
        probe = PingProbe({"count": 4})
        result = probe.parse(make_output(LINUX_PARTIAL_LOSS), expected_count=4)

        assert result.success is True
        assert result.rtts_ms == [1.20, 1.31]
        assert result.packets_sent == 4
        assert result.packets_received == 2
        assert result.loss_pct == 50.0

    def test_total_loss_is_a_failure_with_packet_loss_type(self):
        probe = PingProbe({"count": 5})
        result = probe.parse(make_output(LINUX_TOTAL_LOSS, returncode=1), expected_count=5)

        assert result.success is False
        assert result.error_type is ErrorType.PACKET_LOSS
        assert result.packets_sent == 5
        assert result.packets_received == 0

    def test_dns_failure_is_classified(self):
        probe = PingProbe({"count": 3})
        result = probe.parse(
            make_output(stderr=LINUX_DNS_FAILURE, returncode=2), expected_count=3
        )
        assert result.success is False
        assert result.error_type is ErrorType.DNS_FAILURE

    def test_timeout_keeps_partial_samples(self):
        probe = PingProbe({"count": 3})
        result = probe.parse(
            make_output(LINUX_PARTIAL_LOSS, timed_out=True), expected_count=4
        )
        assert result.success is False
        assert result.error_type is ErrorType.TIMEOUT
        assert result.rtts_ms == [1.20, 1.31]

    def test_windows_english(self):
        probe = PingProbe({"count": 4})
        result = probe.parse(make_output(WINDOWS_OK), expected_count=4)

        assert result.success is True
        # `time<1ms` is a real sample and must be captured as 1.0.
        assert result.rtts_ms == [35.0, 34.0, 1.0]
        assert result.resolved_ip == "142.250.196.110"
        # Windows has no "N packets transmitted" line, so counts come from the
        # request count and the number of replies we parsed.
        assert result.packets_sent == 4
        assert result.packets_received == 3

    def test_windows_korean_locale(self):
        probe = PingProbe({"count": 2})
        result = probe.parse(make_output(WINDOWS_KOREAN), expected_count=2)

        assert result.success is True
        assert result.rtts_ms == [38.0, 37.0]
        assert result.packets_received == 2
        assert result.resolved_ip == "8.8.8.8"

    def test_summary_line_with_multiple_ms_values_is_skipped(self):
        # Direct check of the "exactly one ms value per reply line" rule.
        assert PingProbe._parse_rtts("    Minimum = 34ms, Maximum = 35ms, Average = 34ms") == []
        assert PingProbe._parse_rtts("Reply from 1.1.1.1: bytes=32 time=9ms TTL=55") == [9.0]


class TestCommandConstruction:
    def test_linux_argv(self, monkeypatch):
        monkeypatch.setattr("smokeagent.probes.ping.IS_WINDOWS", False)
        argv = PingProbe({"count": 7, "interval": 0.5, "packet_size": 100}).build_argv("1.1.1.1")

        assert argv[0] == "ping"
        assert "-c" in argv and argv[argv.index("-c") + 1] == "7"
        assert "-i" in argv and argv[argv.index("-i") + 1] == "0.5"
        assert "-s" in argv and argv[argv.index("-s") + 1] == "100"
        assert argv[-1] == "1.1.1.1"

    def test_windows_argv_uses_n_not_c(self, monkeypatch):
        monkeypatch.setattr("smokeagent.probes.ping.IS_WINDOWS", True)
        argv = PingProbe({"count": 4, "packet_timeout": 2.0}).build_argv("1.1.1.1")

        assert "-n" in argv and argv[argv.index("-n") + 1] == "4"
        # Windows expresses the per-packet wait in milliseconds.
        assert "-w" in argv and argv[argv.index("-w") + 1] == "2000"
        assert "-c" not in argv

    def test_ip_version_flag(self, monkeypatch):
        monkeypatch.setattr("smokeagent.probes.ping.IS_WINDOWS", False)
        assert "-6" in PingProbe({"ip_version": 6}).build_argv("example.com")


class TestValidation:
    def test_rejects_timeout_shorter_than_the_cycle(self):
        # 20 pings at 1s cannot finish inside a 5s timeout; catching this at
        # startup beats an endless stream of timeout measurements.
        probe = PingProbe({"count": 20, "interval": 1.0, "timeout": 5.0})
        with pytest.raises(ValueError, match="too short"):
            probe.validate()

    def test_rejects_zero_count(self):
        with pytest.raises(ValueError, match="count"):
            PingProbe({"count": 0}).validate()

    def test_accepts_a_sane_config(self):
        PingProbe({"count": 5, "interval": 0.3, "timeout": 10.0}).validate()


class TestRunWrapper:
    async def test_missing_binary_becomes_tool_missing(self, monkeypatch):
        from smokecommon.process import ToolMissingError

        async def boom(*args, **kwargs):
            raise ToolMissingError("ping")

        monkeypatch.setattr("smokeagent.probes.ping.run_command", boom)
        result = await PingProbe().run(ProbeTarget(name="t", address="1.1.1.1"))

        assert result.success is False
        assert result.error_type is ErrorType.TOOL_MISSING
        assert result.duration_ms is not None

    async def test_unexpected_exception_is_contained(self, monkeypatch):
        async def boom(*args, **kwargs):
            raise RuntimeError("kaboom")

        monkeypatch.setattr("smokeagent.probes.ping.run_command", boom)
        result = await PingProbe().run(ProbeTarget(name="t", address="1.1.1.1"))

        assert result.success is False
        assert result.error_type is ErrorType.INTERNAL
        assert "kaboom" in (result.error_message or "")
