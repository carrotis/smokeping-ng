"""ICMP echo probe built on the system ``ping`` binary.

Why shell out instead of using raw sockets?  Raw ICMP needs CAP_NET_RAW (or
Administrator on Windows); the system ``ping`` is already setuid/capability-
granted everywhere, so the agent runs unprivileged.  Use the ``fping`` probe
when you need to measure many targets efficiently.

Output parsing is intentionally locale-tolerant.  ``LC_ALL=C`` handles Linux,
but Windows' ``ping.exe`` is localised at the OS level and ignores it entirely
-- on a Korean Windows host the reply line reads ``바이트=32 시간=35ms TTL=115``.
So we key off the parts that never get translated: the ``=``/``<`` separator,
the digits, and the literal ``ms``.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from smokeagent.probes._text import find_bracketed_ip, find_ip, to_float
from smokeagent.probes.base import Probe, ProbeTarget, register_probe
from smokecommon.errors import ErrorType, classify_stderr
from smokecommon.models import ProbeResult
from smokecommon.process import IS_WINDOWS, CommandOutput, run_command

#: ``time=12.3 ms``, ``time<1ms``, ``시간=35ms`` -- everything but the number
#: and the ``ms`` unit varies by platform and locale.
_RTT_RE = re.compile(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms", re.IGNORECASE)

#: Linux/BSD summary line, the authoritative loss figure when present.
_SUMMARY_RE = re.compile(
    r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received", re.IGNORECASE
)

#: Lines that carry aggregate timings and would otherwise look like a reply.
_SUMMARY_MARKERS = ("min/avg/max", "round-trip", "rtt ", "---")


@register_probe
class PingProbe(Probe):
    """Sequential ICMP echo against a single host."""

    name = "ping"
    required_binary = "ping"
    description = "ICMP echo via the system ping binary (one target per cycle)"

    default_options: ClassVar[dict[str, Any]] = {
        # SmokePing's `pings` -- how many echoes make up one smoke band.
        "count": 5,
        # Seconds between echoes.  Values below 0.2 need root on Linux.
        "interval": 0.3,
        # Overall deadline for the whole cycle.
        "timeout": 10.0,
        # Per-packet wait, seconds.  None -> let ping decide.
        "packet_timeout": 2.0,
        "packet_size": 56,
        # 4, 6, or None for "whatever the resolver prefers".
        "ip_version": None,
        # Source address/interface, e.g. "eth1" or "10.0.0.5".
        "source": None,
    }

    def validate(self) -> None:
        super().validate()
        count = int(self.options["count"])
        interval = float(self.options["interval"])
        if count < 1:
            raise ValueError("ping: count must be >= 1")
        if interval < 0:
            raise ValueError("ping: interval must be >= 0")
        needed = count * interval
        if needed >= self.timeout:
            raise ValueError(
                f"ping: timeout ({self.timeout}s) is too short for "
                f"count={count} x interval={interval}s (needs > {needed:.1f}s)"
            )
        if self.options["ip_version"] not in (None, 4, 6):
            raise ValueError("ping: ip_version must be 4, 6 or null")

    # -- command construction ---------------------------------------------

    def build_argv(self, address: str) -> list[str]:
        count = int(self.options["count"])
        interval = float(self.options["interval"])
        size = int(self.options["packet_size"])
        packet_timeout = self.options.get("packet_timeout")
        family = self.options.get("ip_version")
        source = self.options.get("source")

        argv = ["ping"]
        if IS_WINDOWS:
            argv += ["-n", str(count), "-l", str(size)]
            if packet_timeout:
                argv += ["-w", str(int(float(packet_timeout) * 1000))]
            if family in (4, 6):
                argv.append(f"-{family}")
            if source:
                argv += ["-S", str(source)]
            # Windows ping has no inter-packet interval knob; it is fixed at 1s.
        else:
            argv += ["-n", "-c", str(count), "-i", str(interval), "-s", str(size)]
            if packet_timeout:
                argv += ["-W", str(int(float(packet_timeout)))]
            # Hard deadline so a black-holing target cannot outlive our timeout.
            argv += ["-w", str(max(1, int(self.timeout)))]
            if family in (4, 6):
                argv.append(f"-{family}")
            if source:
                argv += ["-I", str(source)]
        argv.append(address)
        return argv

    # -- execution ---------------------------------------------------------

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        argv = self.build_argv(target.address)
        # Give the subprocess a hair more than our own deadline so that a
        # ping that self-terminates on `-w` reports partial results instead of
        # being killed with nothing to show.
        output = await run_command(argv, timeout=self.timeout + 1.0)
        return self.parse(output, expected_count=int(self.options["count"]))

    # -- parsing (pure, unit-tested without a network) ---------------------

    def parse(self, output: CommandOutput, expected_count: int) -> ProbeResult:
        text = output.stdout or output.stderr
        resolved_ip = self._resolved_ip(text)
        rtts = self._parse_rtts(text)
        sent, received = self._parse_counts(text, expected_count, len(rtts))

        details: dict[str, Any] = {
            "command": " ".join(output.argv),
            "exit_code": output.returncode,
            "ttl": self._parse_ttl(text),
        }
        if output.stderr.strip():
            details["stderr"] = output.stderr.strip()[:1000]

        if output.timed_out:
            return ProbeResult(
                success=False,
                error_type=ErrorType.TIMEOUT,
                error_message=f"ping exceeded {self.timeout}s",
                rtts_ms=rtts,
                packets_sent=sent,
                packets_received=received,
                resolved_ip=resolved_ip,
                details=details,
                duration_ms=output.duration_ms,
            )

        if not rtts:
            # No replies at all.  Distinguish "the tool broke" (bad hostname,
            # permissions) from "the network ate every packet": the former has
            # no transmitted count, the latter does.
            error_type = (
                ErrorType.PACKET_LOSS if sent > 0 and resolved_ip else classify_stderr(
                    output.combined, default=ErrorType.UNREACHABLE
                )
            )
            message = _first_meaningful_line(output) or "no ICMP replies received"
            return ProbeResult(
                success=False,
                error_type=error_type,
                error_message=message,
                packets_sent=sent,
                packets_received=0,
                resolved_ip=resolved_ip,
                details=details,
                duration_ms=output.duration_ms,
            )

        # Partial loss is still a successful measurement -- that is precisely
        # the signal SmokePing exists to show.
        return ProbeResult(
            success=True,
            rtts_ms=rtts,
            packets_sent=sent,
            packets_received=received,
            resolved_ip=resolved_ip,
            details=details,
            duration_ms=output.duration_ms,
        )

    @staticmethod
    def _parse_rtts(text: str) -> list[float]:
        """Pull one RTT per reply line.

        The locale-independent trick: a reply line contains exactly one
        ``ms`` value, while a summary line contains several.  Windows'
        ``Minimum = 34ms, Maximum = 35ms, Average = 34ms`` is stripped out by
        that rule alone -- which matters because on a Korean or German Windows
        host that line reads nothing like "Minimum" and no keyword filter
        could catch it.
        """
        rtts: list[float] = []
        for line in text.splitlines():
            lowered = line.lower()
            if any(marker in lowered for marker in _SUMMARY_MARKERS):
                continue
            matches = _RTT_RE.findall(line)
            if len(matches) != 1:
                continue
            value = to_float(matches[0])
            if value is not None:
                rtts.append(value)
        return rtts

    @staticmethod
    def _parse_counts(text: str, expected: int, reply_count: int) -> tuple[int, int]:
        match = _SUMMARY_RE.search(text)
        if match:
            return int(match.group(1)), int(match.group(2))
        # Windows (and localised output): trust our own request count and the
        # number of reply lines we managed to parse.
        return expected, min(reply_count, expected)

    @staticmethod
    def _parse_ttl(text: str) -> int | None:
        match = re.search(r"ttl[=\s]+(\d+)", text, re.IGNORECASE)
        return int(match.group(1)) if match else None

    @staticmethod
    def _resolved_ip(text: str) -> str | None:
        # The header line carries the resolved address in brackets/parens.
        head = "\n".join(text.splitlines()[:2])
        return find_bracketed_ip(head) or find_ip(text)


def _first_meaningful_line(output: CommandOutput) -> str | None:
    for stream in (output.stderr, output.stdout):
        for line in stream.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("PING"):
                return stripped[:500]
    return None
