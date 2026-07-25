"""Parallel ICMP probe using ``fping``.

``fping`` exists because sequential ``ping`` does not scale: one process per
target means hundreds of processes and a thundering herd of context switches.
This probe therefore implements the batch interface -- the scheduler hands it
every fping target that shares a cycle, and a single ``fping`` process
round-robins ICMP across all of them.

Hostnames are resolved by the agent *before* invoking fping, and IPs are
passed on the command line.  Two reasons:

1. ``resolved_ip`` becomes exact.  With hostnames, fping echoes back the name
   you gave it and you never learn which CDN edge answered.
2. The output-to-target mapping is unambiguous even when several configured
   targets share an address.
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any, ClassVar

from smokeagent.probes._text import to_float
from smokeagent.probes.base import Probe, ProbeTarget, register_probe
from smokecommon.errors import ErrorType, classify_stderr
from smokecommon.logging import get_logger
from smokecommon.models import ProbeResult
from smokecommon.process import CommandOutput, run_command

log = get_logger(__name__)

#: ``8.8.8.8 : 12.3 11.9 - 12.1`` (fping -C)
_LINE_RE = re.compile(r"^\s*(\S+)\s*:\s*(.*)$")


@register_probe
class FpingProbe(Probe):
    """ICMP echo across many targets from a single ``fping`` process."""

    name = "fping"
    required_binary = "fping"
    supports_batch = True
    description = "Parallel ICMP echo via fping (batches all targets into one process)"

    default_options: ClassVar[dict[str, Any]] = {
        "count": 5,
        # Milliseconds between rounds; fping's -p.
        "interval": 0.3,
        "timeout": 15.0,
        # Per-packet wait, seconds (fping -t).
        "packet_timeout": 2.0,
        "packet_size": 56,
        "ip_version": None,
        "source": None,
        # Resolve names to addresses in-agent (recommended -- see module docs).
        "resolve": True,
        # Upper bound on targets per fping process; beyond this the scheduler
        # splits into several invocations.
        "max_batch": 200,
    }

    def validate(self) -> None:
        super().validate()
        if int(self.options["count"]) < 1:
            raise ValueError("fping: count must be >= 1")
        needed = int(self.options["count"]) * float(self.options["interval"])
        if needed >= self.timeout:
            raise ValueError(
                f"fping: timeout ({self.timeout}s) too short for "
                f"count x interval ({needed:.1f}s)"
            )

    # -- command construction ---------------------------------------------

    def build_argv(self, addresses: list[str]) -> list[str]:
        opts = self.options
        argv = [
            "fping",
            "-C",
            str(int(opts["count"])),
            "-q",
            "-p",
            str(int(float(opts["interval"]) * 1000)),
            "-t",
            str(int(float(opts["packet_timeout"]) * 1000)),
            "-b",
            str(int(opts["packet_size"])),
            # One packet per round, no exponential backoff: we want a clean
            # sample of the link, not fping's reachability heuristics.
            "-r",
            "0",
            "-B",
            "1",
        ]
        if opts.get("ip_version") in (4, 6):
            argv.append(f"-{opts['ip_version']}")
        if opts.get("source"):
            argv += ["-S", str(opts["source"])]
        argv += addresses
        return argv

    # -- execution ---------------------------------------------------------

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        results = await self.probe_many([target])
        return results[target.name]

    async def probe_many(self, targets: list[ProbeTarget]) -> dict[str, ProbeResult]:
        if not targets:
            return {}

        # address -> the configured targets that map onto it
        address_map: dict[str, list[ProbeTarget]] = {}
        failures: dict[str, ProbeResult] = {}

        for target in targets:
            if self.options.get("resolve"):
                try:
                    address = await self._resolve(target.address)
                except OSError as exc:
                    failures[target.name] = ProbeResult.failure(
                        ErrorType.DNS_FAILURE,
                        f"cannot resolve {target.address}: {exc}",
                    )
                    continue
            else:
                address = target.address
            address_map.setdefault(address, []).append(target)

        if not address_map:
            return failures

        argv = self.build_argv(sorted(address_map))
        output = await run_command(argv, timeout=self.timeout + 2.0)
        parsed = self.parse_batch(output, list(address_map))

        results: dict[str, ProbeResult] = dict(failures)
        for address, targets_for_address in address_map.items():
            result = parsed.get(address) or self._missing_result(output, address)
            for target in targets_for_address:
                # Each configured target gets its own copy; the scheduler is
                # free to mutate them independently.
                results[target.name] = result.model_copy(deep=True)
        return results

    async def _resolve(self, host: str) -> str:
        family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(
            self.options.get("ip_version"), socket.AF_UNSPEC
        )
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        if not infos:
            raise OSError(f"no addresses returned for {host}")
        return infos[0][4][0]

    # -- parsing -----------------------------------------------------------

    def parse_batch(
        self, output: CommandOutput, addresses: list[str]
    ) -> dict[str, ProbeResult]:
        """Turn one fping run into per-address results.

        fping writes the ``-C`` table to stderr, but builds and versions
        differ; scan both streams.
        """
        wanted = set(addresses)
        results: dict[str, ProbeResult] = {}
        expected_count = int(self.options["count"])

        for line in f"{output.stderr}\n{output.stdout}".splitlines():
            match = _LINE_RE.match(line)
            if not match:
                continue
            address = match.group(1)
            if address not in wanted or address in results:
                continue

            # fping writes "-" for a lost packet in the -C table.
            rtts = [
                value
                for sample in match.group(2).split()
                if sample != "-" and (value := to_float(sample)) is not None
            ]
            details: dict[str, Any] = {
                "command": " ".join(output.argv),
                "exit_code": output.returncode,
                "batch_size": len(addresses),
                "raw_samples": match.group(2).strip(),
            }

            if rtts:
                results[address] = ProbeResult(
                    success=True,
                    rtts_ms=rtts,
                    packets_sent=expected_count,
                    packets_received=len(rtts),
                    resolved_ip=address,
                    details=details,
                    duration_ms=output.duration_ms,
                )
            else:
                results[address] = ProbeResult(
                    success=False,
                    error_type=ErrorType.PACKET_LOSS,
                    error_message="100% packet loss",
                    packets_sent=expected_count,
                    packets_received=0,
                    resolved_ip=address,
                    details=details,
                    duration_ms=output.duration_ms,
                )
        return results

    def _missing_result(self, output: CommandOutput, address: str) -> ProbeResult:
        """fping said nothing about this address -- decide why."""
        if output.timed_out:
            return ProbeResult.failure(
                ErrorType.TIMEOUT,
                f"fping exceeded {self.timeout}s",
                packets_sent=int(self.options["count"]),
                duration_ms=output.duration_ms,
                resolved_ip=address,
            )
        return ProbeResult.failure(
            classify_stderr(output.combined, default=ErrorType.PARSE_ERROR),
            f"no fping output for {address}: {output.combined[:400] or 'empty output'}",
            packets_sent=int(self.options["count"]),
            duration_ms=output.duration_ms,
            resolved_ip=address,
        )
