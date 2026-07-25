"""Path-quality probe built on ``mtr``.

A ping tells you the path is bad.  mtr tells you *which hop* is bad, and this
probe stores every one of them: per-hop IP, loss, and the best/avg/worst/stddev
latency, plus the end-to-end figures.

Two extras worth calling out:

``path_signature``
    A stable hash of the ordered hop list.  Graph it as a discrete value and a
    route flap becomes a visible step change -- far easier to spot than
    eyeballing hop tables.  Silent (``???``) hops are normalised out of the
    signature so ordinary rate-limiting does not create phantom flaps.

``worst_hop``
    The first hop where loss appears, precomputed at ingest time so alerting
    does not have to unnest the hop array.

``path_complete``
    Whether the trace actually arrived.  The target is resolved by the agent
    before mtr runs, and the last hop's address is compared against it -- the
    last row of an mtr table is only the destination if it *is* the
    destination.  When the trace runs out of TTL (``max_hops``) or the target
    black-holes ICMP, the last row is just some transit router, and reporting
    its latency as the target's would be actively misleading.

mtr's ``--json`` (0.87+) is preferred; the classic ``--report`` table is parsed
as a fallback for older builds.

Note: mtr needs raw-socket privileges.  Distribution packages ship it setuid or
with ``cap_net_raw``, which is enough; otherwise run the agent with
``CAP_NET_RAW``.  See the README's "mtr permissions" section.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import socket
from typing import Any, ClassVar

from smokeagent.probes._text import is_ip, to_float
from smokeagent.probes.base import Probe, ProbeTarget, register_probe
from smokecommon.errors import ErrorType, classify_stderr
from smokecommon.models import HopResult, ProbeResult
from smokecommon.process import CommandOutput, run_command

#: ``  3.|-- 10.0.0.1   0.0%   5   1.2  1.3  1.1  1.6  0.2``
_REPORT_ROW_RE = re.compile(
    r"^\s*(?P<hop>\d+)\.\|--\s+(?P<host>\S+)\s+"
    r"(?P<loss>[\d.]+)%\s+(?P<snt>\d+)\s+"
    r"(?P<last>[\d.]+)\s+(?P<avg>[\d.]+)\s+(?P<best>[\d.]+)\s+"
    r"(?P<wrst>[\d.]+)\s+(?P<stdev>[\d.]+)"
)

#: mtr writes unreachable hops as `???` (json) or `???`/`waiting for reply`.
_SILENT_HOSTS = {"???", "?", "waiting", "waitingforreply"}


@register_probe
class MtrProbe(Probe):
    """Full-path measurement: every hop's loss and latency, not just the end."""

    name = "mtr"
    required_binary = "mtr"
    description = "Per-hop path quality via mtr (loss/latency for every router)"

    default_options: ClassVar[dict[str, Any]] = {
        # Packets per hop.
        "count": 5,
        # mtr walks the whole path; give it room.
        "timeout": 60.0,
        "max_hops": 30,
        "packet_size": 64,
        # icmp | udp | tcp
        "protocol": "icmp",
        # Destination port for udp/tcp mode.
        "port": None,
        "ip_version": None,
        "source": None,
        # Reverse-DNS every hop.  Off by default: it adds seconds of latency
        # to the probe itself and the IP is what you actually analyse on.
        "resolve_names": False,
        # Annotate hops with their origin AS (mtr -z).
        "lookup_asn": False,
        # Fail the measurement when end-to-end loss exceeds this percentage.
        "max_loss_pct": 100.0,
    }

    def validate(self) -> None:
        super().validate()
        protocol = str(self.options["protocol"]).lower()
        if protocol not in ("icmp", "udp", "tcp"):
            raise ValueError(f"mtr: protocol must be icmp, udp or tcp, got {protocol!r}")
        if protocol in ("udp", "tcp") and not self.options.get("port"):
            raise ValueError(f"mtr: protocol={protocol} requires `port`")
        if int(self.options["count"]) < 1:
            raise ValueError("mtr: count must be >= 1")

    # -- command construction ---------------------------------------------

    def build_argv(self, address: str, *, json_output: bool = True) -> list[str]:
        opts = self.options
        argv = [
            "mtr",
            "--report-wide",
            "--json" if json_output else "--report",
            "-c",
            str(int(opts["count"])),
            "-m",
            str(int(opts["max_hops"])),
            "-s",
            str(int(opts["packet_size"])),
        ]
        if not opts.get("resolve_names"):
            argv.append("-n")
        if opts.get("lookup_asn"):
            argv.append("-z")

        protocol = str(opts["protocol"]).lower()
        if protocol == "udp":
            argv.append("-u")
        elif protocol == "tcp":
            argv.append("-T")
        if opts.get("port"):
            argv += ["-P", str(int(opts["port"]))]
        if opts.get("ip_version") in (4, 6):
            argv.append(f"-{opts['ip_version']}")
        if opts.get("source"):
            argv += ["-a", str(opts["source"])]

        argv.append(address)
        return argv

    # -- execution ---------------------------------------------------------

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        # Resolve up front so we can tell "the last hop is the destination"
        # apart from "the trace ran out of hops". See build_result().
        try:
            destination_ip = await self._resolve(target.address)
        except OSError as exc:
            return ProbeResult.failure(
                ErrorType.DNS_FAILURE,
                f"cannot resolve {target.address}: {exc}",
                details={"destination": target.address},
            )

        output = await run_command(self.build_argv(target.address), timeout=self.timeout)
        hops = parse_mtr_json(output.stdout)

        if hops is None and not output.timed_out:
            # Older mtr without --json; retry with the classic report table.
            fallback = await run_command(
                self.build_argv(target.address, json_output=False), timeout=self.timeout
            )
            parsed = parse_mtr_report(fallback.stdout)
            if parsed:
                output, hops = fallback, parsed

        return self.build_result(output, hops, target.address, destination_ip)

    async def _resolve(self, host: str) -> str:
        if is_ip(host):
            return host
        family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(
            self.options.get("ip_version"), socket.AF_UNSPEC
        )
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        if not infos:
            raise OSError("no addresses returned")
        return str(infos[0][4][0])

    # -- result assembly ---------------------------------------------------

    def build_result(
        self,
        output: CommandOutput,
        hops: list[HopResult] | None,
        address: str,
        destination_ip: str | None = None,
    ) -> ProbeResult:
        base_details: dict[str, Any] = {
            "command": " ".join(output.argv),
            "destination": address,
            "destination_ip": destination_ip,
            "protocol": str(self.options["protocol"]).lower(),
            "exit_code": output.returncode,
        }

        if output.timed_out:
            return ProbeResult.failure(
                ErrorType.TIMEOUT,
                f"mtr exceeded {self.timeout}s",
                details=base_details,
                duration_ms=output.duration_ms,
            )

        if not hops:
            message = output.combined[:500] or "mtr produced no hops"
            return ProbeResult.failure(
                classify_stderr(message, default=ErrorType.PARSE_ERROR),
                message,
                details=base_details,
                duration_ms=output.duration_ms,
            )

        final = hops[-1]
        path = [hop.ip or hop.host or "???" for hop in hops]
        responding = [hop.ip for hop in hops if hop.ip and is_ip(hop.ip)]
        final_ip = final.ip if final.ip and is_ip(final.ip) else None

        # Did the trace actually arrive?  The last row of an mtr table is only
        # the destination if it *is* the destination -- when the trace runs out
        # of TTL (`-m`) or the target black-holes ICMP, the last row is just
        # some transit router. Treating it as the endpoint would attribute the
        # target's latency to a random intermediate hop, which is exactly the
        # kind of wrong answer this project exists to avoid.
        reached = bool(final_ip and destination_ip and final_ip == destination_ip)
        max_hops = int(self.options["max_hops"])
        truncated = len(hops) >= max_hops and not reached

        # A hop that answers but loses packets while later hops do not is an
        # ICMP-rate-limiting artifact, not a real problem.  The first hop whose
        # loss persists to the end of the path is the interesting one.
        worst = _first_persistent_loss_hop(hops)

        sent = final.sent or int(self.options["count"])
        loss_pct = final.loss_pct if final.loss_pct is not None else 100.0
        received = max(0, round(sent * (100.0 - loss_pct) / 100.0))

        details = {
            **base_details,
            "hop_count": len(hops),
            "path": path,
            "path_signature": path_signature(hops),
            "path_complete": reached,
            "truncated_at_max_hops": truncated,
            "last_responding_ip": final_ip,
            "responding_hops": len(responding),
            "silent_hops": len(hops) - len(responding),
            # Only meaningful when the trace actually reached the target;
            # otherwise these describe whichever router the path stopped at.
            "destination_loss_pct": final.loss_pct if reached else None,
            "destination_avg_ms": final.avg_ms if reached else None,
            "destination_best_ms": final.best_ms if reached else None,
            "destination_worst_ms": final.worst_ms if reached else None,
            "destination_stddev_ms": final.stddev_ms if reached else None,
            "worst_hop": (
                {
                    "hop_no": worst.hop_no,
                    "ip": worst.ip,
                    "host": worst.host,
                    "loss_pct": worst.loss_pct,
                    "avg_ms": worst.avg_ms,
                }
                if worst
                else None
            ),
        }

        result = ProbeResult(
            success=True,
            # mtr reports aggregates, not individual RTTs, so set the
            # representative latency explicitly rather than faking samples.
            latency_ms=final.avg_ms if reached else None,
            packets_sent=sent,
            packets_received=received if reached else 0,
            # The address we aimed at, whether or not we got there -- so
            # per-IP dashboards group by the target, never by a transit hop.
            resolved_ip=destination_ip,
            details=details,
            hops=hops,
            duration_ms=output.duration_ms,
        )

        max_loss = float(self.options["max_loss_pct"])
        if not reached:
            result.success = False
            result.error_type = ErrorType.UNREACHABLE
            if truncated:
                result.error_message = (
                    f"destination {destination_ip} not reached within max_hops="
                    f"{max_hops}; path stopped at {final_ip or '???'}"
                )
            else:
                result.error_message = (
                    f"destination {destination_ip} never replied; path stopped at "
                    f"{final_ip or '???'} after {len(hops)} hops"
                )
        elif loss_pct >= 100.0:
            result.success = False
            result.error_type = ErrorType.PACKET_LOSS
            result.error_message = "100% loss to destination"
        elif loss_pct > max_loss:
            result.success = False
            result.error_type = ErrorType.PACKET_LOSS
            result.error_message = f"{loss_pct}% loss exceeds max_loss_pct={max_loss}"
        return result


# ---------------------------------------------------------------------------
# Parsers (pure functions -- unit-tested against recorded mtr output)
# ---------------------------------------------------------------------------


def parse_mtr_json(text: str) -> list[HopResult] | None:
    """Parse ``mtr --json``.  Returns ``None`` when the text is not mtr JSON."""
    text = text.strip()
    if not text.startswith("{"):
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None

    hubs = payload.get("report", {}).get("hubs")
    if not isinstance(hubs, list):
        return None

    hops: list[HopResult] = []
    for index, hub in enumerate(hubs, start=1):
        host = str(hub.get("host", "")).strip()
        silent = _is_silent(host)
        sent = _as_int(hub.get("Snt"))
        loss = to_float(str(hub.get("Loss%"))) if hub.get("Loss%") is not None else None
        hops.append(
            HopResult(
                hop_no=_as_int(hub.get("count")) or index,
                host=None if silent else host,
                ip=host if (not silent and is_ip(host)) else None,
                loss_pct=loss,
                sent=sent,
                received=(
                    max(0, round(sent * (100.0 - loss) / 100.0))
                    if sent is not None and loss is not None
                    else None
                ),
                last_ms=_hub_float(hub, "Last"),
                avg_ms=_hub_float(hub, "Avg"),
                best_ms=_hub_float(hub, "Best"),
                worst_ms=_hub_float(hub, "Wrst"),
                stddev_ms=_hub_float(hub, "StDev"),
                asn=str(hub["ASN"]) if hub.get("ASN") else None,
            )
        )
    return hops


def parse_mtr_report(text: str) -> list[HopResult]:
    """Parse the classic ``mtr --report`` table."""
    hops: list[HopResult] = []
    for line in text.splitlines():
        match = _REPORT_ROW_RE.match(line)
        if not match:
            continue
        host = match.group("host")
        silent = _is_silent(host)
        sent = int(match.group("snt"))
        loss = float(match.group("loss"))
        # With -z, mtr prefixes the host with `AS12345`.
        asn = None
        if host.startswith("AS") and host[2:].split()[0].isdigit():
            asn, _, host = host.partition(" ")
        hops.append(
            HopResult(
                hop_no=int(match.group("hop")),
                host=None if silent else host,
                ip=host if (not silent and is_ip(host)) else None,
                loss_pct=loss,
                sent=sent,
                received=max(0, round(sent * (100.0 - loss) / 100.0)),
                last_ms=to_float(match.group("last")),
                avg_ms=to_float(match.group("avg")),
                best_ms=to_float(match.group("best")),
                worst_ms=to_float(match.group("wrst")),
                stddev_ms=to_float(match.group("stdev")),
                asn=asn,
            )
        )
    return hops


def path_signature(hops: list[HopResult]) -> str:
    """Stable short hash of the responding hops, for route-change detection.

    Silent hops are excluded: a router that rate-limits ICMP drops in and out
    of the table on its own, and including it would make every other cycle
    look like a route change.
    """
    identifiers = [hop.ip or hop.host for hop in hops if (hop.ip or hop.host)]
    digest = hashlib.sha1("|".join(identifiers).encode("utf-8"))  # noqa: S324 - not security
    return digest.hexdigest()[:12]


def _first_persistent_loss_hop(hops: list[HopResult]) -> HopResult | None:
    """First hop where loss both appears *and* persists downstream.

    Reading an mtr table correctly means separating two things that look
    identical in the loss column:

    * a router that rate-limits ICMP TTL-exceeded replies shows high loss --
      often 100% -- while forwarding traffic perfectly.  The giveaway is that
      *later* hops show less loss than it does;
    * a genuinely lossy link drops the packets themselves, so every hop after
      it inherits at least that much loss.

    So a hop only counts when the minimum loss of everything downstream is at
    least as high as its own (with a little tolerance for sampling noise).
    """
    if not hops:
        return None
    if (hops[-1].loss_pct or 0.0) <= 0:
        return None

    for index, hop in enumerate(hops):
        loss = hop.loss_pct or 0.0
        if loss <= 0:
            continue
        downstream = [h.loss_pct or 0.0 for h in hops[index + 1 :]]
        # The last hop has nothing downstream, so its loss is real by definition.
        if not downstream or min(downstream) >= loss * 0.9:
            return hop
    return hops[-1]


def _is_silent(host: str) -> bool:
    return host.replace(" ", "").lower() in _SILENT_HOSTS or not host


def _hub_float(hub: dict[str, Any], key: str) -> float | None:
    value = hub.get(key)
    if value is None:
        return None
    return to_float(str(value))


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
