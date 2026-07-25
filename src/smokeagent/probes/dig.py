"""DNS probe built on ``dig``.

Beyond the query time, this records everything you need to answer "why was
DNS slow / wrong just now":

* ``SERVER:`` -- the resolver IP that actually answered.  With anycast (8.8.8.8,
  1.1.1.1) the same configured address is dozens of different machines; this is
  the only way to see that one PoP is degraded.
* the full answer section, plus the extracted A/AAAA list and the CNAME chain,
  so you can catch a target silently repointed to a different CDN.
* the header flags -- notably ``aa`` (authoritative) and ``tc`` (truncated) --
  and the response status (NOERROR/NXDOMAIN/SERVFAIL/...).

All ``count`` queries are issued by a single ``dig`` process (dig accepts
several queries per invocation), which gives a real latency distribution for
the smoke graph at the cost of one fork.

One fidelity caveat: BIND's ``dig`` reports ``Query time`` in whole
milliseconds, so a sub-millisecond answer (a local cache, a resolver on the
same host) is genuinely reported as ``0``. That is dig's resolution, not a
parsing bug. Use the ``nc`` probe against port 53 if you need sub-millisecond
timing of a nearby resolver.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from smokeagent.probes._text import find_ip, is_ip, strip_trailing_dot, to_float
from smokeagent.probes.base import Probe, ProbeTarget, register_probe
from smokecommon.errors import ErrorType, classify_stderr
from smokecommon.models import ProbeResult
from smokecommon.process import CommandOutput, run_command

_HEADER_RE = re.compile(
    r";;\s*->>HEADER<<-\s*opcode:\s*(?P<opcode>\w+),\s*status:\s*(?P<status>\w+),"
    r"\s*id:\s*(?P<id>\d+)",
    re.IGNORECASE,
)
_FLAGS_RE = re.compile(
    r";;\s*flags:\s*(?P<flags>[a-z ]*);\s*QUERY:\s*(?P<qd>\d+),\s*ANSWER:\s*(?P<an>\d+),"
    r"\s*AUTHORITY:\s*(?P<ns>\d+),\s*ADDITIONAL:\s*(?P<ar>\d+)",
    re.IGNORECASE,
)
_QUERY_TIME_RE = re.compile(r";;\s*Query time:\s*(\d+(?:\.\d+)?)\s*(msec|msecs|ms)", re.IGNORECASE)
_SERVER_RE = re.compile(r";;\s*SERVER:\s*(?P<addr>[^#\s]+)#(?P<port>\d+)(?:\((?P<disp>[^)]*)\))?")
_TRANSPORT_RE = re.compile(
    r";;\s*SERVER:.*\((UDP|TCP|TLS|HTTPS)\)\s*$", re.IGNORECASE | re.MULTILINE
)
_MSG_SIZE_RE = re.compile(r";;\s*MSG SIZE\s+rcvd:\s*(\d+)", re.IGNORECASE)
_BLOCK_MARKER = ";; ->>HEADER<<-"


@register_probe
class DigProbe(Probe):
    """Resolve a name and record the full DNS answer, not just the timing."""

    name = "dig"
    required_binary = "dig"
    description = "DNS lookup via dig, capturing responding server, records and flags"

    default_options: ClassVar[dict[str, Any]] = {
        # Queries per cycle -- issued by one dig process.
        "count": 3,
        "timeout": 10.0,
        # Per-query wait in seconds (dig +time).
        "query_timeout": 2.0,
        "record_type": "A",
        # Resolver to query.  None -> whatever /etc/resolv.conf says.
        "resolver": None,
        "port": 53,
        "use_tcp": False,
        "dnssec": False,
        # Send RD.  Set false when probing an authoritative server directly.
        "recurse": True,
        # Response codes considered healthy.
        "expect_status": ["NOERROR"],
        # Fail the measurement if fewer than this many answer records come back.
        "expect_min_answers": 1,
        # Optional: fail unless one of these IPs appears in the answer.
        "expect_ips": None,
    }

    def validate(self) -> None:
        super().validate()
        if int(self.options["count"]) < 1:
            raise ValueError("dig: count must be >= 1")
        if not isinstance(self.options["expect_status"], list):
            raise ValueError("dig: expect_status must be a list, e.g. [NOERROR]")

    # -- command construction ---------------------------------------------

    def build_argv(self, name: str) -> list[str]:
        opts = self.options
        argv = ["dig"]
        if opts.get("resolver"):
            argv.append(f"@{opts['resolver']}")
        argv += ["-p", str(int(opts["port"]))]

        flags = [
            "+tries=1",
            f"+time={int(float(opts['query_timeout']))}",
            "+nocmd",
        ]
        flags.append("+tcp" if opts.get("use_tcp") else "+notcp")
        flags.append("+dnssec" if opts.get("dnssec") else "+nodnssec")
        flags.append("+recurse" if opts.get("recurse", True) else "+norecurse")

        # dig accepts several queries in one run; repeat the tuple `count` times.
        record_type = str(opts["record_type"]).upper()
        for _ in range(int(opts["count"])):
            argv += [name, record_type, *flags]
        return argv

    # -- execution ---------------------------------------------------------

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        argv = self.build_argv(target.address)
        output = await run_command(argv, timeout=self.timeout)
        return self.parse(output, target.address)

    # -- parsing -----------------------------------------------------------

    def parse(self, output: CommandOutput, query_name: str) -> ProbeResult:
        expected = int(self.options["count"])
        record_type = str(self.options["record_type"]).upper()

        base_details: dict[str, Any] = {
            "command": " ".join(output.argv),
            "query_name": query_name,
            "query_type": record_type,
            "resolver_configured": self.options.get("resolver"),
            "exit_code": output.returncode,
        }

        if output.timed_out:
            return ProbeResult.failure(
                ErrorType.TIMEOUT,
                f"dig exceeded {self.timeout}s",
                packets_sent=expected,
                details=base_details,
                duration_ms=output.duration_ms,
            )

        blocks = _split_blocks(output.stdout)
        if not blocks:
            message = output.combined[:500] or "dig produced no parsable answer"
            return ProbeResult.failure(
                classify_stderr(message, default=ErrorType.PARSE_ERROR),
                message,
                packets_sent=expected,
                details=base_details,
                duration_ms=output.duration_ms,
            )

        parsed = [_parse_block(block) for block in blocks]
        rtts = [b["query_time_ms"] for b in parsed if b.get("query_time_ms") is not None]

        # The last block is the authoritative view of "what did we learn";
        # earlier blocks contribute their timings and are kept in `attempts`.
        final = parsed[-1]
        answers = final.get("answers", [])
        answer_ips = [
            record["data"]
            for record in answers
            if record["type"] in ("A", "AAAA") and is_ip(record["data"])
        ]
        cname_chain = [record["data"] for record in answers if record["type"] == "CNAME"]
        ttls = [record["ttl"] for record in answers if record.get("ttl") is not None]

        details = {
            **base_details,
            "status": final.get("status"),
            "flags": final.get("flags", []),
            "authoritative": "aa" in final.get("flags", []),
            "recursion_desired": "rd" in final.get("flags", []),
            "recursion_available": "ra" in final.get("flags", []),
            "truncated": "tc" in final.get("flags", []),
            "authenticated_data": "ad" in final.get("flags", []),
            "server_ip": final.get("server_ip"),
            "server_port": final.get("server_port"),
            "transport": final.get("transport"),
            "answer_count": final.get("answer_count"),
            "authority_count": final.get("authority_count"),
            "additional_count": final.get("additional_count"),
            "answers": answers,
            "answer_ips": answer_ips,
            "cname_chain": cname_chain,
            "ttl_min": min(ttls) if ttls else None,
            "msg_size_bytes": final.get("msg_size_bytes"),
            # Per-query view so a single slow retry is visible.
            "attempts": [
                {
                    "query_time_ms": b.get("query_time_ms"),
                    "status": b.get("status"),
                    "server_ip": b.get("server_ip"),
                }
                for b in parsed
            ],
        }

        server_ip = final.get("server_ip")
        result = ProbeResult(
            success=True,
            rtts_ms=rtts,
            packets_sent=expected,
            packets_received=len(parsed),
            # For DNS, "the IP we actually talked to" is the resolver that
            # answered -- that is what you group by when hunting a bad PoP.
            resolved_ip=server_ip,
            details=details,
            duration_ms=output.duration_ms,
        )

        failure = self._check_expectations(final, answers, answer_ips)
        if failure is not None:
            result.success = False
            result.error_type, result.error_message = failure
        return result

    def _check_expectations(
        self,
        final: dict[str, Any],
        answers: list[dict[str, Any]],
        answer_ips: list[str],
    ) -> tuple[ErrorType, str] | None:
        expected_statuses = {str(s).upper() for s in self.options["expect_status"]}
        status = (final.get("status") or "").upper()
        if status and status not in expected_statuses:
            return (
                ErrorType.BAD_RESPONSE,
                f"DNS status {status}, expected one of {sorted(expected_statuses)}",
            )

        minimum = int(self.options["expect_min_answers"])
        if len(answers) < minimum:
            return (
                ErrorType.BAD_RESPONSE,
                f"{len(answers)} answer record(s), expected at least {minimum}",
            )

        expect_ips = self.options.get("expect_ips")
        if expect_ips:
            wanted = {str(ip) for ip in expect_ips}
            if not wanted.intersection(answer_ips):
                return (
                    ErrorType.BAD_RESPONSE,
                    f"answer {answer_ips} contains none of the expected {sorted(wanted)}",
                )
        return None


def _split_blocks(text: str) -> list[str]:
    """Split a multi-query dig run into one chunk per response."""
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if _BLOCK_MARKER in line]
    if not starts:
        return []
    bounds = [*starts, len(lines)]
    return ["\n".join(lines[bounds[i] : bounds[i + 1]]) for i in range(len(starts))]


def _parse_block(block: str) -> dict[str, Any]:
    """Parse one dig response into a dict."""
    parsed: dict[str, Any] = {}

    header = _HEADER_RE.search(block)
    if header:
        parsed["opcode"] = header.group("opcode").upper()
        parsed["status"] = header.group("status").upper()
        parsed["query_id"] = int(header.group("id"))

    flags = _FLAGS_RE.search(block)
    if flags:
        parsed["flags"] = flags.group("flags").split()
        parsed["question_count"] = int(flags.group("qd"))
        parsed["answer_count"] = int(flags.group("an"))
        parsed["authority_count"] = int(flags.group("ns"))
        parsed["additional_count"] = int(flags.group("ar"))
    else:
        parsed["flags"] = []

    query_time = _QUERY_TIME_RE.search(block)
    if query_time:
        parsed["query_time_ms"] = to_float(query_time.group(1))

    server = _SERVER_RE.search(block)
    if server:
        addr = server.group("addr")
        display = server.group("disp") or ""
        # `SERVER: 8.8.8.8#53(dns.google)` -- prefer whichever half is an IP.
        parsed["server_ip"] = addr if is_ip(addr) else (find_ip(display) or addr)
        parsed["server_port"] = int(server.group("port"))

    transport = _TRANSPORT_RE.search(block)
    if transport:
        parsed["transport"] = transport.group(1).upper()

    msg_size = _MSG_SIZE_RE.search(block)
    if msg_size:
        parsed["msg_size_bytes"] = int(msg_size.group(1))

    parsed["answers"] = _parse_answer_section(block)
    return parsed


def _parse_answer_section(block: str) -> list[dict[str, Any]]:
    """Extract the ANSWER SECTION as structured records."""
    records: list[dict[str, Any]] = []
    in_section = False
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith(";; ANSWER SECTION"):
            in_section = True
            continue
        if in_section:
            if not stripped:
                break
            if stripped.startswith(";"):
                # A new section header ends the answer section.
                if stripped.startswith(";;"):
                    break
                continue
            parts = stripped.split(maxsplit=4)
            if len(parts) < 5:
                continue
            name, ttl, rr_class, rr_type, data = parts
            records.append(
                {
                    "name": strip_trailing_dot(name),
                    "ttl": int(ttl) if ttl.isdigit() else None,
                    "class": rr_class,
                    "type": rr_type.upper(),
                    "data": strip_trailing_dot(data.strip()),
                }
            )
    return records
