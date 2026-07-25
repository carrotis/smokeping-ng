"""HTTP/HTTPS probe built on ``curl``.

This is where the "store more than a number" goal pays off the most.  A single
cycle records:

* the full timing breakdown -- DNS, TCP connect, TLS handshake, request send,
  server think time (TTFB) and body transfer -- so a latency spike can be
  attributed to a layer instead of guessed at;
* ``remote_ip`` / ``remote_port``: the edge that actually served the request.
  For anything behind a CDN this turns "the site is slow" into "the Frankfurt
  edge is slow";
* ``http_code``, ``url_effective`` and the redirect count, so a target that
  starts 302-ing to a login page shows up as a change, not as steady latency;
* HTTP version negotiated, TLS verify result, and transfer sizes/speeds.

Implementation notes
--------------------
``curl -w '%{json}'`` (7.70+) hands us every one of those variables as JSON.
We prefix the format with ``%{stderr}`` so the report lands on stderr and the
response body -- if we asked for one -- stays cleanly on stdout.  For older
curl builds we fall back to an explicit ``key=value`` write-out format.

``count`` requests are issued as ``count`` separate curl processes rather than
chained with ``--next``.  Chaining is cheaper but curl reuses the connection
between transfers, so only the first would measure DNS/TCP/TLS and the rest
would report zeros -- giving a bimodal "distribution" that is an artifact of
connection caching and a timing breakdown stuck at 0 ms.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from typing import Any, ClassVar

from smokeagent.probes.base import Probe, ProbeTarget, register_probe
from smokecommon.errors import ErrorType
from smokecommon.models import ProbeResult
from smokecommon.process import CommandOutput, run_command

#: Variables requested from older curl builds that lack %{json}.
_LEGACY_FIELDS = (
    "http_code",
    "http_version",
    "remote_ip",
    "remote_port",
    "local_ip",
    "local_port",
    "num_connects",
    "num_redirects",
    "redirect_url",
    "url_effective",
    "scheme",
    "content_type",
    "size_download",
    "size_upload",
    "size_header",
    "speed_download",
    "ssl_verify_result",
    "time_namelookup",
    "time_connect",
    "time_appconnect",
    "time_pretransfer",
    "time_redirect",
    "time_starttransfer",
    "time_total",
)

#: curl exit codes we can map onto the shared taxonomy.
_CURL_EXIT_MAP: dict[int, ErrorType] = {
    5: ErrorType.DNS_FAILURE,  # couldn't resolve proxy
    6: ErrorType.DNS_FAILURE,  # couldn't resolve host
    7: ErrorType.CONNECT_FAILED,  # failed to connect
    28: ErrorType.TIMEOUT,
    35: ErrorType.TLS_ERROR,
    47: ErrorType.BAD_RESPONSE,  # too many redirects
    51: ErrorType.TLS_ERROR,
    52: ErrorType.BAD_RESPONSE,  # empty reply
    56: ErrorType.CONNECT_FAILED,  # recv failure
    60: ErrorType.TLS_ERROR,  # certificate verification
    77: ErrorType.TLS_ERROR,
    22: ErrorType.BAD_RESPONSE,  # --fail on HTTP error
}

_STATUS_RANGE_RE = re.compile(r"^(\d{3})\s*-\s*(\d{3})$")
_STATUS_CLASS_RE = re.compile(r"^([1-5])xx$", re.IGNORECASE)


@register_probe
class CurlProbe(Probe):
    """HTTP(S) request with a full timing and connection breakdown."""

    name = "curl"
    required_binary = "curl"
    description = "HTTP/HTTPS via curl, capturing per-phase timings, edge IP and status"

    default_options: ClassVar[dict[str, Any]] = {
        # Requests per cycle.  Each one is a separate curl invocation with its
        # own connection, so the samples are comparable -- see build_argv().
        "count": 1,
        # Seconds between requests within a cycle.
        "interval": 0.0,
        # Total budget for the whole cycle.
        "timeout": 15.0,
        # Per-request budget (curl --max-time).
        "request_timeout": 10.0,
        "connect_timeout": 5.0,
        "method": "GET",
        "follow_redirects": True,
        "max_redirects": 10,
        # Skip TLS verification (self-signed internal endpoints).
        "insecure": False,
        # None | "1.1" | "2" | "3"
        "http_version": None,
        "ip_version": None,
        "headers": {},
        "user_agent": "smoke-agent/curl",
        # Pin a hostname to an address: ["example.com:443:1.2.3.4"].
        # Invaluable for comparing individual CDN edges from one vantage point.
        "resolve": [],
        "proxy": None,
        # Accepted response codes: ints, "200", "2xx" or "200-299".
        "expect_status": ["2xx", "3xx"],
        # When set, the body is downloaded and matched against this regex.
        "expect_body_regex": None,
        "max_body_bytes": 65536,
    }

    def validate(self) -> None:
        super().validate()
        if int(self.options["count"]) < 1:
            raise ValueError("curl: count must be >= 1")
        if self.options["http_version"] not in (None, "1.0", "1.1", "2", "3"):
            raise ValueError("curl: http_version must be one of 1.0, 1.1, 2, 3 or null")
        if self.options["expect_body_regex"]:
            re.compile(self.options["expect_body_regex"])  # fail fast on a bad pattern
        for entry in self.options.get("resolve") or []:
            if str(entry).count(":") < 2:
                raise ValueError(f"curl: resolve entry must be HOST:PORT:ADDRESS, got {entry!r}")

    # -- command construction ---------------------------------------------

    def build_argv(self, url: str, *, legacy: bool = False) -> list[str]:
        opts = self.options
        want_body = bool(opts.get("expect_body_regex"))
        sink = "-" if want_body else os.devnull
        write_out = "%{stderr}" + (_legacy_format() if legacy else "%{json}") + "\n"

        per_request: list[str] = [
            "-o",
            sink,
            "-w",
            write_out,
            "--max-time",
            str(float(opts["request_timeout"])),
            "--connect-timeout",
            str(float(opts["connect_timeout"])),
            "-A",
            str(opts["user_agent"]),
        ]

        method = str(opts["method"]).upper()
        if method == "HEAD":
            per_request.append("-I")
        elif method != "GET":
            per_request += ["-X", method]

        if opts.get("follow_redirects"):
            per_request += ["-L", "--max-redirs", str(int(opts["max_redirects"]))]
        if opts.get("insecure"):
            per_request.append("-k")
        if opts.get("http_version"):
            per_request.append(
                {"1.0": "--http1.0", "1.1": "--http1.1", "2": "--http2", "3": "--http3"}[
                    str(opts["http_version"])
                ]
            )
        if opts.get("ip_version") in (4, 6):
            per_request.append(f"-{opts['ip_version']}")
        if opts.get("proxy"):
            per_request += ["-x", str(opts["proxy"])]
        for name, value in (opts.get("headers") or {}).items():
            per_request += ["-H", f"{name}: {value}"]
        for entry in opts.get("resolve") or []:
            per_request += ["--resolve", str(entry)]

        # One request per invocation.  Chaining `count` transfers with --next
        # would be cheaper, but curl reuses the connection across them: only
        # the first transfer measures DNS/TCP/TLS, the rest report zeros. That
        # makes the samples non-comparable (one cold connect, N-1 warm hits)
        # and leaves the timing breakdown reading 0 ms forever. A latency
        # prober's samples have to measure the same thing, so we pay a fork
        # per request instead. See probe().
        #
        # -s: no progress meter and no error text, so stderr holds only our
        # write-out report.  Failures are reported via the exit code.
        return ["curl", "-s", *per_request, url]

    # -- execution ---------------------------------------------------------

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        count = int(self.options["count"])
        interval = float(self.options.get("interval") or 0.0)
        argv = self.build_argv(target.address)

        reports: list[dict[str, Any]] = []
        last_output: CommandOutput | None = None
        deadline = time.monotonic() + self.timeout

        for index in range(count):
            if index:
                if interval:
                    await asyncio.sleep(interval)
                # Stop early rather than blow through the cycle budget; the
                # samples already collected are still a valid measurement.
                if time.monotonic() >= deadline:
                    break

            remaining = max(1.0, deadline - time.monotonic())
            output = await run_command(argv, timeout=remaining)
            last_output = output
            batch = _parse_json_reports(output.stderr)

            if not batch and not output.timed_out and index == 0:
                # Almost certainly a curl older than 7.70 with no %{json}.
                legacy_output = await run_command(
                    self.build_argv(target.address, legacy=True), timeout=remaining
                )
                batch = _parse_legacy_reports(legacy_output.stderr)
                if batch:
                    last_output = legacy_output

            reports.extend(batch)
            if output.timed_out:
                break

        if last_output is None:  # count < 1 is rejected by validate()
            last_output = await run_command(argv, timeout=self.timeout)
            reports = _parse_json_reports(last_output.stderr)

        return self.parse(last_output, reports, target.address)

    # -- parsing -----------------------------------------------------------

    def parse(
        self, output: CommandOutput, reports: list[dict[str, Any]], url: str
    ) -> ProbeResult:
        count = int(self.options["count"])
        base_details: dict[str, Any] = {
            "command": _redact(output.argv),
            "url_requested": url,
            "method": str(self.options["method"]).upper(),
            "exit_code": output.returncode,
        }

        if output.timed_out:
            return ProbeResult.failure(
                ErrorType.TIMEOUT,
                f"curl exceeded {self.timeout}s",
                packets_sent=count,
                details=base_details,
                duration_ms=output.duration_ms,
            )

        if not reports:
            exit_code = output.returncode if output.returncode is not None else -1
            return ProbeResult.failure(
                _CURL_EXIT_MAP.get(exit_code, ErrorType.TOOL_ERROR),
                f"curl exited {exit_code} with no usable report: "
                f"{output.stderr.strip()[:400] or '(no stderr)'}",
                packets_sent=count,
                details=base_details,
                duration_ms=output.duration_ms,
            )

        timings = [_timing_breakdown(report) for report in reports]
        rtts = [t["total_ms"] for t in timings if t.get("total_ms") is not None]
        final = reports[-1]
        final_timing = timings[-1]

        status = _as_int(final.get("http_code") or final.get("response_code"))
        curl_exit = _as_int(final.get("exitcode"))
        if curl_exit is None:
            curl_exit = output.returncode

        details = {
            **base_details,
            # --- what answered ---
            "remote_ip": final.get("remote_ip") or None,
            "remote_port": _as_int(final.get("remote_port")),
            "local_ip": final.get("local_ip") or None,
            "local_port": _as_int(final.get("local_port")),
            # --- application layer ---
            "http_code": status,
            "http_version": _normalise_http_version(final.get("http_version")),
            "scheme": (final.get("scheme") or "").upper() or None,
            "content_type": final.get("content_type") or None,
            "url_effective": final.get("url_effective") or None,
            "redirect_url": final.get("redirect_url") or None,
            "num_redirects": _as_int(final.get("num_redirects")),
            "redirected": bool(_as_int(final.get("num_redirects")) or 0),
            "num_connects": _as_int(final.get("num_connects")),
            # --- TLS ---
            "ssl_verify_result": _as_int(final.get("ssl_verify_result")),
            # --- volume ---
            "size_download_bytes": _as_int(final.get("size_download")),
            "size_header_bytes": _as_int(final.get("size_header")),
            "speed_download_bps": _as_float(final.get("speed_download")),
            # --- the timing breakdown ---
            **final_timing,
            "curl_exit_code": curl_exit,
            "curl_error": final.get("errormsg") or None,
        }
        if len(reports) > 1:
            details["attempts"] = [
                {"http_code": _as_int(r.get("http_code")), "remote_ip": r.get("remote_ip"), **t}
                for r, t in zip(reports, timings, strict=True)
            ]

        result = ProbeResult(
            success=True,
            rtts_ms=rtts,
            packets_sent=count,
            packets_received=len(rtts),
            resolved_ip=(final.get("remote_ip") or None),
            details=details,
            duration_ms=output.duration_ms,
        )

        failure = self._check_expectations(curl_exit, status, output.stdout, final)
        if failure is not None:
            result.success = False
            result.error_type, result.error_message = failure
        return result

    def _check_expectations(
        self,
        curl_exit: int | None,
        status: int | None,
        body: str,
        final: dict[str, Any],
    ) -> tuple[ErrorType, str] | None:
        if curl_exit:
            message = final.get("errormsg") or f"curl exit code {curl_exit}"
            return _CURL_EXIT_MAP.get(curl_exit, ErrorType.TOOL_ERROR), str(message)[:500]

        if status is None or status == 0:
            return ErrorType.BAD_RESPONSE, "no HTTP status code in response"

        if not status_matches(status, self.options["expect_status"]):
            return (
                ErrorType.BAD_RESPONSE,
                f"HTTP {status}, expected {self.options['expect_status']}",
            )

        pattern = self.options.get("expect_body_regex")
        if pattern:
            excerpt = body[: int(self.options["max_body_bytes"])]
            if not re.search(pattern, excerpt, re.MULTILINE):
                return (
                    ErrorType.BAD_RESPONSE,
                    f"body did not match {pattern!r} (checked {len(excerpt)} bytes)",
                )
        return None


# ---------------------------------------------------------------------------
# Helpers (module level so tests can exercise them directly)
# ---------------------------------------------------------------------------


def status_matches(status: int, patterns: list[Any]) -> bool:
    """Match an HTTP status against ints, ``"2xx"`` or ``"200-299"`` patterns."""
    for pattern in patterns:
        if isinstance(pattern, int):
            if status == pattern:
                return True
            continue
        text = str(pattern).strip()
        if text.isdigit():
            if status == int(text):
                return True
        elif (klass := _STATUS_CLASS_RE.match(text)) is not None:
            if status // 100 == int(klass.group(1)):
                return True
        elif (rng := _STATUS_RANGE_RE.match(text)) is not None:
            if int(rng.group(1)) <= status <= int(rng.group(2)):
                return True
    return False


def _timing_breakdown(report: dict[str, Any]) -> dict[str, Any]:
    """Turn curl's cumulative ``time_*`` seconds into per-phase milliseconds.

    curl's variables are cumulative offsets from the start of the transfer, so
    each phase is the difference between two of them.  ``time_appconnect`` is
    0 for plain HTTP, in which case the TLS phase is reported as ``None``
    rather than a misleading zero.
    """
    def ms(key: str) -> float | None:
        value = _as_float(report.get(key))
        return None if value is None else round(value * 1000.0, 3)

    namelookup = ms("time_namelookup")
    connect = ms("time_connect")
    appconnect = ms("time_appconnect")
    pretransfer = ms("time_pretransfer")
    starttransfer = ms("time_starttransfer")
    redirect = ms("time_redirect")
    total = ms("time_total")

    def delta(later: float | None, earlier: float | None) -> float | None:
        if later is None or earlier is None:
            return None
        return round(max(later - earlier, 0.0), 3)

    tls_ms = delta(appconnect, connect) if appconnect else None
    # Without TLS the request is sent right after the TCP connect.
    request_start = appconnect if appconnect else connect

    return {
        "dns_ms": namelookup,
        "tcp_connect_ms": delta(connect, namelookup),
        "tls_handshake_ms": tls_ms,
        "request_sent_ms": delta(pretransfer, request_start),
        # TTFB as normally understood: absolute time until the first byte.
        "ttfb_ms": starttransfer,
        # How long the server itself took, excluding everything before it.
        "server_processing_ms": delta(starttransfer, pretransfer),
        "content_transfer_ms": delta(total, starttransfer),
        "redirect_ms": redirect,
        "total_ms": total,
    }


def _parse_json_reports(text: str) -> list[dict[str, Any]]:
    """Extract every JSON object emitted by ``-w '%{json}'``.

    Uses ``raw_decode`` in a loop rather than splitting on newlines, so it does
    not care how curl chose to wrap the output.
    """
    decoder = json.JSONDecoder()
    reports: list[dict[str, Any]] = []
    index = 0
    length = len(text)
    while index < length:
        start = text.find("{", index)
        if start == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            index = start + 1
            continue
        if isinstance(obj, dict):
            reports.append(obj)
        index = end
    return reports


def _legacy_format() -> str:
    """Write-out format for curl builds without ``%{json}``."""
    return "\\n".join(f"{field}=%{{{field}}}" for field in _LEGACY_FIELDS) + "\\nEND_REPORT"


def _parse_legacy_reports(text: str) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in text.splitlines():
        line = line.strip()
        if line == "END_REPORT":
            if current:
                reports.append(current)
            current = {}
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            if key in _LEGACY_FIELDS:
                current[key] = value
    if current:
        reports.append(current)
    return reports


def _normalise_http_version(value: Any) -> str | None:
    """curl reports 1.1 / 2 / 3 (or 11 / 20 / 30 on some builds)."""
    if value in (None, "", 0):
        return None
    text = str(value)
    return {"10": "1.0", "11": "1.1", "20": "2", "30": "3"}.get(text, text)


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _redact(argv: list[str]) -> str:
    """Render the command line without leaking credentials from headers."""
    parts: list[str] = []
    redact_next = False
    for token in argv:
        if redact_next:
            name = token.split(":", 1)[0]
            parts.append(f"{name}: <redacted>" if name.lower() in _SENSITIVE_HEADERS else token)
            redact_next = False
            continue
        if token in ("-H", "--header"):
            redact_next = True
        parts.append(token)
    return " ".join(parts)


_SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-api-key"}
