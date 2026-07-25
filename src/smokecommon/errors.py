"""Canonical failure taxonomy.

Every failed measurement carries one of these values in ``error_type`` so that
dashboards can group failures without parsing free-form messages.  The
human-readable detail stays in ``error_message``.
"""

from __future__ import annotations

from enum import StrEnum


class ErrorType(StrEnum):
    """Why a probe did not produce a usable measurement."""

    #: The probe exceeded its configured timeout.
    TIMEOUT = "timeout"
    #: The target hostname could not be resolved.
    DNS_FAILURE = "dns_failure"
    #: Network-level failure: no route, host/network unreachable, reset.
    UNREACHABLE = "unreachable"
    #: TCP/UDP connection refused or closed by peer.
    CONNECT_FAILED = "connect_failed"
    #: The probe ran, but the application-level response was unacceptable
    #: (bad HTTP status, NXDOMAIN, SERVFAIL, ...).
    BAD_RESPONSE = "bad_response"
    #: Every packet was lost, but the probe itself completed normally.
    PACKET_LOSS = "packet_loss"
    #: The external binary (fping/mtr/dig/...) is not installed.
    TOOL_MISSING = "tool_missing"
    #: The binary ran but its output could not be understood.
    PARSE_ERROR = "parse_error"
    #: The binary exited non-zero for a reason we could not classify.
    TOOL_ERROR = "tool_error"
    #: TLS handshake / certificate problem.
    TLS_ERROR = "tls_error"
    #: Bug or unexpected exception inside the agent.
    INTERNAL = "internal"


#: Substrings that appear in tool stderr, mapped to a canonical error type.
#: Ordered most-specific first; the first hit wins.
_STDERR_HINTS: tuple[tuple[str, ErrorType], ...] = (
    ("could not resolve", ErrorType.DNS_FAILURE),
    # dig's phrasing when the *resolver* name cannot be looked up.
    ("couldn't get address", ErrorType.DNS_FAILURE),
    ("name or service not known", ErrorType.DNS_FAILURE),
    ("temporary failure in name resolution", ErrorType.DNS_FAILURE),
    ("unknown host", ErrorType.DNS_FAILURE),
    ("no address associated", ErrorType.DNS_FAILURE),
    ("nodename nor servname", ErrorType.DNS_FAILURE),
    ("certificate", ErrorType.TLS_ERROR),
    ("ssl", ErrorType.TLS_ERROR),
    ("tls", ErrorType.TLS_ERROR),
    ("connection refused", ErrorType.CONNECT_FAILED),
    ("connection reset", ErrorType.CONNECT_FAILED),
    ("network is unreachable", ErrorType.UNREACHABLE),
    # dig's phrasing: ";; communications error to 1.2.3.4#53: network unreachable"
    ("network unreachable", ErrorType.UNREACHABLE),
    ("host unreachable", ErrorType.UNREACHABLE),
    ("destination unreachable", ErrorType.UNREACHABLE),
    ("no route to host", ErrorType.UNREACHABLE),
    ("timed out", ErrorType.TIMEOUT),
    ("timeout", ErrorType.TIMEOUT),
)


def classify_stderr(text: str, default: ErrorType = ErrorType.TOOL_ERROR) -> ErrorType:
    """Best-effort mapping of a tool's stderr to an :class:`ErrorType`.

    Probes call this when a binary exits non-zero so that, say, a ``curl``
    DNS failure and a ``dig`` DNS failure land in the same bucket.
    """
    lowered = text.lower()
    for needle, error_type in _STDERR_HINTS:
        if needle in lowered:
            return error_type
    return default
