"""Small text-parsing helpers shared by the binary-backed probes."""

from __future__ import annotations

import ipaddress
import re

#: Matches a bare IPv4 address.
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
#: Deliberately loose IPv6 matcher; every hit is validated with `ipaddress`
#: before use, so false positives are cheap.
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}\b")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def find_ip(text: str) -> str | None:
    """Return the first syntactically valid IP address in ``text``."""
    for match in IPV4_RE.finditer(text):
        if is_ip(match.group(0)):
            return match.group(0)
    for match in IPV6_RE.finditer(text):
        candidate = match.group(0)
        if is_ip(candidate):
            return candidate
    return None


def find_bracketed_ip(text: str) -> str | None:
    """Extract the address from ``host [1.2.3.4]`` or ``host (1.2.3.4)``.

    This is how both Windows ``ping`` and Linux ``ping`` announce the address
    they resolved the target to, and it is the value we want in
    ``resolved_ip`` -- the *actual* endpoint, not the configured hostname.
    """
    for match in re.finditer(r"[\[(]([0-9A-Fa-f:.]+)[\])]", text):
        if is_ip(match.group(1)):
            return match.group(1)
    return None


def to_float(value: str | None) -> float | None:
    """Parse a number that may use a comma decimal separator, or return None."""
    if value is None:
        return None
    try:
        return float(value.replace(",", "."))
    except (ValueError, AttributeError):
        return None


def strip_trailing_dot(name: str) -> str:
    """``example.com.`` -> ``example.com`` (DNS presentation format)."""
    return name[:-1] if name.endswith(".") else name
