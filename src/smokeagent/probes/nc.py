"""TCP/UDP port-reachability probe (the ``nc`` role).

Implemented natively on asyncio rather than by shelling out to ``netcat``:

* ``nc`` is not installed by default on Windows and comes in three mutually
  incompatible flavours on Linux (traditional, OpenBSD, nmap-ncat), each with
  different flags and exit codes;
* spawning a process adds 5-15 ms of fork/exec noise to a measurement whose
  whole point is sub-millisecond accuracy on a LAN;
* a native socket gives us the peer address, the handshake time and the
  service banner directly, with no output parsing.

The target address may be written ``host:port``, ``[::1]:port`` or just
``host`` with ``port`` set in the options.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from typing import Any, ClassVar

from smokeagent.probes.base import Probe, ProbeTarget, register_probe
from smokecommon.errors import ErrorType
from smokecommon.models import ProbeResult

_IPV6_HOSTPORT_RE = re.compile(r"^\[(?P<host>[^\]]+)\](?::(?P<port>\d+))?$")


class PortCheckError(Exception):
    """Internal: a single attempt failed, with a classification attached."""

    def __init__(self, error_type: ErrorType, message: str):
        super().__init__(message)
        self.error_type = error_type


@register_probe
class NcProbe(Probe):
    """Connect to a TCP or UDP port and time it."""

    name = "nc"
    required_binary = None  # pure asyncio, nothing to install
    description = "TCP connect / UDP datagram port check with handshake timing"

    default_options: ClassVar[dict[str, Any]] = {
        "count": 3,
        "timeout": 10.0,
        # Per-attempt budget.
        "connect_timeout": 3.0,
        # Gap between attempts, seconds.
        "interval": 0.2,
        "protocol": "tcp",
        # Required unless the address carries `:port`.
        "port": None,
        "ip_version": None,
        # Bind to a specific local address.
        "source": None,
        # Bytes to send after connecting.  Use "\\r\\n" style escapes; for
        # binary payloads prefix with "hex:" e.g. "hex:0001ff".
        "payload": None,
        # Read up to this many bytes of banner/response (0 disables).
        "read_bytes": 256,
        "read_timeout": 2.0,
        # Fail unless the banner matches.
        "expect_regex": None,
        # UDP only: a silent port is ambiguous (open or filtered).  When true a
        # missing reply is a failure; when false only an ICMP error fails.
        "udp_expect_response": True,
    }

    def validate(self) -> None:
        super().validate()
        protocol = str(self.options["protocol"]).lower()
        if protocol not in ("tcp", "udp"):
            raise ValueError(f"nc: protocol must be tcp or udp, got {protocol!r}")
        if int(self.options["count"]) < 1:
            raise ValueError("nc: count must be >= 1")
        if self.options.get("expect_regex"):
            re.compile(self.options["expect_regex"])
        if protocol == "udp" and not self.options.get("payload"):
            # An empty UDP datagram is legal but most services ignore it, so
            # the probe would report a false "filtered" forever.
            raise ValueError("nc: udp probes require a `payload` to elicit a response")

    # -- execution ---------------------------------------------------------

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        host, port = self.split_address(target.address)
        if port is None:
            return ProbeResult.failure(
                ErrorType.INTERNAL,
                f"no port for {target.address!r}: set `port` or use host:port",
            )

        protocol = str(self.options["protocol"]).lower()
        count = int(self.options["count"])
        interval = float(self.options["interval"])

        try:
            address, family = await self._resolve(host)
        except OSError as exc:
            return ProbeResult.failure(
                ErrorType.DNS_FAILURE,
                f"cannot resolve {host}: {exc}",
                packets_sent=count,
                details={"host": host, "port": port, "protocol": protocol},
            )

        rtts: list[float] = []
        banners: list[str] = []
        errors: list[tuple[ErrorType, str]] = []
        attempts: list[dict[str, Any]] = []

        for index in range(count):
            if index and interval:
                await asyncio.sleep(interval)
            try:
                elapsed_ms, banner = await self._attempt(address, port, family, protocol)
            except PortCheckError as exc:
                errors.append((exc.error_type, str(exc)))
                attempts.append({"ok": False, "error": str(exc)})
            else:
                rtts.append(elapsed_ms)
                attempts.append({"ok": True, "latency_ms": elapsed_ms})
                if banner:
                    banners.append(banner)

        details: dict[str, Any] = {
            "host": host,
            "port": port,
            "protocol": protocol,
            "address_family": "ipv6" if family == socket.AF_INET6 else "ipv4",
            "attempts": attempts,
            "banner": banners[0][:512] if banners else None,
        }

        if not rtts:
            error_type, message = errors[0] if errors else (
                ErrorType.CONNECT_FAILED,
                "no successful attempts",
            )
            return ProbeResult.failure(
                error_type,
                message,
                packets_sent=count,
                details=details,
                resolved_ip=address,
            )

        result = ProbeResult(
            success=True,
            rtts_ms=rtts,
            packets_sent=count,
            packets_received=len(rtts),
            resolved_ip=address,
            details=details,
        )

        pattern = self.options.get("expect_regex")
        if pattern:
            haystack = "\n".join(banners)
            if not re.search(pattern, haystack):
                result.success = False
                result.error_type = ErrorType.BAD_RESPONSE
                result.error_message = f"banner did not match {pattern!r}"
        return result

    # -- internals ---------------------------------------------------------

    async def _resolve(self, host: str) -> tuple[str, int]:
        family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(
            self.options.get("ip_version"), socket.AF_UNSPEC
        )
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        if not infos:
            raise OSError("no addresses returned")
        chosen = infos[0]
        return chosen[4][0], chosen[0]

    async def _attempt(
        self, address: str, port: int, family: int, protocol: str
    ) -> tuple[float, str | None]:
        if protocol == "tcp":
            return await self._tcp_attempt(address, port, family)
        return await self._udp_attempt(address, port, family)

    async def _tcp_attempt(
        self, address: str, port: int, family: int
    ) -> tuple[float, str | None]:
        connect_timeout = float(self.options["connect_timeout"])
        local_addr = (str(self.options["source"]), 0) if self.options.get("source") else None

        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address, port, family=family, local_addr=local_addr
                ),
                timeout=connect_timeout,
            )
        except TimeoutError as exc:
            raise PortCheckError(
                ErrorType.TIMEOUT, f"connect to {address}:{port} timed out after {connect_timeout}s"
            ) from exc
        except ConnectionRefusedError as exc:
            raise PortCheckError(
                ErrorType.CONNECT_FAILED, f"connection refused by {address}:{port}"
            ) from exc
        except OSError as exc:
            raise PortCheckError(
                ErrorType.UNREACHABLE, f"connect to {address}:{port} failed: {exc}"
            ) from exc

        # Stop the clock at handshake completion; banner reading is separate
        # and must not inflate the latency figure.
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        banner: str | None = None
        try:
            payload = _decode_payload(self.options.get("payload"))
            if payload:
                writer.write(payload)
                await writer.drain()
            read_bytes = int(self.options.get("read_bytes") or 0)
            if read_bytes > 0:
                try:
                    data = await asyncio.wait_for(
                        reader.read(read_bytes), timeout=float(self.options["read_timeout"])
                    )
                    banner = data.decode("utf-8", errors="replace") if data else None
                except TimeoutError:
                    banner = None
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (TimeoutError, OSError):
                pass

        return elapsed_ms, banner

    async def _udp_attempt(
        self, address: str, port: int, family: int
    ) -> tuple[float, str | None]:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        local_addr = (str(self.options["source"]), 0) if self.options.get("source") else None

        started = time.perf_counter()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(future),
            remote_addr=(address, port),
            family=family,
            local_addr=local_addr,
        )
        try:
            transport.sendto(_decode_payload(self.options.get("payload")) or b"\x00")
            try:
                data = await asyncio.wait_for(
                    future, timeout=float(self.options["connect_timeout"])
                )
            except TimeoutError:
                # No reply: the port is open *or* silently filtered.  UDP
                # cannot tell them apart, so let the operator choose.
                if self.options.get("udp_expect_response", True):
                    raise PortCheckError(
                        ErrorType.TIMEOUT,
                        f"no UDP reply from {address}:{port} (open|filtered)",
                    ) from None
                return (time.perf_counter() - started) * 1000.0, None
            except OSError as exc:
                # error_received fired: an ICMP error came back, which proves
                # the datagram reached the host and the port is closed.
                raise PortCheckError(
                    ErrorType.CONNECT_FAILED, f"ICMP error from {address}:{port}: {exc}"
                ) from exc

            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return elapsed_ms, data.decode("utf-8", errors="replace") if data else None
        finally:
            transport.close()

    # -- address helpers ---------------------------------------------------

    def split_address(self, address: str) -> tuple[str, int | None]:
        """Split ``host:port`` / ``[v6]:port`` / ``host``, falling back to options."""
        default_port = self.options.get("port")
        default_port = int(default_port) if default_port else None

        match = _IPV6_HOSTPORT_RE.match(address)
        if match:
            port = match.group("port")
            return match.group("host"), int(port) if port else default_port

        if address.count(":") == 1:
            host, _, port_text = address.partition(":")
            if port_text.isdigit():
                return host, int(port_text)
            return address, default_port

        # Bare IPv6 literal (several colons, no brackets) or a plain hostname.
        return address, default_port


@register_probe
class TcpProbe(NcProbe):
    """Alias so configs can say ``probe: tcp`` instead of ``nc`` + options."""

    name = "tcp"
    description = "TCP connect check (nc probe pinned to TCP)"
    default_options: ClassVar[dict[str, Any]] = {"protocol": "tcp"}


@register_probe
class UdpProbe(NcProbe):
    """Alias so configs can say ``probe: udp``."""

    name = "udp"
    description = "UDP datagram check (nc probe pinned to UDP)"
    default_options: ClassVar[dict[str, Any]] = {"protocol": "udp"}


class _UdpProtocol(asyncio.DatagramProtocol):
    """Resolves the future on the first datagram, or on an ICMP error."""

    def __init__(self, future: asyncio.Future[bytes]):
        self._future = future

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc and not self._future.done():
            self._future.set_exception(exc)


def _decode_payload(payload: str | bytes | None) -> bytes | None:
    """Turn a configured payload into bytes.

    Accepts ``hex:0011ff`` for binary and otherwise interprets Python-style
    escapes so ``"GET / HTTP/1.0\\r\\n\\r\\n"`` works from YAML.
    """
    if payload is None:
        return None
    if isinstance(payload, bytes):
        return payload
    text = str(payload)
    if text.startswith("hex:"):
        return bytes.fromhex(text[4:])
    return text.encode("utf-8").decode("unicode_escape").encode("latin-1")
