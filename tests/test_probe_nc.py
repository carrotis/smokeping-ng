"""nc probe: TCP/UDP port checks.

Unlike the other probes this one has no output to parse -- it talks to real
sockets.  So these tests spin up real listeners on localhost, which also proves
the probe works end to end without any external binary.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from smokeagent.probes.base import ProbeTarget
from smokeagent.probes.nc import NcProbe, TcpProbe, UdpProbe, _decode_payload
from smokecommon.errors import ErrorType


@contextlib.asynccontextmanager
async def tcp_server(banner: bytes | None = None):
    """A localhost TCP listener that optionally greets the client."""

    async def handle(reader, writer):
        if banner:
            writer.write(banner)
            with contextlib.suppress(ConnectionError):
                await writer.drain()
        with contextlib.suppress(ConnectionError, OSError):
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield port


@contextlib.asynccontextmanager
async def udp_echo_server():
    """A localhost UDP echo listener."""

    class Echo(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            self.transport.sendto(b"pong:" + data, addr)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
    try:
        yield transport.get_extra_info("sockname")[1]
    finally:
        transport.close()


class TestAddressParsing:
    @pytest.mark.parametrize(
        ("address", "options", "expected"),
        [
            ("example.com:443", {}, ("example.com", 443)),
            ("example.com", {"port": 8080}, ("example.com", 8080)),
            ("[2606:4700::1111]:443", {}, ("2606:4700::1111", 443)),
            ("[::1]", {"port": 22}, ("::1", 22)),
            ("2606:4700::1111", {"port": 53}, ("2606:4700::1111", 53)),
            ("example.com", {}, ("example.com", None)),
        ],
    )
    def test_splits_host_and_port(self, address, options, expected):
        assert NcProbe(options).split_address(address) == expected


class TestTcp:
    async def test_open_port(self):
        async with tcp_server() as port:
            probe = TcpProbe({"count": 3, "interval": 0, "read_bytes": 0})
            result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))

        assert result.success is True
        assert len(result.rtts_ms) == 3
        assert result.packets_sent == 3
        assert result.packets_received == 3
        assert result.resolved_ip == "127.0.0.1"
        assert result.details["protocol"] == "tcp"
        assert result.details["port"] == port

    async def test_closed_port_is_connect_failed(self):
        # Bind and immediately release, so the port is almost certainly free.
        async with tcp_server() as port:
            pass
        probe = TcpProbe({"count": 1, "interval": 0, "connect_timeout": 1.0})
        result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))

        assert result.success is False
        assert result.error_type in (ErrorType.CONNECT_FAILED, ErrorType.UNREACHABLE)
        assert result.packets_sent == 1

    async def test_banner_is_captured(self):
        async with tcp_server(banner=b"SSH-2.0-OpenSSH_9.6\r\n") as port:
            probe = TcpProbe({"count": 1, "interval": 0, "read_bytes": 128})
            result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))

        assert result.success is True
        assert "OpenSSH" in result.details["banner"]

    async def test_expect_regex_matching_banner(self):
        async with tcp_server(banner=b"SSH-2.0-OpenSSH_9.6\r\n") as port:
            probe = TcpProbe(
                {"count": 1, "interval": 0, "read_bytes": 128, "expect_regex": r"SSH-2\.0"}
            )
            result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))
        assert result.success is True

    async def test_expect_regex_mismatch_fails_but_keeps_timing(self):
        async with tcp_server(banner=b"HTTP/1.1 400 Bad Request\r\n") as port:
            probe = TcpProbe(
                {"count": 1, "interval": 0, "read_bytes": 128, "expect_regex": r"SSH-2\.0"}
            )
            result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))

        assert result.success is False
        assert result.error_type is ErrorType.BAD_RESPONSE
        assert result.rtts_ms  # the handshake still happened and was timed

    async def test_missing_port_is_a_config_error(self):
        result = await NcProbe({"count": 1}).probe(ProbeTarget(name="t", address="example.com"))
        assert result.success is False
        assert result.error_type is ErrorType.INTERNAL
        assert "port" in (result.error_message or "")

    async def test_unresolvable_host(self):
        probe = TcpProbe({"count": 1, "interval": 0})
        result = await probe.probe(
            ProbeTarget(name="t", address="no-such-host.invalid:443")
        )
        assert result.success is False
        assert result.error_type is ErrorType.DNS_FAILURE

    async def test_banner_read_does_not_inflate_the_latency(self):
        # A server that greets slowly must not make the connect look slow --
        # the clock stops at handshake completion.
        async def slow_greeter(reader, writer):
            await asyncio.sleep(0.25)
            writer.write(b"hello\n")
            with contextlib.suppress(ConnectionError):
                await writer.drain()
                writer.close()

        server = await asyncio.start_server(slow_greeter, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            probe = TcpProbe(
                {"count": 1, "interval": 0, "read_bytes": 64, "read_timeout": 2.0}
            )
            result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))

        assert result.success is True
        assert result.rtts_ms[0] < 100.0
        assert "hello" in result.details["banner"]


class TestUdp:
    async def test_echo_response(self):
        async with udp_echo_server() as port:
            probe = UdpProbe({"count": 2, "interval": 0, "payload": "ping"})
            result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))

        assert result.success is True
        assert result.packets_received == 2
        assert result.details["protocol"] == "udp"

    async def test_silent_port_times_out_when_a_response_is_required(self):
        # UDP cannot distinguish open from filtered, so the operator chooses.
        async with udp_echo_server() as port:
            pass
        probe = UdpProbe(
            {"count": 1, "interval": 0, "payload": "ping", "connect_timeout": 0.3}
        )
        result = await probe.probe(ProbeTarget(name="t", address=f"127.0.0.1:{port}"))

        assert result.success is False
        assert result.error_type in (ErrorType.TIMEOUT, ErrorType.CONNECT_FAILED)

    def test_udp_without_payload_is_rejected_at_startup(self):
        with pytest.raises(ValueError, match="payload"):
            UdpProbe({"count": 1}).validate()


class TestPayloadDecoding:
    def test_plain_text(self):
        assert _decode_payload("hello") == b"hello"

    def test_escapes_are_interpreted(self):
        assert _decode_payload("GET / HTTP/1.0\\r\\n\\r\\n") == b"GET / HTTP/1.0\r\n\r\n"

    def test_hex_prefix(self):
        assert _decode_payload("hex:00ff10") == b"\x00\xff\x10"

    def test_none_stays_none(self):
        assert _decode_payload(None) is None


class TestAliases:
    def test_tcp_alias_inherits_nc_defaults_and_pins_the_protocol(self):
        probe = TcpProbe()
        assert probe.options["protocol"] == "tcp"
        assert probe.options["count"] == NcProbe().options["count"]

    def test_udp_alias(self):
        assert UdpProbe().options["protocol"] == "udp"

    def test_needs_no_external_binary(self):
        assert NcProbe.required_binary is None
        assert NcProbe.is_available() is True
