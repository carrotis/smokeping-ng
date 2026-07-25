"""curl probe: timing breakdown, edge IP, status and redirects.

The JSON samples are real ``curl -w '%{json}'`` output (curl 8.5), trimmed of
fields we do not consume.
"""

from __future__ import annotations

import json

import pytest

from smokeagent.probes.base import ProbeTarget
from smokeagent.probes.curl import (
    CurlProbe,
    _parse_json_reports,
    _parse_legacy_reports,
    _timing_breakdown,
    status_matches,
)
from smokecommon.errors import ErrorType

from conftest import make_output


def curl_json(**overrides):
    """A realistic %{json} report; overrides let each test vary one thing."""
    base = {
        "content_type": "text/html; charset=UTF-8",
        "errormsg": "",
        "exitcode": 0,
        "http_code": 200,
        "http_version": "2",
        "local_ip": "192.168.1.20",
        "local_port": 51234,
        "method": "GET",
        "num_connects": 1,
        "num_redirects": 0,
        "redirect_url": "",
        "remote_ip": "142.250.196.110",
        "remote_port": 443,
        "response_code": 200,
        "scheme": "HTTPS",
        "size_download": 15234,
        "size_header": 412,
        "speed_download": 152340.0,
        "ssl_verify_result": 0,
        "time_appconnect": 0.081234,
        "time_connect": 0.035512,
        "time_namelookup": 0.004201,
        "time_pretransfer": 0.081512,
        "time_redirect": 0.0,
        "time_starttransfer": 0.142887,
        "time_total": 0.150221,
        "url_effective": "https://www.google.com/",
    }
    base.update(overrides)
    return json.dumps(base)


class TestTimingBreakdown:
    def test_phases_are_deltas_not_cumulative_offsets(self):
        report = json.loads(curl_json())
        timing = _timing_breakdown(report)

        # curl reports cumulative offsets; each phase is a difference.
        assert timing["dns_ms"] == pytest.approx(4.201)
        assert timing["tcp_connect_ms"] == pytest.approx(31.311)  # 35.512 - 4.201
        assert timing["tls_handshake_ms"] == pytest.approx(45.722)  # 81.234 - 35.512
        assert timing["total_ms"] == pytest.approx(150.221)

    def test_ttfb_is_absolute_and_server_time_is_isolated(self):
        timing = _timing_breakdown(json.loads(curl_json()))
        assert timing["ttfb_ms"] == pytest.approx(142.887)
        # Server think time excludes DNS/TCP/TLS: 142.887 - 81.512
        assert timing["server_processing_ms"] == pytest.approx(61.375)
        assert timing["content_transfer_ms"] == pytest.approx(7.334)

    def test_phases_sum_to_the_total(self):
        timing = _timing_breakdown(json.loads(curl_json()))
        parts = (
            timing["dns_ms"]
            + timing["tcp_connect_ms"]
            + timing["tls_handshake_ms"]
            + timing["request_sent_ms"]
            + timing["server_processing_ms"]
            + timing["content_transfer_ms"]
        )
        assert parts == pytest.approx(timing["total_ms"], abs=0.01)

    def test_plain_http_reports_no_tls_phase(self):
        # time_appconnect is 0 without TLS; reporting 0 ms would wrongly suggest
        # an instant handshake happened.
        timing = _timing_breakdown(json.loads(curl_json(time_appconnect=0.0)))
        assert timing["tls_handshake_ms"] is None
        assert timing["request_sent_ms"] is not None


class TestParsing:
    def test_successful_request(self):
        result = CurlProbe().parse(
            make_output(stderr=curl_json()), _parse_json_reports(curl_json()), "https://google.com"
        )

        assert result.success is True
        assert result.rtts_ms == [pytest.approx(150.221)]
        assert result.resolved_ip == "142.250.196.110"
        assert result.details["http_code"] == 200
        assert result.details["http_version"] == "2"
        assert result.details["remote_port"] == 443

    def test_redirect_chain_records_the_final_url(self):
        payload = curl_json(
            num_redirects=2,
            url_effective="https://www.example.com/login",
            time_redirect=0.052,
            http_code=200,
        )
        result = CurlProbe().parse(
            make_output(stderr=payload), _parse_json_reports(payload), "http://example.com"
        )

        assert result.details["redirected"] is True
        assert result.details["num_redirects"] == 2
        assert result.details["url_effective"] == "https://www.example.com/login"
        assert result.details["redirect_ms"] == pytest.approx(52.0)

    def test_unexpected_status_fails_but_keeps_the_timings(self):
        payload = curl_json(http_code=503, response_code=503)
        result = CurlProbe().parse(
            make_output(stderr=payload), _parse_json_reports(payload), "https://example.com"
        )

        assert result.success is False
        assert result.error_type is ErrorType.BAD_RESPONSE
        assert "503" in (result.error_message or "")
        # Still recorded: a fast 503 and a slow 503 are different problems.
        assert result.details["ttfb_ms"] is not None
        assert result.resolved_ip == "142.250.196.110"

    def test_curl_exit_code_maps_to_the_taxonomy(self):
        payload = curl_json(
            exitcode=6, http_code=0, response_code=0, errormsg="Could not resolve host: nope.invalid"
        )
        result = CurlProbe().parse(
            make_output(stderr=payload, returncode=6),
            _parse_json_reports(payload),
            "https://nope.invalid",
        )

        assert result.success is False
        assert result.error_type is ErrorType.DNS_FAILURE
        assert "resolve" in (result.error_message or "").lower()

    def test_tls_failure(self):
        payload = curl_json(exitcode=60, http_code=0, errormsg="SSL certificate problem")
        result = CurlProbe().parse(
            make_output(stderr=payload, returncode=60),
            _parse_json_reports(payload),
            "https://expired.example.com",
        )
        assert result.error_type is ErrorType.TLS_ERROR

    def test_timeout(self):
        result = CurlProbe().parse(make_output(timed_out=True), [], "https://slow.example.com")
        assert result.success is False
        assert result.error_type is ErrorType.TIMEOUT

    def test_no_report_at_all(self):
        result = CurlProbe().parse(
            make_output(stderr="curl: (7) Failed to connect", returncode=7),
            [],
            "https://down.example.com",
        )
        assert result.success is False
        assert result.error_type is ErrorType.CONNECT_FAILED

    def test_multiple_requests_give_a_distribution(self):
        stderr = curl_json(time_total=0.10) + "\n" + curl_json(time_total=0.20)
        probe = CurlProbe({"count": 2})
        result = probe.parse(
            make_output(stderr=stderr), _parse_json_reports(stderr), "https://example.com"
        )

        assert result.rtts_ms == [pytest.approx(100.0), pytest.approx(200.0)]
        assert result.effective_latency_ms == pytest.approx(150.0)
        assert "attempts" in result.details
        assert len(result.details["attempts"]) == 2

    def test_authorization_header_is_redacted_from_the_stored_command(self):
        probe = CurlProbe({"headers": {"Authorization": "Bearer super-secret-token"}})
        argv = probe.build_argv("https://api.example.com")
        result = probe.parse(
            make_output(stderr=curl_json(), argv=argv),
            _parse_json_reports(curl_json()),
            "https://api.example.com",
        )
        assert "super-secret-token" not in result.details["command"]
        assert "<redacted>" in result.details["command"]


class TestMultiSampleExecution:
    """`count` requests must be independent, comparable measurements.

    curl reuses the connection across `--next` transfers, which used to make
    samples 2..N measure a warm connection while sample 1 measured a cold one,
    and left the reported DNS/TCP/TLS phases at zero.
    """

    async def test_count_runs_that_many_curl_processes(self, monkeypatch):
        calls = []

        async def fake_run(argv, timeout, **kwargs):
            calls.append(argv)
            return make_output(stderr=curl_json(time_total=0.10 + 0.01 * len(calls)))

        monkeypatch.setattr("smokeagent.probes.curl.run_command", fake_run)
        result = await CurlProbe({"count": 3}).probe(
            ProbeTarget(name="t", address="https://example.com")
        )

        assert len(calls) == 3
        assert all("--next" not in argv for argv in calls)
        assert len(result.rtts_ms) == 3

    async def test_every_sample_measures_a_fresh_connection(self, monkeypatch):
        # Each invocation is a separate process, so each report carries real
        # connection timings rather than zeros.
        async def fake_run(argv, timeout, **kwargs):
            return make_output(stderr=curl_json())

        monkeypatch.setattr("smokeagent.probes.curl.run_command", fake_run)
        result = await CurlProbe({"count": 3}).probe(
            ProbeTarget(name="t", address="https://example.com")
        )

        assert result.details["tls_handshake_ms"] == pytest.approx(45.722)
        assert result.details["tcp_connect_ms"] == pytest.approx(31.311)
        assert result.details["dns_ms"] == pytest.approx(4.201)
        for attempt in result.details["attempts"]:
            assert attempt["tls_handshake_ms"] is not None
            assert attempt["tcp_connect_ms"] > 0

    async def test_a_timeout_partway_through_keeps_the_samples_taken(self, monkeypatch):
        calls = []

        async def fake_run(argv, timeout, **kwargs):
            calls.append(argv)
            if len(calls) >= 3:
                return make_output(timed_out=True)
            return make_output(stderr=curl_json())

        monkeypatch.setattr("smokeagent.probes.curl.run_command", fake_run)
        result = await CurlProbe({"count": 5}).probe(
            ProbeTarget(name="t", address="https://example.com")
        )

        # Stopped at the timeout rather than running all five.
        assert len(calls) == 3
        assert result.success is False
        assert result.error_type is ErrorType.TIMEOUT

    async def test_single_request_still_costs_one_process(self, monkeypatch):
        calls = []

        async def fake_run(argv, timeout, **kwargs):
            calls.append(argv)
            return make_output(stderr=curl_json())

        monkeypatch.setattr("smokeagent.probes.curl.run_command", fake_run)
        await CurlProbe().probe(ProbeTarget(name="t", address="https://example.com"))
        assert len(calls) == 1


class TestReportExtraction:
    def test_extracts_several_json_objects(self):
        text = curl_json(http_code=200) + curl_json(http_code=301)
        reports = _parse_json_reports(text)
        assert [r["http_code"] for r in reports] == [200, 301]

    def test_ignores_surrounding_noise(self):
        text = f"warning: something\n{curl_json()}\ntrailing junk"
        assert len(_parse_json_reports(text)) == 1

    def test_returns_empty_for_non_json(self):
        assert _parse_json_reports("curl: (7) Failed to connect") == []

    def test_legacy_key_value_format(self):
        # curl < 7.70 has no %{json}; the fallback write-out is parsed instead.
        text = (
            "http_code=200\nremote_ip=1.2.3.4\ntime_total=0.25\n"
            "time_namelookup=0.01\nEND_REPORT\n"
        )
        reports = _parse_legacy_reports(text)
        assert len(reports) == 1
        assert reports[0]["http_code"] == "200"
        assert reports[0]["remote_ip"] == "1.2.3.4"

    def test_legacy_parses_into_the_same_shape(self):
        text = "http_code=200\nremote_ip=1.2.3.4\ntime_total=0.25\nEND_REPORT\n"
        reports = _parse_legacy_reports(text)
        result = CurlProbe().parse(make_output(stderr=text), reports, "https://x.example.com")
        assert result.success is True
        assert result.details["http_code"] == 200
        assert result.resolved_ip == "1.2.3.4"
        assert result.rtts_ms == [pytest.approx(250.0)]


class TestStatusMatching:
    @pytest.mark.parametrize(
        ("status", "patterns", "expected"),
        [
            (200, ["2xx"], True),
            (204, ["2xx"], True),
            (301, ["2xx"], False),
            (301, ["2xx", "3xx"], True),
            (200, [200], True),
            (200, ["200"], True),
            (404, ["200-299"], False),
            (250, ["200-299"], True),
            (500, ["5xx"], True),
            (200, [], False),
        ],
    )
    def test_patterns(self, status, patterns, expected):
        assert status_matches(status, patterns) is expected


class TestCommandConstruction:
    def test_write_out_goes_to_stderr(self):
        # Keeps the report separate from the body on stdout.
        argv = CurlProbe().build_argv("https://example.com")
        write_out = argv[argv.index("-w") + 1]
        assert write_out.startswith("%{stderr}")
        assert "%{json}" in write_out

    def test_follows_redirects_by_default(self):
        argv = CurlProbe().build_argv("https://example.com")
        assert "-L" in argv

    def test_head_request(self):
        argv = CurlProbe({"method": "HEAD"}).build_argv("https://example.com")
        assert "-I" in argv

    def test_resolve_pins_an_edge(self):
        argv = CurlProbe({"resolve": ["example.com:443:1.2.3.4"]}).build_argv(
            "https://example.com"
        )
        assert argv[argv.index("--resolve") + 1] == "example.com:443:1.2.3.4"

    def test_each_request_is_its_own_invocation(self):
        # Regression: chaining with --next made curl reuse the connection, so
        # transfers 2..N reported connect/appconnect as 0 and the stored timing
        # breakdown read 0 ms for DNS/TCP/TLS forever.
        argv = CurlProbe({"count": 3}).build_argv("https://example.com")
        assert "--next" not in argv
        assert argv.count("https://example.com") == 1

    def test_headers_are_passed_through(self):
        argv = CurlProbe({"headers": {"X-Test": "1"}}).build_argv("https://example.com")
        assert "X-Test: 1" in argv


class TestValidation:
    def test_rejects_a_bad_resolve_entry(self):
        with pytest.raises(ValueError, match="HOST:PORT:ADDRESS"):
            CurlProbe({"resolve": ["example.com"]}).validate()

    def test_rejects_a_bad_body_regex(self):
        import re

        with pytest.raises(re.error):
            CurlProbe({"expect_body_regex": "["}).validate()

    def test_rejects_unknown_http_version(self):
        with pytest.raises(ValueError, match="http_version"):
            CurlProbe({"http_version": "9"}).validate()

    def test_accepts_a_sane_config(self):
        CurlProbe({"count": 1, "expect_status": ["2xx"], "http_version": "2"}).validate()
