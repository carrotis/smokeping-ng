"""dig probe: the rich-DNS-data requirement.

What matters here is not the query time -- it is the responding server IP, the
answer records, and the header flags.  Those are what let you tell "the CDN
changed its address" apart from "the anycast resolver PoP is broken".
"""

from __future__ import annotations

import pytest

from smokeagent.probes.dig import DigProbe, _parse_block, _split_blocks
from smokecommon.errors import ErrorType

from conftest import make_output

# Two queries in one dig invocation (dig accepts several), BIND 9.18.
DIG_TWO_QUERIES = """;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40183
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;google.com.\t\t\tIN\tA

;; ANSWER SECTION:
google.com.\t\t216\tIN\tA\t142.250.196.110

;; Query time: 4 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: Sat Jul 25 12:00:00 KST 2026
;; MSG SIZE  rcvd: 55

;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40184
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;google.com.\t\t\tIN\tA

;; ANSWER SECTION:
google.com.\t\t215\tIN\tA\t142.250.196.110

;; Query time: 12 msec
;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
;; WHEN: Sat Jul 25 12:00:00 KST 2026
;; MSG SIZE  rcvd: 55
"""

# CNAME chain plus two A records, answered authoritatively (aa flag).
DIG_CNAME_CHAIN = """;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9001
;; flags: qr aa rd; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
www.example.com.\t300\tIN\tCNAME\tedge.cdn.example.net.
edge.cdn.example.net.\t60\tIN\tA\t93.184.216.34
edge.cdn.example.net.\t60\tIN\tA\t93.184.216.35

;; Query time: 23 msec
;; SERVER: 8.8.8.8#53(dns.google) (UDP)
;; MSG SIZE  rcvd: 120
"""

DIG_NXDOMAIN = """;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 555
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; AUTHORITY SECTION:
invalid.\t\t1800\tIN\tSOA\ta.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400

;; Query time: 31 msec
;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)
;; MSG SIZE  rcvd: 116
"""

DIG_TRUNCATED_TCP = """;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 777
;; flags: qr tc rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
big.example.com.\t60\tIN\tA\t10.1.1.1

;; Query time: 8 msec
;; SERVER: 10.0.0.53#5353(10.0.0.53) (TCP)
;; MSG SIZE  rcvd: 4096
"""

DIG_NO_SERVERS = "dig: couldn't get address for 'nope.invalid': not found\n"


class TestBlockSplitting:
    def test_splits_one_block_per_response(self):
        blocks = _split_blocks(DIG_TWO_QUERIES)
        assert len(blocks) == 2
        assert "id: 40183" in blocks[0]
        assert "id: 40184" in blocks[1]

    def test_each_block_keeps_its_own_query_time(self):
        first, second = (_parse_block(b) for b in _split_blocks(DIG_TWO_QUERIES))
        assert first["query_time_ms"] == 4.0
        assert second["query_time_ms"] == 12.0

    def test_no_blocks_for_non_dig_text(self):
        assert _split_blocks("this is not dig output") == []


class TestParsing:
    def test_multiple_queries_give_a_latency_distribution(self):
        probe = DigProbe({"count": 2})
        result = probe.parse(make_output(DIG_TWO_QUERIES), "google.com")

        assert result.success is True
        assert result.rtts_ms == [4.0, 12.0]
        assert result.packets_sent == 2
        assert result.packets_received == 2

    def test_resolved_ip_is_the_responding_resolver(self):
        # For DNS the interesting IP is the server that answered -- that is how
        # you spot one bad anycast PoP behind 8.8.8.8.
        result = DigProbe({"count": 1}).parse(make_output(DIG_CNAME_CHAIN), "www.example.com")
        assert result.resolved_ip == "8.8.8.8"
        assert result.details["server_ip"] == "8.8.8.8"
        assert result.details["server_port"] == 53
        assert result.details["transport"] == "UDP"

    def test_answer_records_are_structured(self):
        result = DigProbe({"count": 1}).parse(make_output(DIG_CNAME_CHAIN), "www.example.com")
        answers = result.details["answers"]

        assert len(answers) == 3
        assert answers[0] == {
            "name": "www.example.com",
            "ttl": 300,
            "class": "IN",
            "type": "CNAME",
            "data": "edge.cdn.example.net",
        }

    def test_a_records_and_cname_chain_are_extracted(self):
        result = DigProbe({"count": 1}).parse(make_output(DIG_CNAME_CHAIN), "www.example.com")

        assert result.details["answer_ips"] == ["93.184.216.34", "93.184.216.35"]
        assert result.details["cname_chain"] == ["edge.cdn.example.net"]
        assert result.details["ttl_min"] == 60

    def test_authoritative_flag(self):
        authoritative = DigProbe({"count": 1}).parse(
            make_output(DIG_CNAME_CHAIN), "www.example.com"
        )
        recursive = DigProbe({"count": 2}).parse(make_output(DIG_TWO_QUERIES), "google.com")

        assert authoritative.details["authoritative"] is True
        assert recursive.details["authoritative"] is False
        assert recursive.details["recursion_available"] is True

    def test_truncation_and_tcp_fallback_are_visible(self):
        result = DigProbe({"count": 1}).parse(make_output(DIG_TRUNCATED_TCP), "big.example.com")
        assert result.details["truncated"] is True
        assert result.details["transport"] == "TCP"
        assert result.details["server_port"] == 5353

    def test_header_counts_are_recorded(self):
        result = DigProbe({"count": 1}).parse(make_output(DIG_NXDOMAIN), "nope.invalid")
        assert result.details["answer_count"] == 0
        assert result.details["authority_count"] == 1
        assert result.details["status"] == "NXDOMAIN"

    def test_per_attempt_breakdown_is_kept(self):
        result = DigProbe({"count": 2}).parse(make_output(DIG_TWO_QUERIES), "google.com")
        attempts = result.details["attempts"]
        assert [a["query_time_ms"] for a in attempts] == [4.0, 12.0]
        assert all(a["server_ip"] == "127.0.0.53" for a in attempts)


class TestExpectations:
    def test_nxdomain_fails_by_default(self):
        result = DigProbe({"count": 1}).parse(make_output(DIG_NXDOMAIN), "nope.invalid")
        assert result.success is False
        assert result.error_type is ErrorType.BAD_RESPONSE
        assert "NXDOMAIN" in (result.error_message or "")
        # The timing is still recorded -- a fast NXDOMAIN is useful data.
        assert result.rtts_ms == [31.0]

    def test_nxdomain_can_be_the_expected_result(self):
        # Probing that a blocklist entry still returns NXDOMAIN is a real use.
        probe = DigProbe({"count": 1, "expect_status": ["NXDOMAIN"], "expect_min_answers": 0})
        result = probe.parse(make_output(DIG_NXDOMAIN), "nope.invalid")
        assert result.success is True

    def test_expect_ips_catches_a_repointed_record(self):
        probe = DigProbe({"count": 1, "expect_ips": ["93.184.216.99"]})
        result = probe.parse(make_output(DIG_CNAME_CHAIN), "www.example.com")

        assert result.success is False
        assert result.error_type is ErrorType.BAD_RESPONSE
        assert "93.184.216.99" in (result.error_message or "")

    def test_expect_ips_passes_when_one_matches(self):
        probe = DigProbe({"count": 1, "expect_ips": ["93.184.216.35"]})
        assert probe.parse(make_output(DIG_CNAME_CHAIN), "www.example.com").success is True

    def test_min_answers(self):
        probe = DigProbe({"count": 1, "expect_min_answers": 5})
        result = probe.parse(make_output(DIG_CNAME_CHAIN), "www.example.com")
        assert result.success is False
        assert "expected at least 5" in (result.error_message or "")


class TestFailureModes:
    def test_unparsable_output_is_a_dns_failure(self):
        result = DigProbe({"count": 1}).parse(
            make_output(stderr=DIG_NO_SERVERS, returncode=9), "nope.invalid"
        )
        assert result.success is False
        assert result.error_type is ErrorType.DNS_FAILURE

    def test_timeout(self):
        result = DigProbe({"count": 3}).parse(make_output(timed_out=True), "slow.example.com")
        assert result.success is False
        assert result.error_type is ErrorType.TIMEOUT
        assert result.packets_sent == 3


class TestCommandConstruction:
    def test_repeats_the_query_count_times(self):
        argv = DigProbe({"count": 3, "record_type": "aaaa"}).build_argv("example.com")
        assert argv.count("example.com") == 3
        assert argv.count("AAAA") == 3

    def test_resolver_becomes_an_at_argument(self):
        argv = DigProbe({"count": 1, "resolver": "1.1.1.1"}).build_argv("example.com")
        assert "@1.1.1.1" in argv

    def test_tcp_and_norecurse_flags(self):
        argv = DigProbe({"count": 1, "use_tcp": True, "recurse": False}).build_argv("x.com")
        assert "+tcp" in argv
        assert "+norecurse" in argv

    def test_defaults_are_udp_and_recursive(self):
        argv = DigProbe({"count": 1}).build_argv("x.com")
        assert "+notcp" in argv
        assert "+recurse" in argv

    def test_port_override(self):
        argv = DigProbe({"count": 1, "port": 5353}).build_argv("x.com")
        assert argv[argv.index("-p") + 1] == "5353"


class TestValidation:
    def test_expect_status_must_be_a_list(self):
        with pytest.raises(ValueError, match="expect_status"):
            DigProbe({"expect_status": "NOERROR"}).validate()

    def test_valid_config_passes(self):
        DigProbe({"count": 2, "resolver": "8.8.8.8"}).validate()
