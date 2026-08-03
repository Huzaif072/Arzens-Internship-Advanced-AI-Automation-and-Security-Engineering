"""
test_log_parser.py — pytest unit tests for log_parser.py
Run with:  pytest test_log_parser.py -v
"""

import json
import tempfile
from pathlib import Path

import pytest

from log_parser import (
    is_valid_ip,
    normalize_ip,
    normalize_timestamp,
    parse_auth_line,
    parse_dns_line,
    parse_firewall_line,
    parse_file,
    write_jsonl,
)


# ── 1. Firewall format ────────────────────────────────────────────────────────

class TestFirewallParser:
    def test_allow_record(self):
        line = "2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW,15234"
        event = parse_firewall_line(line)
        assert event is not None
        assert event["log_type"] == "firewall"
        assert event["source_ip"] == "192.168.1.100"
        assert event["target_ip"] == "10.0.0.50"
        assert event["action"] == "ALLOW"
        assert event["status"] == "success"
        assert event["original_line"] == line

    def test_deny_record(self):
        line = "2026-07-15T10:24:10Z,203.0.113.45,192.168.1.1,80,DENY,512"
        event = parse_firewall_line(line)
        assert event is not None
        assert event["action"] == "DENY"
        assert event["status"] == "failure"

    def test_event_id_is_uuid(self):
        line = "2026-07-15T10:23:45Z,10.0.0.1,10.0.0.2,22,ALLOW,0"
        event = parse_firewall_line(line)
        import uuid
        uuid.UUID(event["event_id"])  # raises if not a valid UUID

    def test_fields_present(self):
        line = "2026-07-15T10:23:45Z,192.168.1.1,10.0.0.1,443,ALLOW,100"
        event = parse_firewall_line(line)
        required_keys = {"event_id", "timestamp", "source_ip", "target_ip",
                         "action", "status", "log_type", "original_line", "parsed_at"}
        assert required_keys.issubset(event.keys())


# ── 2. Auth format ────────────────────────────────────────────────────────────

class TestAuthParser:
    def test_success_record(self):
        line = "2026-07-15 10:23:45 alice_web corporate-vpn SUCCESS 203.0.113.45"
        event = parse_auth_line(line)
        assert event is not None
        assert event["log_type"] == "auth"
        assert event["user"] == "alice_web"
        assert event["source_ip"] == "203.0.113.45"
        assert event["action"] == "SUCCESS"
        assert event["status"] == "success"

    def test_failure_record(self):
        line = "2026-07-15 10:25:30 charlie_ops remote-access FAILURE 198.51.100.10"
        event = parse_auth_line(line)
        assert event is not None
        assert event["action"] == "FAILURE"
        assert event["status"] == "failure"

    def test_user_field_extracted(self):
        line = "2026-07-15 10:27:44 dave_admin vpn-gateway SUCCESS 10.0.0.5"
        event = parse_auth_line(line)
        assert event["user"] == "dave_admin"


# ── 3. DNS format ─────────────────────────────────────────────────────────────

class TestDnsParser:
    def test_nxdomain_record(self):
        line = "query_time=2026-07-15T10:23:45Z|client=192.168.1.50|domain=suspicious.example.com|type=A|response=NXDOMAIN"
        event = parse_dns_line(line)
        assert event is not None
        assert event["log_type"] == "dns"
        assert event["source_ip"] == "192.168.1.50"
        assert event["user"] == "suspicious.example.com"
        assert event["action"] == "RESPONSE"

    def test_noerror_record(self):
        line = "query_time=2026-07-15T10:24:10Z|client=10.0.0.25|domain=google.com|type=A|response=NOERROR"
        event = parse_dns_line(line)
        assert event is not None
        assert event["source_ip"] == "10.0.0.25"

    def test_domain_stored_in_user(self):
        line = "query_time=2026-07-15T10:28:44Z|client=10.10.10.5|domain=api.slack.com|type=A|response=NOERROR"
        event = parse_dns_line(line)
        assert event["user"] == "api.slack.com"


# ── 4. Timestamp normalization ────────────────────────────────────────────────

class TestTimestampNormalization:
    def test_iso_utc_z(self):
        result = normalize_timestamp("2026-07-15T10:23:45Z")
        assert result == "2026-07-15T10:23:45Z"

    def test_space_separated(self):
        result = normalize_timestamp("2026-07-15 10:23:45")
        assert result == "2026-07-15T10:23:45Z"

    def test_unparseable_returns_none(self):
        result = normalize_timestamp("not-a-timestamp")
        assert result is None

    def test_empty_returns_none(self):
        result = normalize_timestamp("")
        assert result is None

    def test_iso_no_tz(self):
        result = normalize_timestamp("2026-07-15T10:23:45")
        assert result == "2026-07-15T10:23:45Z"


# ── 5. IP validation ──────────────────────────────────────────────────────────

class TestIPValidation:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.100") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("2001:db8::1") is True

    def test_invalid_ip(self):
        assert is_valid_ip("999.999.999.999") is False

    def test_empty_string(self):
        assert is_valid_ip("") is False

    def test_normalize_invalid_returns_none(self):
        assert normalize_ip("not-an-ip") is None

    def test_normalize_valid_returns_ip(self):
        assert normalize_ip("  10.0.0.1  ") == "10.0.0.1"


# ── 6. Malformed line graceful failure ────────────────────────────────────────

class TestMalformedLines:
    def test_firewall_too_few_fields(self):
        """A CSV line with only 3 fields should be skipped, not crash."""
        event = parse_firewall_line("2026-07-15T10:23:45Z,10.0.0.1")
        assert event is None

    def test_auth_too_few_fields(self):
        event = parse_auth_line("2026-07-15 10:23:45 only_three_fields")
        assert event is None

    def test_dns_no_kv_pairs(self):
        event = parse_dns_line("this is just garbage text with no equals signs")
        assert event is None

    def test_empty_line_firewall(self):
        assert parse_firewall_line("") is None

    def test_empty_line_auth(self):
        assert parse_auth_line("") is None

    def test_empty_line_dns(self):
        assert parse_dns_line("") is None

    def test_comment_line_skipped(self):
        assert parse_firewall_line("# this is a comment") is None


# ── 7. End-to-end file parsing ────────────────────────────────────────────────

class TestEndToEnd:
    def test_parse_firewall_file(self, tmp_path):
        log_file = tmp_path / "firewall.csv"
        log_file.write_text(
            "2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW,15234\n"
            "2026-07-15T10:24:10Z,203.0.113.45,192.168.1.1,80,DENY,512\n"
        )
        events = parse_file(log_file, fmt="firewall")
        assert len(events) == 2
        assert all(e["log_type"] == "firewall" for e in events)

    def test_parse_auth_file(self, tmp_path):
        log_file = tmp_path / "auth.txt"
        log_file.write_text(
            "2026-07-15 10:23:45 alice_web corporate-vpn SUCCESS 203.0.113.45\n"
            "2026-07-15 10:25:30 charlie_ops remote-access FAILURE 198.51.100.10\n"
        )
        events = parse_file(log_file, fmt="auth")
        assert len(events) == 2

    def test_parse_dns_file(self, tmp_path):
        log_file = tmp_path / "dns.txt"
        log_file.write_text(
            "query_time=2026-07-15T10:23:45Z|client=192.168.1.50|domain=bad.com|type=A|response=NXDOMAIN\n"
            "query_time=2026-07-15T10:24:10Z|client=10.0.0.25|domain=google.com|type=A|response=NOERROR\n"
        )
        events = parse_file(log_file, fmt="dns")
        assert len(events) == 2

    def test_output_is_valid_jsonl(self, tmp_path):
        log_file = tmp_path / "firewall.csv"
        log_file.write_text(
            "2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW,15234\n"
        )
        out_file = tmp_path / "out.jsonl"
        events = parse_file(log_file, fmt="firewall")
        write_jsonl(events, out_file)
        lines = out_file.read_text().splitlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["log_type"] == "firewall"

    def test_malformed_lines_skipped_not_crashed(self, tmp_path):
        log_file = tmp_path / "mixed.csv"
        log_file.write_text(
            "GARBAGE LINE THAT SHOULD BE SKIPPED\n"
            "2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW,15234\n"
            "another bad line\n"
        )
        events = parse_file(log_file, fmt="firewall")
        # Only the valid line should parse
        assert len(events) == 1
