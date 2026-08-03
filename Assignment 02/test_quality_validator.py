"""
test_quality_validator.py — pytest unit tests for quality_validator.py
Run with:  pytest test_quality_validator.py -v
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from quality_validator import (
    check_duplicates,
    check_ip_validation,
    check_missing_fields,
    check_suspicious_patterns,
    check_timestamp_anomalies,
    load_jsonl,
    run_all_checks,
    write_csv_report,
    write_json_summary,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_record(**overrides) -> dict:
    """Create a minimal valid event record, overriding specified fields."""
    base = {
        "event_id":      "evt-00000000-0000-0000-0000-000000000001",
        "timestamp":     "2026-07-15T10:23:45Z",
        "source_ip":     "203.0.113.45",
        "target_ip":     None,
        "user":          None,
        "action":        "ALLOW",
        "status":        "success",
        "log_type":      "firewall",
        "original_line": "2026-07-15T10:23:45Z,203.0.113.45,10.0.0.1,443,ALLOW,1024",
        "parsed_at":     "2026-07-15T10:24:00Z",
    }
    base.update(overrides)
    return base


# ── Check 1: Missing fields ────────────────────────────────────────────────────

class TestMissingFields:
    def test_valid_record_no_issues(self):
        records = [_make_record()]
        issues = check_missing_fields(records)
        assert issues == []

    def test_missing_event_id(self):
        records = [_make_record(event_id=None)]
        issues = check_missing_fields(records)
        assert len(issues) == 1
        assert "event_id" in issues[0]["description"]
        assert issues[0]["severity"] == "ERROR"

    def test_missing_source_ip(self):
        records = [_make_record(source_ip=None)]
        issues = check_missing_fields(records)
        assert any("source_ip" in i["description"] for i in issues)

    def test_missing_multiple_fields(self):
        records = [_make_record(event_id=None, action=None, log_type=None)]
        issues = check_missing_fields(records)
        assert len(issues) == 1
        desc = issues[0]["description"]
        for f in ("event_id", "action", "log_type"):
            assert f in desc

    def test_multiple_records_flags_only_bad_ones(self):
        records = [_make_record(), _make_record(event_id=None), _make_record()]
        issues = check_missing_fields(records)
        assert len(issues) == 1
        assert issues[0]["line_number"] == 2


# ── Check 2: IP validation ─────────────────────────────────────────────────────

class TestIPValidation:
    def test_valid_public_ip_no_issues(self):
        records = [_make_record(source_ip="203.0.113.45")]
        issues = check_ip_validation(records)
        assert issues == []

    def test_invalid_ip_format(self):
        records = [_make_record(source_ip="999.999.999.999")]
        issues = check_ip_validation(records)
        assert any(i["severity"] == "ERROR" for i in issues)

    def test_private_ip_warning(self):
        records = [_make_record(source_ip="192.168.1.100")]
        issues = check_ip_validation(records)
        assert any(i["severity"] == "WARNING" for i in issues)

    def test_private_range_10(self):
        records = [_make_record(source_ip="10.0.0.1")]
        issues = check_ip_validation(records)
        assert any("private" in i["description"].lower() for i in issues)

    def test_private_range_172(self):
        records = [_make_record(source_ip="172.20.0.1")]
        issues = check_ip_validation(records)
        assert any(i["severity"] == "WARNING" for i in issues)

    def test_target_ip_also_checked(self):
        records = [_make_record(target_ip="invalid_ip")]
        issues = check_ip_validation(records)
        assert any("target_ip" in i["description"] for i in issues)


# ── Check 3: Timestamp anomalies ──────────────────────────────────────────────

class TestTimestampAnomalies:
    def test_valid_timestamp_no_issues(self):
        records = [_make_record(timestamp="2026-07-15T10:23:45Z")]
        issues = check_timestamp_anomalies(records)
        assert issues == []

    def test_future_timestamp(self):
        records = [_make_record(timestamp="2099-01-01T00:00:00Z")]
        issues = check_timestamp_anomalies(records)
        assert any("future" in i["description"].lower() for i in issues)
        assert any(i["severity"] == "WARNING" for i in issues)

    def test_old_timestamp(self):
        records = [_make_record(timestamp="2020-01-01T00:00:00Z")]
        issues = check_timestamp_anomalies(records)
        assert any("older than 1 year" in i["description"] for i in issues)

    def test_unparseable_timestamp(self):
        records = [_make_record(timestamp="not-a-date")]
        issues = check_timestamp_anomalies(records)
        assert any(i["severity"] == "ERROR" for i in issues)

    def test_missing_timestamp_flagged(self):
        records = [_make_record(timestamp=None)]
        issues = check_timestamp_anomalies(records)
        assert any(i["severity"] == "ERROR" for i in issues)


# ── Check 4: Duplicate detection ─────────────────────────────────────────────

class TestDuplicates:
    def test_unique_records_no_issues(self):
        import uuid
        records = [_make_record(event_id=str(uuid.uuid4())) for _ in range(5)]
        issues = check_duplicates(records)
        assert issues == []

    def test_duplicate_event_id_detected(self):
        eid = "evt-dup-0000-0000-0000-000000000001"
        records = [_make_record(event_id=eid), _make_record(event_id=eid)]
        issues = check_duplicates(records)
        assert len(issues) == 1
        assert issues[0]["severity"] == "ERROR"
        assert eid in issues[0]["description"]

    def test_multiple_duplicates(self):
        eid = "evt-dup-0000-0000-0000-000000000002"
        records = [_make_record(event_id=eid)] * 4
        issues = check_duplicates(records)
        assert len(issues) == 3  # first occurrence not flagged; 3 duplicates

    def test_duplicate_line_number_correct(self):
        eid = "evt-dup-0000-0000-0000-000000000003"
        records = [
            _make_record(event_id="unique-1"),
            _make_record(event_id=eid),
            _make_record(event_id="unique-2"),
            _make_record(event_id=eid),  # line 4 is the duplicate
        ]
        issues = check_duplicates(records)
        assert issues[0]["line_number"] == 4


# ── Check 5: Suspicious patterns ─────────────────────────────────────────────

class TestSuspiciousPatterns:
    def test_valid_record_no_issues(self):
        records = [_make_record(action="ALLOW", status="success")]
        issues = check_suspicious_patterns(records)
        assert issues == []

    def test_impossible_deny_success(self):
        records = [_make_record(action="DENY", status="success")]
        issues = check_suspicious_patterns(records)
        assert any("Impossible" in i["description"] for i in issues)

    def test_impossible_allow_failure(self):
        records = [_make_record(action="ALLOW", status="failure")]
        issues = check_suspicious_patterns(records)
        assert any("Impossible" in i["description"] for i in issues)

    def test_negative_byte_count(self):
        records = [_make_record(
            original_line="2026-07-15T10:23:45Z,10.0.0.1,10.0.0.2,443,ALLOW,-100"
        )]
        issues = check_suspicious_patterns(records)
        assert any("Negative" in i["description"] for i in issues)

    def test_extreme_byte_count(self):
        records = [_make_record(
            original_line="2026-07-15T10:23:45Z,10.0.0.1,10.0.0.2,443,ALLOW,2000000000000"
        )]
        issues = check_suspicious_patterns(records)
        assert any("Extreme" in i["description"] or "TB" in i["description"] for i in issues)

    def test_rapid_sequential_events(self):
        records = [
            _make_record(timestamp="2026-07-15T10:23:45Z"),
            _make_record(timestamp="2026-07-15T10:23:45Z"),  # same second
        ]
        issues = check_suspicious_patterns(records)
        assert any("Rapid" in i["description"] for i in issues)


# ── End-to-end test ───────────────────────────────────────────────────────────

class TestEndToEnd:
    def _write_jsonl(self, path: Path, records: list[dict]) -> None:
        with path.open("w") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")

    def test_full_pipeline_clean_data(self, tmp_path):
        """Validator runs end-to-end on clean data with no errors."""
        import uuid
        records = [
            _make_record(event_id=str(uuid.uuid4()), source_ip="203.0.113.{i}".format(i=i))
            for i in range(1, 6)
        ]
        input_file = tmp_path / "sample.jsonl"
        self._write_jsonl(input_file, records)
        loaded, errors = load_jsonl(input_file)
        assert errors == []
        result = run_all_checks(loaded)
        err_issues = [i for i in result["all_issues"] if i["severity"] == "ERROR"]
        assert err_issues == []

    def test_full_pipeline_with_issues(self, tmp_path):
        """Validator detects planted errors in a sample file."""
        import uuid
        eid = "FIXED-DUP-ID"
        records = [
            _make_record(event_id=eid, source_ip="999.invalid"),  # bad IP + will be dup
            _make_record(event_id=eid),                           # duplicate
            _make_record(event_id=str(uuid.uuid4()), timestamp="2099-01-01T00:00:00Z"),  # future ts
        ]
        input_file = tmp_path / "issues.jsonl"
        self._write_jsonl(input_file, records)
        loaded, _ = load_jsonl(input_file)
        result = run_all_checks(loaded)

        all_types = {i["check_type"] for i in result["all_issues"]}
        assert "IP Validation" in all_types
        assert "Duplicate Detection" in all_types
        assert "Timestamp Anomaly" in all_types

    def test_csv_report_written(self, tmp_path):
        records = [_make_record(event_id=None)]  # trigger one error
        result = run_all_checks(records)
        csv_path = tmp_path / "report.csv"
        write_csv_report(result["all_issues"], csv_path)
        assert csv_path.exists()
        content = csv_path.read_text()
        assert "line_number" in content
        assert "ERROR" in content

    def test_json_summary_written(self, tmp_path):
        records = [_make_record()]
        result = run_all_checks(records)
        json_path = tmp_path / "summary.json"
        write_json_summary(records, result, json_path)
        data = json.loads(json_path.read_text())
        assert "total_records" in data
        assert data["total_records"] == 1
        assert "by_check" in data
