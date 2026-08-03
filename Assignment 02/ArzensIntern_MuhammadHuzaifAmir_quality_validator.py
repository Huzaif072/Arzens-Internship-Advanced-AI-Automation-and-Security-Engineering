"""
quality_validator.py — Data Quality Validator for Normalized Security Logs
Validates JSONL output from log_parser.py and generates compliance reports.

Usage:
    python quality_validator.py --input output_normalized.jsonl
    python quality_validator.py --input output_bulk.jsonl --csv bulk_report.csv --json bulk_summary.json
"""

import argparse
import csv
import ipaddress
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ── Constants ──────────────────────────────────────────────────────────────────

CRITICAL_FIELDS = {"event_id", "timestamp", "source_ip", "action", "log_type"}

# Private IP ranges per RFC 1918 and RFC 4193
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Impossible action/status combinations
IMPOSSIBLE_COMBOS = {
    ("DENY", "success"),
    ("ALLOW", "failure"),
    ("SUCCESS", "failure"),
    ("FAILURE", "success"),
}

MAX_BYTES = 1_000_000_000_000          # 1 TB
ONE_YEAR_AGO = datetime.now(timezone.utc) - timedelta(days=365)


# ── Helpers ────────────────────────────────────────────────────────────────────

def parse_ts(ts_str: str) -> datetime | None:
    """Parse an ISO 8601 UTC timestamp string into a timezone-aware datetime."""
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is in a private/RFC-1918 range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def is_valid_ipv4(ip_str: str) -> bool:
    """Return True only for well-formed IPv4 addresses."""
    try:
        ipaddress.IPv4Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_ip(ip_str: str) -> bool:
    """Return True for any valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def load_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    """
    Load a JSONL file.
    Returns (records, parse_errors) where parse_errors lists lines that failed.
    """
    records, errors = [], []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                errors.append(f"Line {lineno}: {exc}")
    return records, errors


# ── Issue builder ──────────────────────────────────────────────────────────────

def _issue(line_number: int, check_type: str, severity: str, description: str, action: str) -> dict:
    return {
        "line_number": line_number,
        "check_type": check_type,
        "severity": severity,
        "description": description,
        "recommended_action": action,
    }


# ── Check 1: Missing critical fields ──────────────────────────────────────────

def check_missing_fields(records: list[dict]) -> list[dict]:
    issues = []
    for i, rec in enumerate(records, start=1):
        missing = [f for f in CRITICAL_FIELDS if not rec.get(f)]
        if missing:
            issues.append(_issue(
                i, "Missing Fields", "ERROR",
                f"Missing or null critical fields: {', '.join(missing)}",
                "Fix log source or parser to ensure all critical fields are populated.",
            ))
    return issues


# ── Check 2: Invalid IP addresses ─────────────────────────────────────────────

def check_ip_validation(records: list[dict]) -> list[dict]:
    issues = []
    for i, rec in enumerate(records, start=1):
        for field in ("source_ip", "target_ip"):
            ip = rec.get(field)
            if not ip:
                continue
            if not is_valid_ip(ip):
                issues.append(_issue(
                    i, "IP Validation", "ERROR",
                    f"{field} '{ip}' is not a valid IPv4 or IPv6 address.",
                    f"Verify {field} extraction logic in the parser.",
                ))
            elif is_private_ip(ip):
                issues.append(_issue(
                    i, "IP Validation", "WARNING",
                    f"{field} '{ip}' is a private/RFC-1918 IP address in log_type='{rec.get('log_type')}'.",
                    "Confirm whether this is an internal-facing log; private IPs may be unexpected in external-facing records.",
                ))
    return issues


# ── Check 3: Timestamp anomalies ──────────────────────────────────────────────

def check_timestamp_anomalies(records: list[dict]) -> list[dict]:
    issues = []
    now = datetime.now(timezone.utc)
    for i, rec in enumerate(records, start=1):
        ts_str = rec.get("timestamp")
        if not ts_str:
            # Already caught by check 1 if timestamp is critical; but still note it
            issues.append(_issue(
                i, "Timestamp Anomaly", "ERROR",
                "Timestamp field is missing or empty.",
                "Ensure the parser correctly extracts and normalizes timestamps.",
            ))
            continue
        dt = parse_ts(ts_str)
        if dt is None:
            issues.append(_issue(
                i, "Timestamp Anomaly", "ERROR",
                f"Timestamp '{ts_str}' cannot be parsed as ISO 8601.",
                "Normalize all timestamps to YYYY-MM-DDTHH:MM:SSZ format.",
            ))
            continue
        if dt > now:
            issues.append(_issue(
                i, "Timestamp Anomaly", "WARNING",
                f"Timestamp '{ts_str}' is in the future (now={now.strftime('%Y-%m-%dT%H:%M:%SZ')}).",
                "Verify system clock on log source; investigate potential clock skew.",
            ))
        elif dt < ONE_YEAR_AGO:
            issues.append(_issue(
                i, "Timestamp Anomaly", "WARNING",
                f"Timestamp '{ts_str}' is older than 1 year.",
                "Confirm log retention policy; stale logs may indicate replay or ingestion delay.",
            ))
    return issues


# ── Check 4: Duplicate detection ─────────────────────────────────────────────

def check_duplicates(records: list[dict]) -> list[dict]:
    seen: dict[str, int] = {}          # event_id -> first line_number
    issues = []
    for i, rec in enumerate(records, start=1):
        eid = rec.get("event_id")
        if not eid:
            continue
        if eid in seen:
            issues.append(_issue(
                i, "Duplicate Detection", "ERROR",
                f"Duplicate event_id '{eid}' first seen at line {seen[eid]}.",
                "Investigate log source for double-submission or de-duplication failure.",
            ))
        else:
            seen[eid] = i
    return issues


# ── Check 5: Suspicious patterns ─────────────────────────────────────────────

def check_suspicious_patterns(records: list[dict]) -> list[dict]:
    issues = []
    prev_ts: datetime | None = None
    prev_line = 0

    for i, rec in enumerate(records, start=1):
        action = (rec.get("action") or "").upper()
        status = (rec.get("status") or "").lower()

        # 5a. Impossible action/status combination
        if (action, status) in IMPOSSIBLE_COMBOS:
            issues.append(_issue(
                i, "Suspicious Pattern", "WARNING",
                f"Impossible combination: action='{action}', status='{status}'.",
                "Review parser logic for correct action/status normalization.",
            ))

        # 5b. Extreme byte counts (if present in original line)
        orig = rec.get("original_line", "")
        import re
        byte_match = re.search(r",(-?\d+)\s*$", orig)
        if byte_match:
            byte_val = int(byte_match.group(1))
            if byte_val < 0:
                issues.append(_issue(
                    i, "Suspicious Pattern", "WARNING",
                    f"Negative byte count ({byte_val}) in record.",
                    "Verify byte counter in log source; wrap-around or corruption suspected.",
                ))
            elif byte_val > MAX_BYTES:
                issues.append(_issue(
                    i, "Suspicious Pattern", "WARNING",
                    f"Extreme byte count ({byte_val:,}) exceeds 1 TB.",
                    "Confirm traffic volume; possible byte counter overflow or data exfiltration.",
                ))

        # 5c. Rapid sequential events (< 1 s apart)
        ts_str = rec.get("timestamp")
        if ts_str:
            curr_ts = parse_ts(ts_str)
            if curr_ts and prev_ts:
                delta = abs((curr_ts - prev_ts).total_seconds())
                if delta < 1.0:
                    issues.append(_issue(
                        i, "Suspicious Pattern", "INFO",
                        f"Rapid sequential event: {delta:.3f}s after line {prev_line}.",
                        "Verify whether this is expected high-frequency traffic or a scan/flood.",
                    ))
            if curr_ts:
                prev_ts = curr_ts
                prev_line = i

    return issues


# ── Aggregate & report ────────────────────────────────────────────────────────

def run_all_checks(records: list[dict]) -> dict:
    """Run all five checks and return a structured result dict."""
    checks = {
        "Missing Fields":        check_missing_fields(records),
        "IP Validation":         check_ip_validation(records),
        "Timestamp Anomalies":   check_timestamp_anomalies(records),
        "Duplicate Detection":   check_duplicates(records),
        "Suspicious Patterns":   check_suspicious_patterns(records),
    }
    all_issues = [iss for grp in checks.values() for iss in grp]
    return {"checks": checks, "all_issues": all_issues}


def count_severity(issues: list[dict], severity: str) -> int:
    return sum(1 for iss in issues if iss["severity"] == severity)


# ── Console report ─────────────────────────────────────────────────────────────

def print_console_report(records: list[dict], result: dict, input_name: str) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    all_issues = result["all_issues"]
    total = len(records)
    err_count  = count_severity(all_issues, "ERROR")
    warn_count = count_severity(all_issues, "WARNING")
    info_count = count_severity(all_issues, "INFO")

    # Lines that have at least one ERROR
    error_lines: set[int] = {iss["line_number"] for iss in all_issues if iss["severity"] == "ERROR"}
    valid_count = total - len(error_lines)

    border = "═" * 54
    print(f"\n{border}")
    print("DATA QUALITY VALIDATION REPORT")
    print(f"Generated: {now_str}")
    print(f"Input:     {input_name}")
    print(border)

    check_names = list(result["checks"].keys())
    for idx, name in enumerate(check_names, start=1):
        issues = result["checks"][name]
        err = count_severity(issues, "ERROR")
        warn = count_severity(issues, "WARNING")
        info = count_severity(issues, "INFO")
        total_issues = err + warn + info

        if err:
            verdict = "ERROR"
        elif warn:
            verdict = "WARNING"
        else:
            verdict = "PASS"

        detail = f"({total - total_issues}/{total} records clean)"
        if err:
            # Collect duplicate lines for quick summary
            dup_lines = [str(iss["line_number"]) for iss in issues if iss["severity"] == "ERROR"][:5]
            detail = f"({err} error(s): lines {', '.join(dup_lines)}{'...' if len(dup_lines) == 5 else ''})"
        elif warn:
            detail = f"({warn} warning(s))"

        print(f"Check {idx}: {name:<25} {verdict:<8} {detail}")

    print(f"\n{'─'*54}")
    print("SUMMARY:")
    print(f"  Total Records : {total}")
    print(f"  Valid Records : {valid_count}")
    print(f"  Errors        : {err_count}")
    print(f"  Warnings      : {warn_count}")
    print(f"  Info          : {info_count}")

    if all_issues:
        print("\nTop Recommendations:")
        seen_types: set[str] = set()
        for iss in all_issues:
            ct = iss["check_type"]
            if ct not in seen_types:
                print(f"  • {iss['recommended_action']}")
                seen_types.add(ct)
    print(f"{border}\n")


# ── CSV report ─────────────────────────────────────────────────────────────────

def write_csv_report(all_issues: list[dict], output_path: Path) -> None:
    fieldnames = ["line_number", "check_type", "severity", "description", "recommended_action"]
    with output_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for iss in sorted(all_issues, key=lambda x: x["line_number"]):
            writer.writerow(iss)


# ── JSON summary ───────────────────────────────────────────────────────────────

def write_json_summary(records: list[dict], result: dict, output_path: Path) -> None:
    all_issues = result["all_issues"]
    total = len(records)
    err_count  = count_severity(all_issues, "ERROR")
    warn_count = count_severity(all_issues, "WARNING")
    info_count = count_severity(all_issues, "INFO")
    error_lines = {iss["line_number"] for iss in all_issues if iss["severity"] == "ERROR"}
    valid_count = total - len(error_lines)

    by_check: dict[str, dict] = {}
    for name, issues in result["checks"].items():
        by_check[name] = {
            "errors":   count_severity(issues, "ERROR"),
            "warnings": count_severity(issues, "WARNING"),
            "info":     count_severity(issues, "INFO"),
            "pass":     count_severity(issues, "ERROR") == 0,
        }

    summary = {
        "generated_at":   datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_records":  total,
        "valid_records":  valid_count,
        "error_count":    err_count,
        "warning_count":  warn_count,
        "info_count":     info_count,
        "by_check":       by_check,
    }
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Data quality validator for normalized JSONL security logs"
    )
    p.add_argument("--input", "-i", required=True, help="JSONL file to validate")
    p.add_argument("--csv", default="sample_validation_report.csv",
                   help="CSV report output path (default: sample_validation_report.csv)")
    p.add_argument("--json", default="sample_validation_summary.json",
                   help="JSON summary output path (default: sample_validation_summary.json)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        return 1

    records, parse_errors = load_jsonl(input_path)
    if parse_errors:
        for err in parse_errors:
            print(f"[WARN] JSON parse error — {err}", file=sys.stderr)

    result = run_all_checks(records)

    # Console
    print_console_report(records, result, input_path.name)

    # CSV
    csv_path = Path(args.csv)
    write_csv_report(result["all_issues"], csv_path)
    print(f"CSV report  → {csv_path}")

    # JSON
    json_path = Path(args.json)
    write_json_summary(records, result, json_path)
    print(f"JSON summary → {json_path}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
