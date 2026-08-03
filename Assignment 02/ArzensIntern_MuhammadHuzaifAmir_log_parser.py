"""
log_parser.py — Multi-Format Security Log Parser
Parses firewall (CSV), authentication (space-delimited), and DNS (key-value) logs
into a normalized JSONL output.

Usage:
    python log_parser.py --input <logfile> --format <firewall|auth|dns> --output <output.jsonl>
    python log_parser.py --input sample_firewall_logs.csv --format firewall --output output_normalized.jsonl
    python log_parser.py --auto-detect --input <logfile> --output <output.jsonl>
"""

import argparse
import csv
import ipaddress
import json
import logging
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ── Logging setup ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)


# ── IP validation ──────────────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 or IPv6 address."""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def normalize_ip(ip: str) -> str | None:
    """Return a cleaned IP string or None if invalid/absent."""
    if not ip:
        return None
    ip = ip.strip()
    return ip if is_valid_ip(ip) else None


# ── Timestamp normalization ────────────────────────────────────────────────────

_TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",       # ISO 8601 UTC with Z
    "%Y-%m-%dT%H:%M:%S",        # ISO 8601 no TZ
    "%Y-%m-%d %H:%M:%S",        # space-separated
    "%Y-%m-%dT%H:%M:%S%z",      # ISO 8601 with offset
    "%d/%b/%Y:%H:%M:%S %z",     # Apache-style
]


def normalize_timestamp(raw: str) -> str | None:
    """
    Parse *raw* into a UTC ISO 8601 string (YYYY-MM-DDTHH:MM:SSZ).
    Returns None if the string cannot be parsed.
    """
    if not raw:
        return None
    raw = raw.strip()
    for fmt in _TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    logger.warning("Could not parse timestamp: %r", raw)
    return None


def now_utc() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Action / status normalization ─────────────────────────────────────────────

_ACTION_MAP = {
    "allow":    "ALLOW",
    "deny":     "DENY",
    "drop":     "DENY",
    "reject":   "DENY",
    "block":    "DENY",
    "accept":   "ALLOW",
    "permit":   "ALLOW",
    "success":  "SUCCESS",
    "pass":     "SUCCESS",
    "failure":  "FAILURE",
    "fail":     "FAILURE",
    "failed":   "FAILURE",
    "error":    "FAILURE",
    "query":    "QUERY",
    "response": "RESPONSE",
    "nxdomain": "RESPONSE",
    "noerror":  "RESPONSE",
    "servfail": "RESPONSE",
    "refused":  "RESPONSE",
}


def normalize_action(raw: str) -> str:
    """Map a raw action/status string to a canonical verb."""
    if not raw:
        return "UNKNOWN"
    key = raw.strip().lower()
    return _ACTION_MAP.get(key, raw.strip().upper())


def action_to_status(action: str) -> str:
    """Derive a high-level status from a normalized action."""
    if action in ("ALLOW", "SUCCESS", "QUERY", "RESPONSE"):
        return "success"
    if action in ("DENY", "FAILURE"):
        return "failure"
    return "unknown"


# ── Base event builder ─────────────────────────────────────────────────────────

def _base_event(log_type: str, original_line: str) -> dict:
    return {
        "event_id":      str(uuid.uuid4()),
        "timestamp":     None,
        "source_ip":     None,
        "target_ip":     None,
        "user":          None,
        "action":        None,
        "status":        "unknown",
        "log_type":      log_type,
        "original_line": original_line.rstrip("\n"),
        "parsed_at":     now_utc(),
    }


# ── Format parsers ─────────────────────────────────────────────────────────────

def parse_firewall_line(line: str) -> dict | None:
    """
    CSV format: timestamp,src_ip,dst_ip,port,action,bytes
    Example:    2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW,15234
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        # Use csv reader to handle any quoted fields gracefully
        parts = next(csv.reader([line]))
        if len(parts) < 5:
            logger.warning("Firewall line too short, skipping: %r", line)
            return None

        ts_raw, src, dst, _port, action = parts[0], parts[1], parts[2], parts[3], parts[4]
        event = _base_event("firewall", line)
        event["timestamp"] = normalize_timestamp(ts_raw)
        event["source_ip"] = normalize_ip(src)
        event["target_ip"] = normalize_ip(dst)
        event["action"]    = normalize_action(action)
        event["status"]    = action_to_status(event["action"])
        return event
    except Exception as exc:
        logger.warning("Failed to parse firewall line %r: %s", line, exc)
        return None


def parse_auth_line(line: str) -> dict | None:
    """
    Space-delimited: date time user host status source_ip
    Example: 2026-07-15 10:23:45 alice_web corporate-vpn SUCCESS 203.0.113.45
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        parts = line.split()
        if len(parts) < 6:
            logger.warning("Auth line too short, skipping: %r", line)
            return None

        date_part, time_part, user, _host, status, src_ip = (
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        )
        ts_raw = f"{date_part} {time_part}"
        event = _base_event("auth", line)
        event["timestamp"] = normalize_timestamp(ts_raw)
        event["user"]      = user
        event["source_ip"] = normalize_ip(src_ip)
        event["action"]    = normalize_action(status)
        event["status"]    = action_to_status(event["action"])
        return event
    except Exception as exc:
        logger.warning("Failed to parse auth line %r: %s", line, exc)
        return None


_DNS_KV_RE = re.compile(r"(\w+)\s*=\s*([^|]+)")


def parse_dns_line(line: str) -> dict | None:
    """
    Key-value style: query_time=...|client=...|domain=...|type=...|response=...
    Pipes and optional spaces are used as separators.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        kv = {m.group(1).strip(): m.group(2).strip() for m in _DNS_KV_RE.finditer(line)}
        if not kv:
            logger.warning("DNS line has no key-value pairs, skipping: %r", line)
            return None

        event = _base_event("dns", line)
        event["timestamp"] = normalize_timestamp(kv.get("query_time", ""))
        event["source_ip"] = normalize_ip(kv.get("client", ""))

        # Action is derived from the DNS response code
        raw_resp = kv.get("response", "QUERY")
        event["action"] = normalize_action(raw_resp)
        event["status"] = action_to_status(event["action"])

        # Store domain in user field (closest semantic match; no dedicated column)
        event["user"] = kv.get("domain") or None
        return event
    except Exception as exc:
        logger.warning("Failed to parse DNS line %r: %s", line, exc)
        return None


# ── Format auto-detection ──────────────────────────────────────────────────────

def detect_format(line: str) -> str | None:
    """
    Heuristically detect the log format of a single line.
    Returns 'firewall', 'auth', 'dns', or None if unknown.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "query_time=" in line or "client=" in line and "domain=" in line:
        return "dns"
    parts_comma = line.split(",")
    if len(parts_comma) >= 5:
        # First field looks like a timestamp, and 5th looks like an action keyword
        ts_candidate = parts_comma[0].strip()
        if re.match(r"\d{4}-\d{2}-\d{2}", ts_candidate):
            return "firewall"
    parts_space = line.split()
    if len(parts_space) >= 6:
        ts_candidate = f"{parts_space[0]} {parts_space[1]}"
        if re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", ts_candidate):
            return "auth"
    return None


# ── File parsing ───────────────────────────────────────────────────────────────

_PARSERS = {
    "firewall": parse_firewall_line,
    "auth":     parse_auth_line,
    "dns":      parse_dns_line,
}


def parse_file(input_path: Path, fmt: str | None = None) -> list[dict]:
    """
    Parse *input_path* and return a list of normalized event dicts.
    If *fmt* is None, auto-detect per line.
    """
    events: list[dict] = []
    skipped = 0

    with input_path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            if not line.strip() or line.strip().startswith("#"):
                continue

            effective_fmt = fmt or detect_format(line)
            if effective_fmt is None:
                logger.warning("Line %d: format undetectable, skipping: %r", lineno, line)
                skipped += 1
                continue

            parser = _PARSERS.get(effective_fmt)
            if parser is None:
                logger.warning("Line %d: unknown format %r, skipping.", lineno, effective_fmt)
                skipped += 1
                continue

            event = parser(line)
            if event is None:
                skipped += 1
                continue
            events.append(event)

    logger.info("Parsed %d events; skipped %d lines.", len(events), skipped)
    return events


def write_jsonl(events: list[dict], output_path: Path) -> None:
    """Write events to a JSONL file (one JSON object per line)."""
    with output_path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    logger.info("Wrote %d records to %s", len(events), output_path)


# ── CLI ────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Multi-format security log parser → normalized JSONL"
    )
    p.add_argument(
        "--input", "-i",
        required=True,
        help="Path to the input log file",
    )
    p.add_argument(
        "--format", "-f",
        choices=["firewall", "auth", "dns"],
        default=None,
        dest="fmt",
        help="Log format to use. Omit to auto-detect per line.",
    )
    p.add_argument(
        "--output", "-o",
        default="output_normalized.jsonl",
        help="Path for the JSONL output file (default: output_normalized.jsonl)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        logger.error("Input file not found: %s", input_path)
        return 1

    output_path = Path(args.output)
    events = parse_file(input_path, fmt=args.fmt)

    if not events:
        logger.warning("No events were parsed from %s", input_path)

    write_jsonl(events, output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
