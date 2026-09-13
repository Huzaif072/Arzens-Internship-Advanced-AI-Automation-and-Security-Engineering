#!/usr/bin/env python3
"""Multi-source IOC enrichment with caching, rate limiting, and safe failures.

The tool uses only the Python standard library. API keys may be supplied in
config.yaml or through environment variables; placeholders are never sent.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_CONFIG = {
    "virustotal_api_key": "",
    "abuseipdb_api_key": "",
    "otx_api_key": "",
    "cache_ttl_hours": 24,
    "request_timeout_seconds": 12,
    "rate_limit_pause_seconds": 15,
}
PLACEHOLDERS = {"", "YOUR_VIRUSTOTAL_API_KEY", "YOUR_ABUSEIPDB_API_KEY", "YOUR_OTX_API_KEY"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_simple_yaml(path: str | Path) -> dict[str, Any]:
    """Read the flat scalar YAML used by the assignment without dependencies."""
    values: dict[str, Any] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip().strip("'\"")
        if value.lower() in {"true", "false"}:
            values[key.strip()] = value.lower() == "true"
        else:
            try:
                values[key.strip()] = float(value) if "." in value else int(value)
            except ValueError:
                values[key.strip()] = value
    return values


def load_config(path: str | Path) -> dict[str, Any]:
    config = DEFAULT_CONFIG.copy()
    if Path(path).exists():
        config.update(load_simple_yaml(path))
    config["virustotal_api_key"] = os.getenv("VIRUSTOTAL_API_KEY", config["virustotal_api_key"])
    config["abuseipdb_api_key"] = os.getenv("ABUSEIPDB_API_KEY", config["abuseipdb_api_key"])
    config["otx_api_key"] = os.getenv("OTX_API_KEY", config["otx_api_key"])
    return config


def load_json(path: str | Path, default: Any) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path: str | Path, value: Any) -> None:
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def detect_type(indicator: str) -> str:
    value = indicator.strip()
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "sha256"
    if value.startswith(("http://", "https://")):
        return "url"
    if re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}", value):
        return "domain"
    raise ValueError(f"unsupported indicator: {indicator!r}")


def request_json(url: str, headers: dict[str, str], timeout: int) -> tuple[int, Any]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
            return response.status, json.loads(payload)
    except urllib.error.HTTPError as exc:
        try:
            body: Any = json.loads(exc.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            body = {"error": str(exc)}
        return exc.code, body
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return 0, {"error": str(exc)}


def cached(cache: dict[str, Any], key: str, ttl_hours: float) -> Any | None:
    item = cache.get("entries", {}).get(key)
    if not item:
        return None
    if time.time() - float(item.get("saved_epoch", 0)) > ttl_hours * 3600:
        return None
    return item.get("value")


def cache_value(cache: dict[str, Any], key: str, value: Any) -> None:
    cache.setdefault("entries", {})[key] = {"saved_epoch": time.time(), "value": value}


def wait_for_source(cache: dict[str, Any], source: str, pause: float) -> None:
    last = float(cache.setdefault("last_request_epoch", {}).get(source, 0))
    delay = pause - (time.time() - last)
    if delay > 0:
        time.sleep(delay)
    cache["last_request_epoch"][source] = time.time()


def unavailable(source: str, reason: str) -> dict[str, Any]:
    return {"source": source, "status": "unavailable", "reason": reason, "risk": None}


def query_virustotal(indicator: str, kind: str, key: str, cache: dict[str, Any], config: dict[str, Any], offline: bool) -> dict[str, Any]:
    if offline:
        return unavailable("virustotal", "offline mode")
    if key in PLACEHOLDERS:
        return unavailable("virustotal", "API key not configured")
    suffix = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "md5": "files", "sha1": "files", "sha256": "files"}[kind]
    value = indicator
    if kind == "url":
        value = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
    cache_key = f"virustotal:{kind}:{indicator}"
    old = cached(cache, cache_key, config["cache_ttl_hours"])
    if old is not None:
        return {**old, "cached": True}
    wait_for_source(cache, "virustotal", float(config["rate_limit_pause_seconds"]))
    status, body = request_json(f"https://www.virustotal.com/api/v3/{suffix}/{urllib.parse.quote(value, safe='')}", {"x-apikey": key, "accept": "application/json"}, int(config["request_timeout_seconds"]))
    if status != 200 or not isinstance(body, dict):
        return unavailable("virustotal", f"HTTP {status}")
    attrs = body.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values()) or 1
    result = {"source": "virustotal", "status": "ok", "risk": min(100, round((malicious * 100 + suspicious * 40) / total)), "malicious": malicious, "suspicious": suspicious, "cached": False}
    cache_value(cache, cache_key, result)
    return result


def query_abuseipdb(indicator: str, kind: str, key: str, cache: dict[str, Any], config: dict[str, Any], offline: bool) -> dict[str, Any]:
    if kind != "ip":
        return unavailable("abuseipdb", "source supports IP indicators only")
    if offline:
        return unavailable("abuseipdb", "offline mode")
    if key in PLACEHOLDERS:
        return unavailable("abuseipdb", "API key not configured")
    cache_key = f"abuseipdb:{indicator}"
    old = cached(cache, cache_key, config["cache_ttl_hours"])
    if old is not None:
        return {**old, "cached": True}
    wait_for_source(cache, "abuseipdb", float(config["rate_limit_pause_seconds"]))
    query = urllib.parse.urlencode({"ipAddress": indicator, "maxAgeInDays": 90})
    status, body = request_json(f"https://api.abuseipdb.com/api/v2/check?{query}", {"Key": key, "Accept": "application/json"}, int(config["request_timeout_seconds"]))
    if status != 200 or not isinstance(body, dict):
        return unavailable("abuseipdb", f"HTTP {status}")
    data = body.get("data", {})
    confidence = data.get("abuseConfidenceScore")
    if not isinstance(confidence, (int, float)):
        return unavailable("abuseipdb", "invalid response schema")
    result = {"source": "abuseipdb", "status": "ok", "risk": int(confidence), "abuse_confidence": int(confidence), "reports": data.get("totalReports", 0), "cached": False}
    cache_value(cache, cache_key, result)
    return result


def query_otx(indicator: str, kind: str, key: str, cache: dict[str, Any], config: dict[str, Any], offline: bool) -> dict[str, Any]:
    if offline:
        return unavailable("otx", "offline mode")
    if key in PLACEHOLDERS:
        return unavailable("otx", "API key not configured")
    otx_kind = {"ip": "IPv4", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}[kind]
    cache_key = f"otx:{otx_kind}:{indicator}"
    old = cached(cache, cache_key, config["cache_ttl_hours"])
    if old is not None:
        return {**old, "cached": True}
    wait_for_source(cache, "otx", float(config["rate_limit_pause_seconds"]))
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_kind}/{urllib.parse.quote(indicator, safe='')}/general"
    status, body = request_json(url, {"X-OTX-API-KEY": key, "accept": "application/json"}, int(config["request_timeout_seconds"]))
    if status != 200 or not isinstance(body, dict):
        return unavailable("otx", f"HTTP {status}")
    pulses = body.get("pulse_info", {}).get("count", 0)
    if not isinstance(pulses, int):
        return unavailable("otx", "invalid response schema")
    result = {"source": "otx", "status": "ok", "risk": min(100, pulses * 20), "pulse_count": pulses, "cached": False}
    cache_value(cache, cache_key, result)
    return result


def enrich_one(indicator: str, config: dict[str, Any], cache: dict[str, Any], cache_path: str | Path, offline: bool = False) -> dict[str, Any]:
    indicator = indicator.strip()
    kind = detect_type(indicator)
    results = [
        query_virustotal(indicator, kind, str(config["virustotal_api_key"]), cache, config, offline),
        query_abuseipdb(indicator, kind, str(config["abuseipdb_api_key"]), cache, config, offline),
        query_otx(indicator, kind, str(config["otx_api_key"]), cache, config, offline),
    ]
    valid = [item for item in results if item.get("status") == "ok" and isinstance(item.get("risk"), (int, float))]
    risk = round(sum(float(item["risk"]) for item in valid) / len(valid)) if valid else None
    record = {
        "indicator": indicator,
        "type": kind,
        "queried_at": utc_now(),
        "risk_score": risk,
        "sources_ok": len(valid),
        "source_results": results,
        "status": "enriched" if valid else "unavailable",
    }
    save_json(cache_path, cache)
    return record


def read_indicators(args: argparse.Namespace) -> list[str]:
    if bool(args.indicator) == bool(args.input_file):
        raise SystemExit("provide exactly one of --indicator or --input-file")
    if args.indicator:
        return [args.indicator]
    values: list[str] = []
    with Path(args.input_file).open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            value = row.get("indicator") or row.get("ioc") or ""
            if value.strip():
                values.append(value.strip())
    return values


def flat_row(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "indicator": record["indicator"],
        "type": record["type"],
        "queried_at": record["queried_at"],
        "risk_score": "" if record["risk_score"] is None else record["risk_score"],
        "sources_ok": record["sources_ok"],
        "status": record["status"],
    }


def print_table(records: list[dict[str, Any]]) -> None:
    rows = [flat_row(item) for item in records]
    columns = ["indicator", "type", "risk_score", "sources_ok", "status"]
    widths = {column: max(len(column), *(len(str(row[column])) for row in rows)) for column in columns}
    print(" | ".join(column.upper().ljust(widths[column]) for column in columns))
    print("-+-".join("-" * widths[column] for column in columns))
    for row in rows:
        print(" | ".join(str(row[column]).ljust(widths[column]) for column in columns))


def write_output(records: list[dict[str, Any]], output_format: str, output: str | None) -> None:
    if output_format == "table":
        print_table(records)
        return
    if output_format == "json":
        rendered = json.dumps(records, indent=2)
    else:
        fields = ["indicator", "type", "queried_at", "risk_score", "sources_ok", "status"]
        from io import StringIO
        buffer = StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writeheader()
        writer.writerows(flat_row(item) for item in records)
        rendered = buffer.getvalue()
    if output:
        Path(output).write_text(rendered + ("" if rendered.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(rendered)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indicator")
    parser.add_argument("--input-file")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--cache", default="cache.json")
    parser.add_argument("--format", choices=("table", "json", "csv"), default="table")
    parser.add_argument("--output")
    parser.add_argument("--offline", action="store_true", help="validate and format inputs without network calls")
    args = parser.parse_args()
    config = load_config(args.config)
    cache = load_json(args.cache, {"entries": {}, "last_request_epoch": {}})
    records = []
    for indicator in read_indicators(args):
        try:
            records.append(enrich_one(indicator, config, cache, args.cache, args.offline))
        except ValueError as exc:
            records.append({"indicator": indicator, "type": "invalid", "queried_at": utc_now(), "risk_score": None, "sources_ok": 0, "source_results": [], "status": f"invalid: {exc}"})
    write_output(records, args.format, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
