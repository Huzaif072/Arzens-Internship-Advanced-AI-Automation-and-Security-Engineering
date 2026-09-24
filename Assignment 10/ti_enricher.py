#!/usr/bin/env python3
"""
ti_enricher.py — Module 2: Threat Intelligence Enrichment
=========================================================
AI Security Automation Platform
Author: Muhammad Huzaif Amir

Enriches network events with threat intelligence from VirusTotal,
AbuseIPDB, and AlienVault OTX. Results are cached in a local JSON
file (TTL-based). A composite risk score (0–100) is computed for
each indicator and appended to every event.

Usage
-----
    python ti_enricher.py                         # enrich entire queue
    python ti_enricher.py --ip 185.220.101.34     # single IP lookup
    python ti_enricher.py --input events.jsonl    # custom input file
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import _pathfix  # noqa: F401
import requests
import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def load_config(path: Path = CONFIG_PATH) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def get_logger(name: str = "ti_enricher") -> logging.Logger:
    return logging.getLogger(name)


def _now_ts() -> float:
    return time.time()


# ─────────────────────────────────────────────────────────────
# Cache
# ─────────────────────────────────────────────────────────────

class TICache:
    """Simple TTL-based JSON file cache for TI lookups."""

    def __init__(self, cache_path: Path, ttl_seconds: int = 3600):
        self.path = cache_path
        self.ttl = ttl_seconds
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except Exception:
                self._data = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, indent=2))

    def _key(self, source: str, indicator: str) -> str:
        return hashlib.sha256(f"{source}:{indicator}".encode()).hexdigest()[:16]

    def get(self, source: str, indicator: str) -> dict | None:
        k = self._key(source, indicator)
        entry = self._data.get(k)
        if not entry:
            return None
        if _now_ts() - entry.get("cached_at", 0) > self.ttl:
            del self._data[k]
            return None
        return entry.get("data")

    def set(self, source: str, indicator: str, data: dict) -> None:
        k = self._key(source, indicator)
        self._data[k] = {"cached_at": _now_ts(), "data": data}
        self._save()


# ─────────────────────────────────────────────────────────────
# Demo / mock responses (used when API keys are absent)
# ─────────────────────────────────────────────────────────────

# Known-bad IPs for realistic demo
_KNOWN_BAD = {
    "185.220.101.34", "45.33.32.156", "91.108.4.1",
    "149.154.167.92", "23.129.64.214",
}

def _mock_virustotal(ip: str) -> dict:
    bad = ip in _KNOWN_BAD
    malicious = random.randint(5, 25) if bad else random.randint(0, 2)
    return {
        "source": "virustotal",
        "indicator": ip,
        "malicious_votes": malicious,
        "total_engines": 70,
        "categories": ["malware", "phishing"] if bad else [],
        "community_score": -malicious if bad else 0,
        "last_analysis_date": datetime.now(timezone.utc).isoformat(),
        "demo": True,
    }


def _mock_abuseipdb(ip: str) -> dict:
    bad = ip in _KNOWN_BAD
    score = random.randint(60, 100) if bad else random.randint(0, 15)
    return {
        "source": "abuseipdb",
        "indicator": ip,
        "abuse_confidence_score": score,
        "country_code": random.choice(["RU", "CN", "KP", "IR"]) if bad else random.choice(["US", "DE", "FR"]),
        "total_reports": random.randint(50, 500) if bad else random.randint(0, 3),
        "last_reported_at": datetime.now(timezone.utc).isoformat(),
        "is_whitelisted": False,
        "demo": True,
    }


def _mock_alienvault(ip: str) -> dict:
    bad = ip in _KNOWN_BAD
    pulses = random.randint(3, 12) if bad else random.randint(0, 1)
    return {
        "source": "alienvault",
        "indicator": ip,
        "pulse_count": pulses,
        "threat_score": min(100, pulses * 8),
        "malware_families": ["Mirai", "TrickBot"] if bad else [],
        "tags": ["botnet", "scanner"] if bad else [],
        "demo": True,
    }


# ─────────────────────────────────────────────────────────────
# Real API callers
# ─────────────────────────────────────────────────────────────

def query_virustotal(ip: str, api_key: str) -> dict | None:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "source": "virustotal",
            "indicator": ip,
            "malicious_votes": stats.get("malicious", 0),
            "total_engines": sum(stats.values()),
            "categories": list(data["data"]["attributes"].get("categories", {}).values()),
            "community_score": data["data"]["attributes"].get("reputation", 0),
            "last_analysis_date": data["data"]["attributes"].get("last_analysis_date"),
        }
    except Exception as exc:
        get_logger().warning("VirusTotal query failed for %s: %s", ip, exc)
        return None


def query_abuseipdb(ip: str, api_key: str) -> dict | None:
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        d = r.json()["data"]
        return {
            "source": "abuseipdb",
            "indicator": ip,
            "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
            "country_code": d.get("countryCode", ""),
            "total_reports": d.get("totalReports", 0),
            "last_reported_at": d.get("lastReportedAt"),
            "is_whitelisted": d.get("isWhitelisted", False),
        }
    except Exception as exc:
        get_logger().warning("AbuseIPDB query failed for %s: %s", ip, exc)
        return None


def query_alienvault(ip: str, api_key: str) -> dict | None:
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        d = r.json()
        return {
            "source": "alienvault",
            "indicator": ip,
            "pulse_count": d.get("pulse_info", {}).get("count", 0),
            "threat_score": d.get("pulse_info", {}).get("count", 0) * 8,
            "malware_families": [],
            "tags": d.get("tags", []),
        }
    except Exception as exc:
        get_logger().warning("AlienVault query failed for %s: %s", ip, exc)
        return None


# ─────────────────────────────────────────────────────────────
# Risk score calculation
# ─────────────────────────────────────────────────────────────

def calculate_risk_score(vt: dict | None, ab: dict | None, av: dict | None,
                         weights: dict) -> float:
    """
    Composite risk score 0–100.
    Each source contributes a normalised partial score weighted by config.
    """
    scores: list[tuple[float, float]] = []  # (partial_score, weight)

    if vt:
        total = vt.get("total_engines", 70) or 70
        malicious = vt.get("malicious_votes", 0)
        vt_score = min(100.0, (malicious / total) * 200)  # amplified
        scores.append((vt_score, weights.get("virustotal", 0.40)))

    if ab:
        ab_score = float(ab.get("abuse_confidence_score", 0))
        scores.append((ab_score, weights.get("abuseipdb", 0.35)))

    if av:
        pulse_score = min(100.0, av.get("pulse_count", 0) * 10.0)
        scores.append((pulse_score, weights.get("alienvault", 0.25)))

    if not scores:
        return 0.0

    total_weight = sum(w for _, w in scores)
    composite = sum(s * w for s, w in scores) / total_weight
    return round(composite, 2)


# ─────────────────────────────────────────────────────────────
# Enrichment engine
# ─────────────────────────────────────────────────────────────

class TIEnricher:
    def __init__(self, cfg: dict):
        ti_cfg = cfg.get("threat_intel", {})
        self.demo_mode = ti_cfg.get("demo_mode", True)
        self.vt_key = ti_cfg.get("virustotal_api_key", "")
        self.ab_key = ti_cfg.get("abuseipdb_api_key", "")
        self.av_key = ti_cfg.get("alienvault_api_key", "")
        self.weights = ti_cfg.get("risk_score_weights", {})
        self.high_thresh = ti_cfg.get("high_risk_threshold", 70)
        self.med_thresh = ti_cfg.get("medium_risk_threshold", 40)
        cache_path = BASE_DIR / ti_cfg.get("cache_file", "cache/ti_cache.json")
        self.cache = TICache(cache_path, ti_cfg.get("cache_ttl_seconds", 3600))
        self.log = get_logger()

    def _query(self, source: str, ip: str) -> dict | None:
        cached = self.cache.get(source, ip)
        if cached:
            self.log.debug("Cache hit: %s / %s", source, ip)
            return cached

        if self.demo_mode or not all([self.vt_key, self.ab_key, self.av_key]):
            result = {
                "virustotal": _mock_virustotal,
                "abuseipdb": _mock_abuseipdb,
                "alienvault": _mock_alienvault,
            }[source](ip)
        else:
            result = {
                "virustotal": lambda i: query_virustotal(i, self.vt_key),
                "abuseipdb": lambda i: query_abuseipdb(i, self.ab_key),
                "alienvault": lambda i: query_alienvault(i, self.av_key),
            }[source](ip)

        if result:
            self.cache.set(source, ip, result)
        return result

    def enrich_ip(self, ip: str) -> dict:
        """Enrich a single IP address and return the full TI result."""
        if not ip or ip in ("None", "unknown", ""):
            return {"ip": ip, "risk_score": 0, "risk_level": "unknown", "error": "invalid_ip"}

        self.log.info("Enriching IP: %s", ip)
        vt = self._query("virustotal", ip)
        ab = self._query("abuseipdb", ip)
        av = self._query("alienvault", ip)

        risk_score = calculate_risk_score(vt, ab, av, self.weights)
        risk_level = (
            "HIGH" if risk_score >= self.high_thresh else
            "MEDIUM" if risk_score >= self.med_thresh else
            "LOW"
        )

        return {
            "ip": ip,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "virustotal": vt,
            "abuseipdb": ab,
            "alienvault": av,
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

    def enrich_event(self, event: dict) -> dict:
        """Enrich a normalised event record (adds ti_src and ti_dst keys)."""
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")

        event["ti_src"] = self.enrich_ip(src_ip) if src_ip else {}
        event["ti_dst"] = self.enrich_ip(dst_ip) if dst_ip else {}
        event["ti_max_risk"] = max(
            event["ti_src"].get("risk_score", 0),
            event["ti_dst"].get("risk_score", 0),
        )
        event["ti_risk_level"] = (
            "HIGH" if event["ti_max_risk"] >= self.high_thresh else
            "MEDIUM" if event["ti_max_risk"] >= self.med_thresh else
            "LOW"
        )
        return event

    def enrich_queue(self, queue_path: Path, output_path: Path | None = None) -> list[dict]:
        """Enrich every event in a JSONL queue file."""
        if not queue_path.exists():
            self.log.warning("Queue file not found: %s", queue_path)
            return []

        lines = [l for l in queue_path.read_text().splitlines() if l.strip()]
        self.log.info("Enriching %d events from %s", len(lines), queue_path)
        enriched = []
        for line in lines:
            try:
                ev = json.loads(line)
                enriched.append(self.enrich_event(ev))
            except Exception as exc:
                self.log.error("Failed to enrich event: %s", exc)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as fh:
                for ev in enriched:
                    fh.write(json.dumps(ev) + "\n")
            self.log.info("Wrote %d enriched events to %s", len(enriched), output_path)

        return enriched


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Module 2 — Threat Intelligence Enrichment",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", default=str(CONFIG_PATH))
    p.add_argument("--ip", help="Single IP address to look up")
    p.add_argument("--input", help="Input JSONL file to enrich (default: ingestion queue)")
    p.add_argument("--output", help="Output JSONL file for enriched events")
    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(Path(args.config))

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                        stream=sys.stdout)

    enricher = TIEnricher(cfg)

    if args.ip:
        result = enricher.enrich_ip(args.ip)
        print(json.dumps(result, indent=2))
        return

    queue = BASE_DIR / cfg["ingestion"]["output_queue"]
    if args.input:
        queue = Path(args.input)
    out_path = Path(args.output) if args.output else BASE_DIR / "data" / "enriched_queue.jsonl"

    enriched = enricher.enrich_queue(queue, out_path)
    print(f"\n✅  Enriched {len(enriched)} events → {out_path}")

    high = sum(1 for e in enriched if e.get("ti_risk_level") == "HIGH")
    med = sum(1 for e in enriched if e.get("ti_risk_level") == "MEDIUM")
    print(f"   Risk distribution → HIGH: {high}  MEDIUM: {med}  LOW: {len(enriched)-high-med}")


if __name__ == "__main__":
    main()
