#!/usr/bin/env python3
"""Lifecycle manager for enriched IOCs stored in JSON."""

from __future__ import annotations

import argparse
import csv
import html
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ENRICHER_PATH = HERE.parent / "task2" / "ti_enricher.py"
SPEC = importlib.util.spec_from_file_location("ti_enricher", ENRICHER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {ENRICHER_PATH}")
ENRICHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENRICHER)


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.isoformat()


def load_yaml(path: str | Path) -> dict[str, Any]:
    return ENRICHER.load_simple_yaml(path)


def load_db(path: str | Path) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {"schema_version": 1, "updated_at": iso(now()), "iocs": {}}


def save_db(path: str | Path, db: dict[str, Any]) -> None:
    db["updated_at"] = iso(now())
    Path(path).write_text(json.dumps(db, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def confidence(record: dict[str, Any], old: dict[str, Any] | None, cfg: dict[str, Any]) -> int:
    sources = int(record.get("sources_ok", 0))
    diversity = min(40, sources * 20)
    score = record.get("risk_score")
    stability = 30
    if old and isinstance(score, (int, float)):
        history = old.get("score_history", [])
        if history:
            spread = max([float(score), *[float(x) for x in history]]) - min([float(score), *[float(x) for x in history]])
            stability = max(0, 30 - round(spread / 4))
    recency = 30
    if old:
        try:
            age = (now() - datetime.fromisoformat(old["last_seen"])).days
            recency = max(0, 30 - age)
        except (KeyError, ValueError):
            pass
    return max(0, min(100, diversity + stability + recency))


def add_or_update(db: dict[str, Any], record: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    key = record["indicator"]
    old = db.setdefault("iocs", {}).get(key)
    timestamp = iso(now())
    ttl_days = int(cfg.get("expiration_days", 30))
    item = {
        "indicator": key,
        "type": record.get("type", "unknown"),
        "first_seen": old.get("first_seen", timestamp) if old else timestamp,
        "last_seen": timestamp,
        "expiration": iso(now() + timedelta(days=ttl_days)),
        "risk_score": record.get("risk_score"),
        "confidence": confidence(record, old, cfg),
        "status": "active",
        "source_results": record.get("source_results", []),
        "score_history": ((old or {}).get("score_history", []) + ([record["risk_score"]] if isinstance(record.get("risk_score"), (int, float)) else []))[-10:],
    }
    db["iocs"][key] = item
    return item


def import_file(path: str | Path, db: dict[str, Any], cfg: dict[str, Any], offline: bool) -> int:
    config_path = HERE.parent / "task2" / "config.yaml"
    cache_path = HERE.parent / "task2" / "cache.json"
    config = ENRICHER.load_config(config_path)
    count = 0
    with Path(path).open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            indicator = (row.get("indicator") or row.get("ioc") or "").strip()
            if not indicator:
                continue
            try:
                record = ENRICHER.enrich_one(indicator, config, ENRICHER.load_json(cache_path, {"entries": {}, "last_request_epoch": {}}), cache_path, offline=offline)
                add_or_update(db, record, cfg)
                count += 1
            except ValueError as exc:
                print(f"SKIP {indicator}: {exc}", file=sys.stderr)
    return count


def update_all(db: dict[str, Any], cfg: dict[str, Any], offline: bool) -> int:
    config_path = HERE.parent / "task2" / "config.yaml"
    cache_path = HERE.parent / "task2" / "cache.json"
    config = ENRICHER.load_config(config_path)
    updated = 0
    for indicator, old in list(db.get("iocs", {}).items()):
        try:
            record = ENRICHER.enrich_one(indicator, config, ENRICHER.load_json(cache_path, {"entries": {}, "last_request_epoch": {}}), cache_path, offline=offline)
            add_or_update(db, record, cfg)
            updated += 1
        except ValueError:
            old["status"] = "invalid"
    return updated


def expire(db: dict[str, Any]) -> int:
    removed = 0
    current = now()
    for indicator in list(db.get("iocs", {})):
        item = db["iocs"][indicator]
        try:
            if datetime.fromisoformat(item["expiration"]) <= current:
                del db["iocs"][indicator]
                removed += 1
        except (KeyError, ValueError):
            del db["iocs"][indicator]
            removed += 1
    return removed


def export_blocklist(db: dict[str, Any], path: str | Path, threshold: int) -> int:
    values = []
    for indicator, item in sorted(db.get("iocs", {}).items()):
        if item.get("status") == "active" and int(item.get("confidence", 0)) >= threshold:
            values.append(indicator)
    Path(path).write_text("\n".join(values) + ("\n" if values else ""), encoding="utf-8")
    return len(values)


def report(db: dict[str, Any], path: str | Path, health: str) -> None:
    rows = []
    for item in sorted(db.get("iocs", {}).values(), key=lambda x: x["indicator"]):
        rows.append(f"<tr><td>{html.escape(item['indicator'])}</td><td>{html.escape(item.get('type', ''))}</td><td>{item.get('risk_score', '')}</td><td>{item.get('confidence', 0)}</td><td>{html.escape(item.get('expiration', ''))}</td><td>{html.escape(item.get('status', ''))}</td></tr>")
    document = f"""<!doctype html><html><head><meta charset="utf-8"><title>Weekly IOC Report</title>
    <style>body{{font-family:Arial;color:#172033;margin:32px}}h1{{color:#0b2447}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #cbd5e1;padding:7px;text-align:left}}th{{background:#dbeafe}}.health{{padding:10px;background:#dcfce7}}</style></head>
    <body><h1>Weekly IOC Lifecycle Report</h1><p>Generated: {html.escape(ENRICHER.utc_now())}</p>
    <p class="health"><strong>Platform health:</strong> {html.escape(health)} · active IOCs: {len(rows)}</p>
    <table><thead><tr><th>Indicator</th><th>Type</th><th>Risk</th><th>Confidence</th><th>Expiration</th><th>Status</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
    </body></html>"""
    Path(path).write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--add-file")
    actions.add_argument("--update-all", action="store_true")
    actions.add_argument("--expire-check", action="store_true")
    actions.add_argument("--export-blocklist", action="store_true")
    parser.add_argument("--database", default="ioc_database.json")
    parser.add_argument("--config", default="ioc_config.yaml")
    parser.add_argument("--blocklist", default="blocklist.txt")
    parser.add_argument("--report", default="weekly_report.html")
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    cfg = load_yaml(args.config)
    db = load_db(args.database)
    changed = 0
    if args.add_file:
        changed = import_file(args.add_file, db, cfg, args.offline)
    elif args.update_all:
        changed = update_all(db, cfg, args.offline)
    elif args.expire_check:
        changed = expire(db)
    elif args.export_blocklist:
        changed = export_blocklist(db, args.blocklist, int(cfg.get("blocklist_confidence_threshold", 70)))
    save_db(args.database, db)
    health = "healthy" if db.get("iocs") is not None else "degraded"
    report(db, args.report, health)
    print(f"completed; changed={changed}; active_iocs={len(db.get('iocs', {}))}; report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
