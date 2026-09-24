#!/usr/bin/env python3
"""
ingest_logs.py — Module 1: Data Ingestion Layer
================================================
AI Security Automation Platform
Author: Muhammad Huzaif Amir

Collects logs from multiple sources (log files, API endpoints, streaming
simulation), normalises every record to a common JSON schema, and writes
normalised events to a JSONL processing queue consumed by downstream modules.

Usage
-----
    python ingest_logs.py                    # single run, all enabled sources
    python ingest_logs.py --source file      # file sources only
    python ingest_logs.py --source stream    # streaming simulation only
    python ingest_logs.py --stream-duration 30  # stream for 30 seconds
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import _pathfix  # noqa: F401 — fixes platform.py vs stdlib shadow
import pandas as pd
import yaml

# ─────────────────────────────────────────────────────────────
# Bootstrap — must run before any platform-internal imports so
# that the logger is configured for all submodules too.
# ─────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"


def load_config(path: Path = CONFIG_PATH) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def setup_logging(cfg: dict) -> logging.Logger:
    log_cfg = cfg.get("logging", {})
    log_file = BASE_DIR / log_cfg.get("file", "logs/platform.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file),
        ],
    )
    return logging.getLogger("ingest")


# ─────────────────────────────────────────────────────────────
# Common schema
# ─────────────────────────────────────────────────────────────
COMMON_SCHEMA = {
    "event_id": None,
    "timestamp": None,
    "source_type": None,   # file | api | stream
    "src_ip": None,
    "dst_ip": None,
    "src_port": None,
    "dst_port": None,
    "protocol": None,
    "bytes_sent": None,
    "bytes_recv": None,
    "duration": None,      # seconds
    "label": "unknown",
    "raw": None,
}

# Realistic public IP pools for simulation
_PUBLIC_IPS = [
    "45.33.32.156", "192.241.200.10", "185.220.101.34",
    "23.129.64.214", "198.51.100.42", "203.0.113.99",
    "8.8.8.8", "1.1.1.1", "104.21.0.1", "172.67.182.3",
    "91.108.4.1", "149.154.167.92", "192.168.10.5",
    "10.0.0.23", "172.16.5.100",
]

_ATTACK_TYPES = [
    "DoS", "PortScan", "BruteForce", "WebAttack", "Botnet",
    "Infiltration", "C2", "Exfiltration",
]


# ─────────────────────────────────────────────────────────────
# Normalisation helpers
# ─────────────────────────────────────────────────────────────

def _new_event_id() -> str:
    return str(uuid.uuid4())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_record(raw: dict, source_type: str = "file") -> dict:
    """Map an arbitrary raw record onto the common schema."""
    ev = dict(COMMON_SCHEMA)
    ev["event_id"] = _new_event_id()
    ev["source_type"] = source_type
    ev["raw"] = json.dumps(raw)

    # timestamp — try several common field names
    for ts_field in ("timestamp", "time", "ts", "datetime", "date"):
        if ts_field in raw:
            ev["timestamp"] = str(raw[ts_field])
            break
    if not ev["timestamp"]:
        ev["timestamp"] = _now_iso()

    # network fields
    for src in ("src_ip", "source_ip", "srcip", "src", "client_ip"):
        if src in raw:
            ev["src_ip"] = str(raw[src])
            break
    for dst in ("dst_ip", "dest_ip", "dstip", "dst", "server_ip", "remote_ip"):
        if dst in raw:
            ev["dst_ip"] = str(raw[dst])
            break
    for sp in ("src_port", "source_port", "sport"):
        if sp in raw:
            ev["src_port"] = int(raw[sp]) if raw[sp] is not None else None
            break
    for dp in ("dst_port", "dest_port", "dport", "port"):
        if dp in raw:
            ev["dst_port"] = int(raw[dp]) if raw[dp] is not None else None
            break
    for pr in ("protocol", "proto"):
        if pr in raw:
            ev["protocol"] = str(raw[pr]).upper()
            break

    for bs in ("bytes_sent", "sbytes", "total_fwd_bytes", "tx_bytes"):
        if bs in raw:
            ev["bytes_sent"] = int(float(raw[bs])) if raw[bs] is not None else 0
            break
    for br in ("bytes_recv", "dbytes", "total_bwd_bytes", "rx_bytes"):
        if br in raw:
            ev["bytes_recv"] = int(float(raw[br])) if raw[br] is not None else 0
            break
    for dur in ("duration", "dur", "flow_duration"):
        if dur in raw:
            ev["duration"] = float(raw[dur]) if raw[dur] is not None else 0.0
            break

    for lbl in ("label", "label_binary", "attack_type", "category", "class"):
        if lbl in raw:
            ev["label"] = str(raw[lbl])
            break

    return ev


# ─────────────────────────────────────────────────────────────
# Source readers
# ─────────────────────────────────────────────────────────────

def read_json_file(path: Path, log: logging.Logger) -> Iterator[dict]:
    """Read a JSON or JSONL log file."""
    try:
        text = path.read_text()
        try:
            data = json.loads(text)
            items = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # try JSONL
            items = [json.loads(line) for line in text.splitlines() if line.strip()]
        log.info("Read %d records from %s", len(items), path)
        yield from items
    except Exception as exc:
        log.error("Failed to read %s: %s", path, exc)


def read_csv_file(path: Path, log: logging.Logger) -> Iterator[dict]:
    """Read a CSV network-flow log file (chunk-by-chunk for large files)."""
    try:
        chunk_size = 1000
        total = 0
        for chunk in pd.read_csv(path, chunksize=chunk_size, low_memory=False):
            chunk = chunk.fillna("")
            for _, row in chunk.iterrows():
                yield row.to_dict()
            total += len(chunk)
        log.info("Read %d records from %s", total, path)
    except Exception as exc:
        log.error("Failed to read CSV %s: %s", path, exc)


def simulate_stream(interval: float, log: logging.Logger) -> Iterator[dict]:
    """Generate a single realistic network-flow event (streaming simulation)."""
    is_attack = random.random() < 0.18
    label = random.choice(_ATTACK_TYPES) if is_attack else "Benign"
    event = {
        "timestamp": _now_iso(),
        "src_ip": random.choice(_PUBLIC_IPS),
        "dst_ip": random.choice(_PUBLIC_IPS),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 22, 25, 53, 3389, 8080, 3306]),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "bytes_sent": random.randint(200, 500_000) if is_attack else random.randint(64, 5000),
        "bytes_recv": random.randint(100, 200_000) if is_attack else random.randint(64, 3000),
        "duration": round(random.uniform(0.001, 30.0), 3),
        "label": label,
    }
    log.debug("Stream event: %s | %s -> %s | label=%s",
              event["timestamp"], event["src_ip"], event["dst_ip"], label)
    yield event


# ─────────────────────────────────────────────────────────────
# Queue writer
# ─────────────────────────────────────────────────────────────

def write_to_queue(events: list[dict], queue_path: Path, log: logging.Logger) -> int:
    """Append normalised events to the JSONL processing queue."""
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(queue_path, "a") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
            count += 1
    log.info("Wrote %d events to queue: %s", count, queue_path)
    return count


# ─────────────────────────────────────────────────────────────
# Sample data generator (creates demo files if they don't exist)
# ─────────────────────────────────────────────────────────────

def generate_sample_data(base_dir: Path, log: logging.Logger) -> None:
    """Generate sample log files for demonstration if they don't exist."""
    data_dir = base_dir / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    json_path = data_dir / "sample_logs.json"
    if not json_path.exists():
        records = []
        for _ in range(200):
            is_attack = random.random() < 0.20
            records.append({
                "timestamp": _now_iso(),
                "src_ip": random.choice(_PUBLIC_IPS),
                "dst_ip": random.choice(_PUBLIC_IPS),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 25, 53]),
                "protocol": random.choice(["TCP", "UDP"]),
                "bytes_sent": random.randint(100, 100000),
                "bytes_recv": random.randint(100, 50000),
                "duration": round(random.uniform(0.01, 10.0), 3),
                "label": random.choice(_ATTACK_TYPES) if is_attack else "Benign",
            })
        json_path.write_text(json.dumps(records, indent=2))
        log.info("Created sample JSON log: %s (%d records)", json_path, len(records))


# ─────────────────────────────────────────────────────────────
# Main ingestion pipeline
# ─────────────────────────────────────────────────────────────

def run_ingestion(cfg: dict, source_filter: str | None,
                  stream_duration: int, log: logging.Logger) -> int:
    """
    Run the ingestion pipeline.
    Returns total number of events written to the queue.
    """
    ingest_cfg = cfg.get("ingestion", {})
    queue_path = BASE_DIR / ingest_cfg.get("output_queue", "data/ingestion_queue.jsonl")
    batch_size = ingest_cfg.get("batch_size", 100)
    sources = ingest_cfg.get("sources", [])

    generate_sample_data(BASE_DIR, log)

    total_written = 0
    batch: list[dict] = []

    def flush(b: list) -> None:
        nonlocal total_written
        total_written += write_to_queue(b, queue_path, log)
        b.clear()

    # ── File / CSV sources ────────────────────────────────────
    if source_filter in (None, "file"):
        for src in sources:
            if not src.get("enabled", True):
                continue
            if src["type"] not in ("file", "csv"):
                continue
            path = BASE_DIR / src["path"]
            if not path.exists():
                log.warning("Source path not found: %s — skipping", path)
                continue

            reader = read_csv_file if path.suffix.lower() == ".csv" else read_json_file
            for raw in reader(path, log):
                ev = normalize_record(raw, source_type="file")
                batch.append(ev)
                if len(batch) >= batch_size:
                    flush(batch)
        if batch:
            flush(batch)

    # ── Streaming simulation ──────────────────────────────────
    if source_filter in (None, "stream"):
        stream_src = next(
            (s for s in sources if s["type"] == "stream" and s.get("enabled", True)),
            None,
        )
        if stream_src:
            interval = stream_src.get("interval_seconds", 5)
            log.info("Streaming simulation started — duration=%ds interval=%ds",
                     stream_duration, interval)
            deadline = time.time() + stream_duration
            while time.time() < deadline:
                for raw in simulate_stream(interval, log):
                    ev = normalize_record(raw, source_type="stream")
                    batch.append(ev)
                if len(batch) >= batch_size:
                    flush(batch)
                time.sleep(interval)
            if batch:
                flush(batch)

    log.info("Ingestion complete — total events queued: %d", total_written)
    return total_written


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Module 1 — Data Ingestion Layer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.yaml")
    p.add_argument("--source", choices=["file", "stream"],
                   help="Limit to a specific source type (default: all)")
    p.add_argument("--stream-duration", type=int, default=15,
                   help="How long (seconds) to run the streaming simulation")
    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(Path(args.config))
    log = setup_logging(cfg)
    log.info("=" * 60)
    log.info("AI Security Automation Platform — Data Ingestion Layer")
    log.info("=" * 60)
    n = run_ingestion(cfg, args.source, args.stream_duration, log)
    print(f"\n✅  Ingestion complete — {n} events written to queue.")


if __name__ == "__main__":
    main()
