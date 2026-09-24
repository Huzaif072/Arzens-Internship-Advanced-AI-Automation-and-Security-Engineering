#!/usr/bin/env python3
"""
platform.py — Main Orchestrator
================================
AI Security Automation Platform
Author: Muhammad Huzaif Amir

Runs all 5 modules as an integrated pipeline.

Modes
-----
    python platform.py --mode full          # run all modules end-to-end
    python platform.py --mode ingest        # ingestion only
    python platform.py --mode enrich        # TI enrichment only
    python platform.py --mode detect        # ML detection only
    python platform.py --mode soar          # SOAR only
    python platform.py --mode dashboard     # launch dashboard
    python platform.py --mode status        # show pipeline health

Options
-------
    --stream-duration N   seconds to run streaming simulation (default 15)
    --loop                continuous mode (re-runs every N seconds)
    --loop-interval N     seconds between loop iterations (default 30)
    --config PATH         path to config.yaml
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"


# ─────────────────────────────────────────────────────────────
# Bootstrap logging
# ─────────────────────────────────────────────────────────────

def _setup_root_logging(cfg: dict) -> logging.Logger:
    log_cfg = cfg.get("logging", {})
    log_file = BASE_DIR / log_cfg.get("file", "logs/platform.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)

    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"

    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(logging.StreamHandler(sys.stdout))
        root.addHandler(logging.FileHandler(log_file))
    for h in root.handlers:
        h.setFormatter(logging.Formatter(fmt))

    return logging.getLogger("platform")


# ─────────────────────────────────────────────────────────────
# Module runners
# ─────────────────────────────────────────────────────────────

def run_ingestion(cfg: dict, stream_duration: int, log: logging.Logger) -> int:
    """Module 1: Data Ingestion."""
    from ingest_logs import run_ingestion as _run, setup_logging
    setup_logging(cfg)
    n = _run(cfg, source_filter=None, stream_duration=stream_duration, log=log)
    return n


def run_enrichment(cfg: dict, log: logging.Logger) -> list[dict]:
    """Module 2: Threat Intelligence Enrichment."""
    from ti_enricher import TIEnricher
    enricher = TIEnricher(cfg)
    queue_path = BASE_DIR / cfg["ingestion"]["output_queue"]
    out_path = BASE_DIR / "data" / "enriched_queue.jsonl"
    return enricher.enrich_queue(queue_path, out_path)


def run_detection(cfg: dict, log: logging.Logger) -> list[dict]:
    """Module 3: ML Detection."""
    from ml_detector import MLDetector
    detector = MLDetector(cfg)
    in_path = BASE_DIR / "data" / "enriched_queue.jsonl"
    if not in_path.exists():
        in_path = BASE_DIR / cfg["ingestion"]["output_queue"]
    out_path = BASE_DIR / "data" / "scored_events.jsonl"
    return detector.score_queue(in_path, out_path)


def run_soar(cfg: dict, log: logging.Logger) -> list[dict]:
    """Module 4: SOAR Orchestration."""
    from soar_engine import SOAREngine
    engine = SOAREngine(cfg)
    in_path = BASE_DIR / "data" / "scored_events.jsonl"
    cases = engine.process_queue(in_path)
    engine.print_stats()
    return cases


def launch_dashboard(cfg: dict, log: logging.Logger) -> None:
    """Module 5: Launch Streamlit dashboard."""
    dash_cfg = cfg.get("dashboard", {})
    port = dash_cfg.get("port", 8501)
    host = dash_cfg.get("host", "0.0.0.0")
    dashboard_path = BASE_DIR / "dashboard.py"

    log.info("Launching dashboard on http://%s:%d …", host, port)
    cmd = [
        sys.executable, "-m", "streamlit", "run",
        str(dashboard_path),
        "--server.port", str(port),
        "--server.address", host,
        "--server.headless", "true",
        "--theme.base", "dark",
    ]
    subprocess.run(cmd)


# ─────────────────────────────────────────────────────────────
# Status reporter
# ─────────────────────────────────────────────────────────────

def show_status(cfg: dict, log: logging.Logger) -> None:
    import json
    print("\n" + "═" * 65)
    print("  AI Security Automation Platform — Pipeline Status")
    print("═" * 65)

    files = {
        "Ingestion Queue":  BASE_DIR / cfg["ingestion"]["output_queue"],
        "Enriched Queue":   BASE_DIR / "data" / "enriched_queue.jsonl",
        "Scored Events":    BASE_DIR / "data" / "scored_events.jsonl",
        "Cases":            BASE_DIR / "alerts" / "cases.json",
        "Analyst Queue":    BASE_DIR / "alerts" / "analyst_queue.json",
        "Blocked IPs":      BASE_DIR / "alerts" / "blocked_ips.json",
        "TI Cache":         BASE_DIR / cfg["threat_intel"]["cache_file"],
    }

    for label, path in files.items():
        if path.exists():
            size = path.stat().st_size
            try:
                if path.suffix == ".jsonl":
                    count = sum(1 for _ in open(path))
                elif path.suffix == ".json":
                    data = json.loads(path.read_text())
                    count = len(data) if isinstance(data, list) else 1
                else:
                    count = "?"
            except Exception:
                count = "?"
            print(f"  ✅  {label:20s} {path.name:35s} [{count} records, {size//1024}KB]")
        else:
            print(f"  ❌  {label:20s} {str(path.name):35s} [NOT FOUND]")

    print("═" * 65 + "\n")


# ─────────────────────────────────────────────────────────────
# Full pipeline
# ─────────────────────────────────────────────────────────────

def run_full_pipeline(cfg: dict, stream_duration: int, log: logging.Logger) -> None:
    start = time.time()

    print("\n" + "█" * 65)
    print("  🛡️  AI SECURITY AUTOMATION PLATFORM — FULL PIPELINE")
    print("█" * 65 + "\n")

    # Module 1 — Ingestion
    _section("MODULE 1 · Data Ingestion")
    n_events = run_ingestion(cfg, stream_duration, log)
    _ok(f"Ingested {n_events} events")

    # Module 2 — TI Enrichment
    _section("MODULE 2 · Threat Intelligence Enrichment")
    enriched = run_enrichment(cfg, log)
    _ok(f"Enriched {len(enriched)} events")

    # Module 3 — ML Detection
    _section("MODULE 3 · ML Anomaly Detection")
    scored = run_detection(cfg, log)
    n_alerts = sum(1 for e in scored if e.get("ml_alert"))
    _ok(f"Scored {len(scored)} events → {n_alerts} alerts raised")

    # Module 4 — SOAR
    _section("MODULE 4 · SOAR Orchestration")
    cases = run_soar(cfg, log)
    _ok(f"Created/updated {len(cases)} SOAR cases")

    elapsed = time.time() - start
    print("\n" + "█" * 65)
    print(f"  ✅  Pipeline complete in {elapsed:.1f}s")
    print("  💡  Launch dashboard: streamlit run dashboard.py")
    print("█" * 65 + "\n")


def _section(title: str) -> None:
    print(f"\n{'─'*65}")
    print(f"  ▶  {title}")
    print(f"{'─'*65}")


def _ok(msg: str) -> None:
    print(f"     ✅  {msg}")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AI Security Automation Platform — Main Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--mode",
        choices=["full", "ingest", "enrich", "detect", "soar", "dashboard", "status"],
        default="full",
        help="Which module(s) to run",
    )
    p.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.yaml")
    p.add_argument("--stream-duration", type=int, default=15,
                   help="Streaming simulation duration (seconds)")
    p.add_argument("--loop", action="store_true",
                   help="Run full pipeline in a continuous loop")
    p.add_argument("--loop-interval", type=int, default=30,
                   help="Seconds between loop iterations")
    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg_path = Path(args.config)
    with open(cfg_path) as fh:
        cfg = yaml.safe_load(fh)

    log = _setup_root_logging(cfg)
    log.info("Platform starting — mode=%s", args.mode)

    def run_once():
        if args.mode == "full":
            run_full_pipeline(cfg, args.stream_duration, log)
        elif args.mode == "ingest":
            n = run_ingestion(cfg, args.stream_duration, log)
            print(f"✅  Ingested {n} events.")
        elif args.mode == "enrich":
            ev = run_enrichment(cfg, log)
            print(f"✅  Enriched {len(ev)} events.")
        elif args.mode == "detect":
            sc = run_detection(cfg, log)
            print(f"✅  Scored {len(sc)} events.")
        elif args.mode == "soar":
            cases = run_soar(cfg, log)
            print(f"✅  {len(cases)} SOAR cases created.")
        elif args.mode == "dashboard":
            launch_dashboard(cfg, log)
        elif args.mode == "status":
            show_status(cfg, log)

    if args.loop and args.mode == "full":
        iteration = 0
        while True:
            iteration += 1
            print(f"\n{'═'*65}")
            print(f"  🔁  Loop iteration {iteration} — {datetime.now(timezone.utc).isoformat()}")
            print(f"{'═'*65}")
            try:
                run_once()
            except Exception as exc:
                log.error("Pipeline error in iteration %d: %s", iteration, exc)
            print(f"\n   ⏱  Next run in {args.loop_interval}s …")
            time.sleep(args.loop_interval)
    else:
        run_once()


if __name__ == "__main__":
    main()
