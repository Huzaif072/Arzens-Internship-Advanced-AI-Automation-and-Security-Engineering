#!/usr/bin/env python3
"""
ml_detector.py — Module 3: ML Threat Detection
===============================================
AI Security Automation Platform
Author: Muhammad Huzaif Amir

Loads the pre-trained Isolation Forest model (from Assignment 05) and runs
real-time anomaly detection on incoming network-flow events.  Falls back to
training a fresh model on the bundled dataset if the saved model is absent.

Usage
-----
    python ml_detector.py                       # score entire enriched queue
    python ml_detector.py --input events.jsonl  # custom input
    python ml_detector.py --retrain             # force re-train and save
    python ml_detector.py --single '{"dur":0.5,"spkts":10,...}'
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import _pathfix  # noqa: F401
import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"

# ─────────────────────────────────────────────────────────────
# Config & logging
# ─────────────────────────────────────────────────────────────

def load_config(path: Path = CONFIG_PATH) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def get_logger(name: str = "ml_detector") -> logging.Logger:
    return logging.getLogger(name)


# ─────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────

CANONICAL_FEATURES = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate"]

FEATURE_ALIASES = {
    "dur": ["flow_duration", "duration"],
    "spkts": ["total_fwd_packets", "src_pkts", "fwd_packets"],
    "dpkts": ["total_bwd_packets", "dst_pkts", "bwd_packets"],
    "sbytes": ["total_fwd_bytes", "bytes_sent", "src_bytes"],
    "dbytes": ["total_bwd_bytes", "bytes_recv", "dst_bytes"],
    "rate": ["flow_packets_per_sec", "pkt_rate", "packets_per_sec"],
}


def extract_features(record: dict) -> list[float]:
    """
    Extract the 6 canonical features from a raw / normalised event dict.
    Returns [dur, spkts, dpkts, sbytes, dbytes, rate].
    Missing values become 0.0; inf values are clamped to 1e9.
    """
    values = []
    for feat, aliases in FEATURE_ALIASES.items():
        val = record.get(feat)
        if val is None:
            for alias in aliases:
                val = record.get(alias)
                if val is not None:
                    break
        try:
            v = float(val) if val is not None else 0.0
            v = 0.0 if (np.isnan(v) or np.isinf(v)) else min(v, 1e9)
        except (TypeError, ValueError):
            v = 0.0
        values.append(v)
    return values


def features_to_df(records: list[dict]) -> pd.DataFrame:
    rows = [extract_features(r) for r in records]
    return pd.DataFrame(rows, columns=CANONICAL_FEATURES)


# ─────────────────────────────────────────────────────────────
# Model management
# ─────────────────────────────────────────────────────────────

class MLDetector:
    def __init__(self, cfg: dict):
        ml_cfg = cfg.get("ml_detection", {})
        self.model_path = Path(ml_cfg.get("model_path",
                                           "../Assignment 05/outputs/isolation_forest_model.pkl"))
        self.scaler_path = Path(ml_cfg.get("scaler_path",
                                            "../Assignment 05/outputs/standard_scaler.pkl"))
        self.fallback_data = Path(ml_cfg.get(
            "fallback_train_data",
            "../Assignment 05/sample_data/network_traffic_dataset.csv",
        ))
        self.threshold = float(ml_cfg.get("decision_threshold", 0.0))
        self.high_conf_thresh = float(ml_cfg.get("high_confidence_threshold", -0.3))
        self.med_conf_thresh = float(ml_cfg.get("medium_confidence_threshold", 0.0))
        self.contamination = float(ml_cfg.get("contamination", 0.1))
        self.n_estimators = int(ml_cfg.get("n_estimators", 100))
        self.random_state = int(ml_cfg.get("random_state", 42))
        self.log = get_logger()
        self.model: IsolationForest | None = None
        self.scaler: StandardScaler | None = None
        self._load_or_train()

    # ── resolve paths relative to this script's parent ───────

    def _resolve(self, p: Path) -> Path:
        return p if p.is_absolute() else (BASE_DIR / p).resolve()

    # ── model loading ─────────────────────────────────────────

    def _load_or_train(self) -> None:
        model_p = self._resolve(self.model_path)
        scaler_p = self._resolve(self.scaler_path)

        if model_p.exists() and scaler_p.exists():
            try:
                self.model = joblib.load(model_p)
                self.scaler = joblib.load(scaler_p)
                self.log.info("Loaded pre-trained model from %s", model_p)
                return
            except Exception as exc:
                self.log.warning("Failed to load saved model (%s) — will train fresh.", exc)

        self.log.warning("Pre-trained model not found — training fresh Isolation Forest.")
        self._train_fresh()

    def _train_fresh(self) -> None:
        """Train a new Isolation Forest on the bundled dataset."""
        data_p = self._resolve(self.fallback_data)
        if not data_p.exists():
            self.log.error("Fallback dataset not found: %s", data_p)
            raise FileNotFoundError(f"Dataset not found: {data_p}")

        self.log.info("Loading training data from %s …", data_p)
        df = pd.read_csv(data_p, low_memory=False)
        # map aliases
        alias_map: dict[str, str] = {}
        for feat, aliases in FEATURE_ALIASES.items():
            if feat in df.columns:
                alias_map[feat] = feat
            else:
                for alias in aliases:
                    if alias in df.columns:
                        alias_map[feat] = alias
                        break
        available = [alias_map[f] for f in CANONICAL_FEATURES if f in alias_map]
        X = df[available].fillna(0).replace([np.inf, -np.inf], 0).values

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        self.log.info("Fresh model trained on %d samples.", len(X))

        # save for reuse
        out_dir = BASE_DIR / "data"
        out_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, out_dir / "isolation_forest_model.pkl")
        joblib.dump(self.scaler, out_dir / "standard_scaler.pkl")
        self.log.info("Saved fresh model to %s", out_dir)

    def retrain(self) -> None:
        self.log.info("Force-retraining model …")
        self._train_fresh()

    # ── scoring ───────────────────────────────────────────────

    def score_records(self, records: list[dict]) -> list[dict]:
        """
        Score a list of event dicts.
        Adds keys: anomaly_score, is_anomaly, confidence_level, ml_alert.
        """
        if not records:
            return []
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model not loaded.")

        X = features_to_df(records).values
        X_scaled = self.scaler.transform(X)
        scores = self.model.decision_function(X_scaled)
        preds = self.model.predict(X_scaled)   # 1 normal / -1 anomaly

        results = []
        for i, rec in enumerate(records):
            score = float(scores[i])
            is_anomaly = int(preds[i] == -1)

            # confidence level
            if score < self.high_conf_thresh:
                confidence = "HIGH"
                alert = True
            elif score < self.med_conf_thresh:
                confidence = "MEDIUM"
                alert = True
            else:
                confidence = "LOW"
                alert = False

            enriched = dict(rec)
            enriched.update({
                "anomaly_score": round(score, 4),
                "is_anomaly": is_anomaly,
                "confidence_level": confidence,
                "ml_alert": alert,
                "scored_at": datetime.now(timezone.utc).isoformat(),
            })
            results.append(enriched)

        return results

    def score_single(self, record: dict) -> dict:
        return self.score_records([record])[0]

    def score_queue(self, queue_path: Path, output_path: Path | None = None) -> list[dict]:
        """Score all events in a JSONL file and write results."""
        log = self.log
        if not queue_path.exists():
            log.warning("Queue file not found: %s", queue_path)
            return []

        lines = [l for l in queue_path.read_text().splitlines() if l.strip()]
        log.info("Scoring %d events from %s", len(lines), queue_path)

        records = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except Exception:
                log.warning("Skipping unparseable line: %s", line[:80])

        t0 = time.time()
        scored = self.score_records(records)
        elapsed = time.time() - t0
        log.info("Scored %d events in %.3fs (%.0f events/sec)",
                 len(scored), elapsed, len(scored) / max(elapsed, 1e-6))

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as fh:
                for ev in scored:
                    fh.write(json.dumps(ev) + "\n")
            log.info("Wrote %d scored events to %s", len(scored), output_path)

        return scored


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Module 3 — ML Threat Detection (Isolation Forest)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", default=str(CONFIG_PATH))
    p.add_argument("--input", help="Input JSONL (default: enriched queue)")
    p.add_argument("--output", help="Output JSONL for scored events")
    p.add_argument("--retrain", action="store_true", help="Force re-train the model")
    p.add_argument("--single", metavar="JSON", help="Score a single JSON record string")
    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(Path(args.config))

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                        stream=sys.stdout)

    detector = MLDetector(cfg)

    if args.retrain:
        detector.retrain()
        print("✅  Model retrained and saved.")
        return

    if args.single:
        record = json.loads(args.single)
        result = detector.score_single(record)
        print(json.dumps(result, indent=2))
        return

    # Default: score the enriched queue
    in_path = Path(args.input) if args.input else BASE_DIR / "data" / "enriched_queue.jsonl"
    # fall back to the raw ingestion queue if enriched doesn't exist
    if not in_path.exists():
        in_path = BASE_DIR / cfg["ingestion"]["output_queue"]

    out_path = Path(args.output) if args.output else BASE_DIR / "data" / "scored_events.jsonl"

    scored = detector.score_queue(in_path, out_path)
    n_alerts = sum(1 for e in scored if e.get("ml_alert"))
    n_high = sum(1 for e in scored if e.get("confidence_level") == "HIGH")
    print(f"\n✅  Scored {len(scored)} events → {out_path}")
    print(f"   Alerts: {n_alerts}  (HIGH: {n_high}  MEDIUM: {n_alerts - n_high})")


if __name__ == "__main__":
    main()
