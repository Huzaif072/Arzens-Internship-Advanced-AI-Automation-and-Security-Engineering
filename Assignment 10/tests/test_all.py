#!/usr/bin/env python3
"""
tests/test_all.py — Unit Tests for AI Security Automation Platform
===================================================================
Author: Muhammad Huzaif Amir

Covers core functions across all 5 modules.
Run:  pytest tests/test_all.py -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure the platform package root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ─────────────────────────────────────────────────────────────
# Module 1: Data Ingestion
# ─────────────────────────────────────────────────────────────

class TestDataIngestion:
    def test_normalize_record_basic(self):
        from ingest_logs import normalize_record
        raw = {
            "timestamp": "2024-01-01T00:00:00Z",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": "tcp",
            "bytes_sent": 1024,
            "bytes_recv": 512,
            "duration": 1.5,
            "label": "Benign",
        }
        ev = normalize_record(raw)
        assert ev["src_ip"] == "1.2.3.4"
        assert ev["dst_ip"] == "5.6.7.8"
        assert ev["src_port"] == 1234
        assert ev["dst_port"] == 80
        assert ev["protocol"] == "TCP"
        assert ev["bytes_sent"] == 1024
        assert ev["bytes_recv"] == 512
        assert ev["duration"] == 1.5
        assert ev["label"] == "Benign"
        assert ev["event_id"] is not None
        assert ev["source_type"] == "file"

    def test_normalize_record_aliases(self):
        from ingest_logs import normalize_record
        raw = {"source_ip": "10.0.0.1", "server_ip": "8.8.8.8", "sport": 5000,
               "dport": 443, "proto": "udp", "sbytes": 200, "dbytes": 100}
        ev = normalize_record(raw)
        assert ev["src_ip"] == "10.0.0.1"
        assert ev["dst_ip"] == "8.8.8.8"
        assert ev["src_port"] == 5000
        assert ev["dst_port"] == 443
        assert ev["protocol"] == "UDP"

    def test_normalize_record_missing_fields(self):
        from ingest_logs import normalize_record
        ev = normalize_record({})
        assert ev["event_id"] is not None
        assert ev["src_ip"] is None
        assert ev["bytes_sent"] is None
        assert ev["label"] == "unknown"

    def test_new_event_id_unique(self):
        from ingest_logs import _new_event_id
        ids = {_new_event_id() for _ in range(1000)}
        assert len(ids) == 1000

    def test_read_json_file(self, tmp_path):
        from ingest_logs import read_json_file
        import logging
        log = logging.getLogger("test")
        data = [{"a": 1}, {"b": 2}]
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data))
        records = list(read_json_file(f, log))
        assert len(records) == 2

    def test_read_jsonl_file(self, tmp_path):
        from ingest_logs import read_json_file
        import logging
        log = logging.getLogger("test")
        f = tmp_path / "test.jsonl"
        f.write_text('{"a":1}\n{"b":2}\n')
        records = list(read_json_file(f, log))
        assert len(records) == 2

    def test_write_to_queue(self, tmp_path):
        from ingest_logs import write_to_queue, normalize_record
        import logging
        log = logging.getLogger("test")
        events = [normalize_record({"src_ip": "1.1.1.1", "label": "test"}) for _ in range(5)]
        q = tmp_path / "queue.jsonl"
        n = write_to_queue(events, q, log)
        assert n == 5
        lines = [l for l in q.read_text().splitlines() if l]
        assert len(lines) == 5


# ─────────────────────────────────────────────────────────────
# Module 2: Threat Intelligence
# ─────────────────────────────────────────────────────────────

class TestThreatIntel:
    def test_ti_cache_set_get(self, tmp_path):
        from ti_enricher import TICache
        cache = TICache(tmp_path / "cache.json", ttl_seconds=60)
        cache.set("virustotal", "1.2.3.4", {"malicious": 5})
        result = cache.get("virustotal", "1.2.3.4")
        assert result == {"malicious": 5}

    def test_ti_cache_miss(self, tmp_path):
        from ti_enricher import TICache
        cache = TICache(tmp_path / "cache.json", ttl_seconds=60)
        result = cache.get("virustotal", "nonexistent")
        assert result is None

    def test_ti_cache_ttl_expired(self, tmp_path):
        from ti_enricher import TICache
        import ti_enricher
        cache = TICache(tmp_path / "cache.json", ttl_seconds=1)
        cache.set("virustotal", "1.2.3.4", {"data": "test"})
        time.sleep(1.1)
        result = cache.get("virustotal", "1.2.3.4")
        assert result is None

    def test_calculate_risk_score_high(self):
        from ti_enricher import calculate_risk_score
        weights = {"virustotal": 0.4, "abuseipdb": 0.35, "alienvault": 0.25}
        vt = {"malicious_votes": 20, "total_engines": 70}
        ab = {"abuse_confidence_score": 95}
        av = {"pulse_count": 10}
        score = calculate_risk_score(vt, ab, av, weights)
        assert score > 50  # should be high

    def test_calculate_risk_score_low(self):
        from ti_enricher import calculate_risk_score
        weights = {"virustotal": 0.4, "abuseipdb": 0.35, "alienvault": 0.25}
        vt = {"malicious_votes": 0, "total_engines": 70}
        ab = {"abuse_confidence_score": 2}
        av = {"pulse_count": 0}
        score = calculate_risk_score(vt, ab, av, weights)
        assert score < 20

    def test_calculate_risk_score_none_sources(self):
        from ti_enricher import calculate_risk_score
        weights = {"virustotal": 0.4, "abuseipdb": 0.35, "alienvault": 0.25}
        score = calculate_risk_score(None, None, None, weights)
        assert score == 0.0

    def test_mock_virustotal_known_bad(self):
        from ti_enricher import _mock_virustotal
        result = _mock_virustotal("185.220.101.34")  # known bad
        assert result["source"] == "virustotal"
        assert result["malicious_votes"] > 0

    def test_mock_abuseipdb_known_bad(self):
        from ti_enricher import _mock_abuseipdb
        result = _mock_abuseipdb("185.220.101.34")
        assert result["abuse_confidence_score"] >= 60

    def test_enricher_demo_mode(self, tmp_path):
        from ti_enricher import TIEnricher
        cfg = {
            "threat_intel": {
                "demo_mode": True,
                "cache_file": str(tmp_path / "cache.json"),
                "cache_ttl_seconds": 3600,
                "risk_score_weights": {"virustotal": 0.4, "abuseipdb": 0.35, "alienvault": 0.25},
                "high_risk_threshold": 70,
                "medium_risk_threshold": 40,
                "virustotal_api_key": "",
                "abuseipdb_api_key": "",
                "alienvault_api_key": "",
            }
        }
        enricher = TIEnricher(cfg)
        result = enricher.enrich_ip("185.220.101.34")
        assert "risk_score" in result
        assert "risk_level" in result
        assert result["risk_level"] in ("HIGH", "MEDIUM", "LOW")


# ─────────────────────────────────────────────────────────────
# Module 3: ML Detection
# ─────────────────────────────────────────────────────────────

class TestMLDetector:
    @pytest.fixture
    def detector(self, tmp_path):
        """Create a detector with a fresh minimal model."""
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import joblib

        # Train a tiny model
        X = np.random.randn(200, 6)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
        model.fit(X_scaled)

        model_path = tmp_path / "model.pkl"
        scaler_path = tmp_path / "scaler.pkl"
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)

        cfg = {
            "ml_detection": {
                "model_path": str(model_path),
                "scaler_path": str(scaler_path),
                "decision_threshold": 0.0,
                "high_confidence_threshold": -0.3,
                "medium_confidence_threshold": 0.0,
                "contamination": 0.1,
                "n_estimators": 10,
                "random_state": 42,
            }
        }
        from ml_detector import MLDetector
        return MLDetector(cfg)

    def test_extract_features_canonical(self):
        from ml_detector import extract_features
        record = {"dur": 1.0, "spkts": 10, "dpkts": 5, "sbytes": 1000,
                  "dbytes": 500, "rate": 2.0}
        features = extract_features(record)
        assert len(features) == 6
        assert features[0] == 1.0
        assert features[1] == 10.0

    def test_extract_features_aliases(self):
        from ml_detector import extract_features
        record = {"flow_duration": 2.5, "total_fwd_packets": 20,
                  "total_bwd_packets": 10, "bytes_sent": 2000,
                  "bytes_recv": 1000, "flow_packets_per_sec": 4.0}
        features = extract_features(record)
        assert len(features) == 6
        assert features[0] == 2.5

    def test_extract_features_missing(self):
        from ml_detector import extract_features
        features = extract_features({})
        assert features == [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    def test_extract_features_inf(self):
        from ml_detector import extract_features
        import math
        record = {"dur": float("inf"), "spkts": float("nan")}
        features = extract_features(record)
        assert features[0] == 0.0
        assert features[1] == 0.0

    def test_score_single_record(self, detector):
        record = {"dur": 1.0, "spkts": 10, "dpkts": 5,
                  "sbytes": 1000, "dbytes": 500, "rate": 2.0}
        result = detector.score_single(record)
        assert "anomaly_score" in result
        assert "is_anomaly" in result
        assert "confidence_level" in result
        assert result["confidence_level"] in ("HIGH", "MEDIUM", "LOW")
        assert result["is_anomaly"] in (0, 1)

    def test_score_multiple_records(self, detector):
        records = [
            {"dur": float(i), "spkts": i, "dpkts": i//2,
             "sbytes": i * 100, "dbytes": i * 50, "rate": float(i) / 10}
            for i in range(1, 11)
        ]
        results = detector.score_records(records)
        assert len(results) == 10
        for r in results:
            assert "anomaly_score" in r
            assert "confidence_level" in r

    def test_score_queue(self, detector, tmp_path):
        records = [
            {"dur": 1.0, "spkts": 10, "dpkts": 5, "sbytes": 1000, "dbytes": 500, "rate": 2.0}
            for _ in range(5)
        ]
        q = tmp_path / "queue.jsonl"
        with open(q, "w") as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
        out = tmp_path / "out.jsonl"
        scored = detector.score_queue(q, out)
        assert len(scored) == 5
        assert out.exists()


# ─────────────────────────────────────────────────────────────
# Module 4: SOAR
# ─────────────────────────────────────────────────────────────

class TestSOAR:
    @pytest.fixture
    def engine(self, tmp_path):
        from soar_engine import SOAREngine
        cfg = {
            "soar": {
                "alerts_dir": str(tmp_path / "alerts"),
                "cases_file": str(tmp_path / "alerts" / "cases.json"),
                "analyst_queue_file": str(tmp_path / "alerts" / "analyst_queue.json"),
                "high_confidence_threshold": 75,
                "medium_confidence_threshold": 40,
                "email": {"enabled": False},
                "playbooks": {
                    "auto_block_ip": True,
                    "auto_enrich": True,
                    "auto_notify": False,
                    "create_ticket": True,
                },
            }
        }
        return SOAREngine(cfg)

    def _make_alert(self, score: float, ti_risk: float = 50.0) -> dict:
        return {
            "event_id": "test-001",
            "src_ip": "185.220.101.34",
            "dst_ip": "10.0.0.1",
            "src_port": 54321,
            "dst_port": 443,
            "protocol": "TCP",
            "anomaly_score": score,
            "is_anomaly": 1,
            "confidence_level": "HIGH" if score < -0.3 else "MEDIUM",
            "ml_alert": True,
            "ti_max_risk": ti_risk,
            "ti_risk_level": "HIGH" if ti_risk >= 70 else "MEDIUM",
            "label": "DoS",
        }

    def test_composite_confidence_high(self, engine):
        ev = self._make_alert(-0.45, ti_risk=90)
        conf = engine._composite_confidence(ev)
        assert conf >= 75  # should trigger HIGH playbook

    def test_composite_confidence_low(self, engine):
        ev = self._make_alert(0.4, ti_risk=5)
        conf = engine._composite_confidence(ev)
        assert conf < 40

    def test_playbook_auto_remediate(self, engine):
        ev = self._make_alert(-0.45, ti_risk=90)
        case = engine.playbook_auto_remediate(ev)
        assert case["status"] == "AUTO_REMEDIATED"
        assert case["action_taken"] == "AUTO_REMEDIATED"
        assert case["case_id"] is not None

    def test_playbook_human_review(self, engine):
        ev = self._make_alert(-0.1, ti_risk=50)
        case = engine.playbook_human_review(ev)
        assert case["status"] == "PENDING_REVIEW"
        # check analyst queue was written
        analyst_file = Path(engine.analyst_queue)
        assert analyst_file.exists()

    def test_process_event_no_alert(self, engine):
        ev = {"ml_alert": False, "anomaly_score": 0.3}
        result = engine.process_event(ev)
        assert result is None

    def test_process_event_high_confidence(self, engine):
        ev = self._make_alert(-0.45, ti_risk=95)
        case = engine.process_event(ev)
        assert case is not None
        assert case["status"] == "AUTO_REMEDIATED"

    def test_new_case_fields(self):
        from soar_engine import new_case
        ev = {"event_id": "e1", "src_ip": "1.1.1.1", "confidence_level": "HIGH",
              "anomaly_score": -0.4}
        case = new_case(ev, "TEST_ACTION")
        assert "case_id" in case
        assert case["action_taken"] == "TEST_ACTION"
        assert case["src_ip"] == "1.1.1.1"

    def test_process_queue(self, engine, tmp_path):
        events = [self._make_alert(-0.45, 90) for _ in range(3)]
        q = tmp_path / "scored.jsonl"
        with open(q, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        # patch the engine's queue path
        cases = engine.process_queue(q)
        assert len(cases) == 3

    def test_stats_tracking(self, engine):
        ev_high = self._make_alert(-0.45, 90)
        engine.process_event(ev_high)
        assert engine.stats["high"] == 1
        assert engine.stats["auto_remediated"] == 1


# ─────────────────────────────────────────────────────────────
# Integration: Ingestion → Enrichment → Detection → SOAR
# ─────────────────────────────────────────────────────────────

class TestIntegration:
    def test_full_pipeline_small(self, tmp_path):
        """Mini integration test: 10 events through all 4 processing modules."""
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import joblib

        # 1. Create sample events
        events = []
        from ingest_logs import normalize_record
        for i in range(10):
            raw = {
                "timestamp": "2024-01-01T00:00:00Z",
                "src_ip": "185.220.101.34" if i < 3 else "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "src_port": 1024 + i,
                "dst_port": 80,
                "protocol": "TCP",
                "bytes_sent": (i + 1) * 1000,
                "bytes_recv": (i + 1) * 500,
                "duration": float(i + 1),
                "label": "Benign",
                "dur": float(i + 1),
                "spkts": (i + 1) * 5,
                "dpkts": (i + 1) * 2,
                "sbytes": (i + 1) * 1000,
                "dbytes": (i + 1) * 500,
                "rate": float(i + 1) / 10,
            }
            events.append(normalize_record(raw))

        # Write to queue
        queue = tmp_path / "queue.jsonl"
        with open(queue, "w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

        # 2. TI enrichment
        from ti_enricher import TIEnricher
        ti_cfg = {
            "threat_intel": {
                "demo_mode": True,
                "cache_file": str(tmp_path / "cache.json"),
                "cache_ttl_seconds": 3600,
                "risk_score_weights": {"virustotal": 0.4, "abuseipdb": 0.35, "alienvault": 0.25},
                "high_risk_threshold": 70,
                "medium_risk_threshold": 40,
                "virustotal_api_key": "",
                "abuseipdb_api_key": "",
                "alienvault_api_key": "",
            }
        }
        enricher = TIEnricher(ti_cfg)
        enriched_out = tmp_path / "enriched.jsonl"
        enriched = enricher.enrich_queue(queue, enriched_out)
        assert len(enriched) == 10
        assert all("ti_risk_level" in e for e in enriched)

        # 3. ML detection — use a fresh tiny model
        X = np.random.randn(200, 6)
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
        model.fit(X_scaled)
        model_path = tmp_path / "model.pkl"
        scaler_path = tmp_path / "scaler.pkl"
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)

        from ml_detector import MLDetector
        ml_cfg = {
            "ml_detection": {
                "model_path": str(model_path),
                "scaler_path": str(scaler_path),
                "decision_threshold": 0.0,
                "high_confidence_threshold": -0.3,
                "medium_confidence_threshold": 0.0,
                "contamination": 0.1,
                "n_estimators": 10,
                "random_state": 42,
            }
        }
        detector = MLDetector(ml_cfg)
        scored_out = tmp_path / "scored.jsonl"
        scored = detector.score_queue(enriched_out, scored_out)
        assert len(scored) == 10
        assert all("anomaly_score" in e for e in scored)

        # 4. SOAR
        from soar_engine import SOAREngine
        soar_cfg = {
            "soar": {
                "alerts_dir": str(tmp_path / "alerts"),
                "cases_file": str(tmp_path / "alerts" / "cases.json"),
                "analyst_queue_file": str(tmp_path / "alerts" / "analyst_queue.json"),
                "high_confidence_threshold": 75,
                "medium_confidence_threshold": 40,
                "email": {"enabled": False},
                "playbooks": {
                    "auto_block_ip": True, "auto_enrich": True,
                    "auto_notify": False, "create_ticket": True,
                },
            }
        }
        soar = SOAREngine(soar_cfg)
        cases = soar.process_queue(scored_out)
        # Cases created only for ml_alert=True events
        alert_count = sum(1 for e in scored if e.get("ml_alert"))
        assert len(cases) == alert_count
        assert soar.stats["processed"] == alert_count


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
