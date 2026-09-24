#!/usr/bin/env python3
"""
soar_engine.py — Module 4: SOAR Orchestration
=============================================
AI Security Automation Platform
Author: Muhammad Huzaif Amir

Security Orchestration, Automation & Response engine.

Playbook logic
--------------
HIGH-confidence alerts (score < high_conf_thresh + high TI risk):
  1. Auto-enrich (TI lookup if not yet done)
  2. Create incident ticket
  3. Log to blocked IPs (simulated firewall action)
  4. Send email notification (if configured)

MEDIUM-confidence alerts:
  1. Auto-enrich
  2. Queue to analyst human-review file
  3. Create pending ticket

LOW:
  → Logged, no action.

Usage
-----
    python soar_engine.py                       # process scored queue
    python soar_engine.py --input events.jsonl
    python soar_engine.py --show-cases          # pretty-print open cases
"""

from __future__ import annotations

import argparse
import json
import logging
import smtplib
import sys
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import _pathfix  # noqa: F401
import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"


# ─────────────────────────────────────────────────────────────
# Config & logging
# ─────────────────────────────────────────────────────────────

def load_config(path: Path = CONFIG_PATH) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def get_logger(name: str = "soar") -> logging.Logger:
    return logging.getLogger(name)


# ─────────────────────────────────────────────────────────────
# Case / ticket models
# ─────────────────────────────────────────────────────────────

def new_case(event: dict, action: str, status: str = "OPEN") -> dict:
    return {
        "case_id": str(uuid.uuid4())[:8].upper(),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,        # OPEN | PENDING_REVIEW | CLOSED | AUTO_REMEDIATED
        "action_taken": action,
        "severity": event.get("confidence_level", "UNKNOWN"),
        "anomaly_score": event.get("anomaly_score"),
        "ti_risk_level": event.get("ti_risk_level", "UNKNOWN"),
        "ti_risk_score": event.get("ti_max_risk", 0),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "src_port": event.get("src_port"),
        "dst_port": event.get("dst_port"),
        "protocol": event.get("protocol"),
        "event_id": event.get("event_id"),
        "label": event.get("label"),
        "playbook": None,
        "notes": [],
    }


# ─────────────────────────────────────────────────────────────
# Persistence helpers
# ─────────────────────────────────────────────────────────────

def _load_json(path: Path) -> list:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return []
    return []


def _save_json(path: Path, data: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def _append_jsonl(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(record) + "\n")


# ─────────────────────────────────────────────────────────────
# Email notifier
# ─────────────────────────────────────────────────────────────

def send_alert_email(cfg: dict, case: dict) -> bool:
    """Send an email alert. Returns True on success."""
    email_cfg = cfg.get("soar", {}).get("email", {})
    if not email_cfg.get("enabled", False):
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SECURITY ALERT] {case['severity']} severity — Case {case['case_id']}"
        msg["From"] = email_cfg["sender"]
        msg["To"] = ", ".join(email_cfg["recipients"])

        html = f"""
        <html><body>
        <h2 style="color:#cc0000">Security Alert — Case {case['case_id']}</h2>
        <table border="1" cellpadding="4">
        <tr><td><b>Severity</b></td><td>{case['severity']}</td></tr>
        <tr><td><b>Anomaly Score</b></td><td>{case['anomaly_score']}</td></tr>
        <tr><td><b>TI Risk</b></td><td>{case['ti_risk_level']} ({case['ti_risk_score']})</td></tr>
        <tr><td><b>Source IP</b></td><td>{case['src_ip']}</td></tr>
        <tr><td><b>Destination IP</b></td><td>{case['dst_ip']}</td></tr>
        <tr><td><b>Action Taken</b></td><td>{case['action_taken']}</td></tr>
        <tr><td><b>Created At</b></td><td>{case['created_at']}</td></tr>
        </table>
        </body></html>
        """
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
            if email_cfg.get("use_tls"):
                server.starttls()
            if email_cfg.get("username"):
                server.login(email_cfg["username"], email_cfg["password"])
            server.sendmail(email_cfg["sender"], email_cfg["recipients"], msg.as_string())
        return True
    except Exception as exc:
        get_logger().error("Email failed: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────
# SOAR Engine
# ─────────────────────────────────────────────────────────────

class SOAREngine:
    def __init__(self, cfg: dict):
        soar_cfg = cfg.get("soar", {})
        self.alerts_dir = BASE_DIR / soar_cfg.get("alerts_dir", "alerts/")
        self.cases_file = BASE_DIR / soar_cfg.get("cases_file", "alerts/cases.json")
        self.analyst_queue = BASE_DIR / soar_cfg.get("analyst_queue_file", "alerts/analyst_queue.json")
        self.high_thresh = soar_cfg.get("high_confidence_threshold", 75)
        self.med_thresh = soar_cfg.get("medium_confidence_threshold", 40)
        self.playbooks = soar_cfg.get("playbooks", {})
        self.email_cfg = soar_cfg.get("email", {})
        self.cfg = cfg
        self.log = get_logger()
        self.alerts_dir.mkdir(parents=True, exist_ok=True)

        # runtime stats
        self.stats = {"processed": 0, "high": 0, "medium": 0, "low": 0,
                      "auto_remediated": 0, "queued_for_review": 0}

    # ── Composite confidence score ────────────────────────────

    def _composite_confidence(self, event: dict) -> float:
        """
        Blend ML anomaly score and TI risk score into a single 0-100
        confidence value (higher = more confident it's an attack).
        """
        score = event.get("anomaly_score", 0)
        # anomaly_score is a decision_function value: lower = more anomalous
        # map [-0.5, 0.5] → [100, 0]
        ml_conf = max(0.0, min(100.0, (0.5 - score) * 100))
        ti_score = float(event.get("ti_max_risk", 0))
        return round(0.6 * ml_conf + 0.4 * ti_score, 2)

    # ── Playbooks ─────────────────────────────────────────────

    def playbook_auto_remediate(self, event: dict) -> dict:
        """HIGH-confidence automated remediation playbook."""
        case = new_case(event, "AUTO_REMEDIATED", status="AUTO_REMEDIATED")
        case["playbook"] = "auto_remediate"

        steps: list[str] = []

        # 1. Simulated IP block
        if self.playbooks.get("auto_block_ip") and event.get("src_ip"):
            blocked_log = self.alerts_dir / "blocked_ips.json"
            blocked = _load_json(blocked_log)
            entry = {
                "ip": event["src_ip"], "blocked_at": case["created_at"],
                "case_id": case["case_id"], "reason": "auto_remediate_playbook",
            }
            if entry not in blocked:
                blocked.append(entry)
                _save_json(blocked_log, blocked)
            steps.append(f"IP blocked: {event['src_ip']}")

        # 2. Create ticket
        if self.playbooks.get("create_ticket"):
            steps.append(f"Ticket created: {case['case_id']}")

        # 3. Email notification
        if self.playbooks.get("auto_notify"):
            sent = send_alert_email(self.cfg, case)
            steps.append("Email sent" if sent else "Email skipped (not configured)")

        case["notes"] = steps
        self.stats["auto_remediated"] += 1
        self.log.warning("AUTO-REMEDIATED | case=%s src=%s score=%.3f",
                         case["case_id"], event.get("src_ip"), event.get("anomaly_score", 0))
        return case

    def playbook_human_review(self, event: dict) -> dict:
        """MEDIUM-confidence human-in-the-loop playbook."""
        case = new_case(event, "QUEUED_FOR_REVIEW", status="PENDING_REVIEW")
        case["playbook"] = "human_review"
        case["notes"] = ["Queued to analyst review queue", f"Ticket pending: {case['case_id']}"]

        # append to analyst queue file
        analyst_queue_data = _load_json(self.analyst_queue)
        analyst_queue_data.append(case)
        _save_json(self.analyst_queue, analyst_queue_data)

        self.stats["queued_for_review"] += 1
        self.log.info("HUMAN_REVIEW | case=%s src=%s score=%.3f",
                      case["case_id"], event.get("src_ip"), event.get("anomaly_score", 0))
        return case

    def playbook_low_confidence(self, event: dict) -> dict:
        """LOW-confidence — log only."""
        case = new_case(event, "LOGGED_ONLY", status="CLOSED")
        case["playbook"] = "log_only"
        return case

    # ── Main processing loop ──────────────────────────────────

    def process_event(self, event: dict) -> dict | None:
        """Decide which playbook to run and execute it."""
        if not event.get("ml_alert"):
            return None  # not an alert

        self.stats["processed"] += 1
        conf = self._composite_confidence(event)

        if conf >= self.high_thresh:
            self.stats["high"] += 1
            case = self.playbook_auto_remediate(event)
        elif conf >= self.med_thresh:
            self.stats["medium"] += 1
            case = self.playbook_human_review(event)
        else:
            self.stats["low"] += 1
            case = self.playbook_low_confidence(event)

        case["composite_confidence"] = conf
        return case

    def process_queue(self, queue_path: Path) -> list[dict]:
        """Process all scored events from a JSONL file."""
        if not queue_path.exists():
            self.log.warning("Scored queue not found: %s", queue_path)
            return []

        lines = [l for l in queue_path.read_text().splitlines() if l.strip()]
        self.log.info("Processing %d scored events through SOAR …", len(lines))

        cases: list[dict] = []
        for line in lines:
            try:
                ev = json.loads(line)
                case = self.process_event(ev)
                if case:
                    cases.append(case)
            except Exception as exc:
                self.log.error("SOAR event processing failed: %s", exc)

        # Persist all cases
        existing = _load_json(self.cases_file)
        existing.extend(cases)
        _save_json(self.cases_file, existing)
        self.log.info("Saved %d cases to %s", len(cases), self.cases_file)
        return cases

    def show_cases(self) -> None:
        cases = _load_json(self.cases_file)
        if not cases:
            print("No cases found.")
            return
        print(f"\n{'─'*70}")
        print(f"  SOAR Case Manager — {len(cases)} cases")
        print(f"{'─'*70}")
        for c in cases[-20:]:  # last 20
            print(f"  [{c['status']:20s}] {c['case_id']} | "
                  f"{c['severity']:6s} | score={c.get('anomaly_score', 'N/A')} | "
                  f"src={c.get('src_ip', 'N/A')}")
        print(f"{'─'*70}\n")

    def print_stats(self) -> None:
        s = self.stats
        print(f"\n{'─'*50}")
        print(f"  SOAR Summary")
        print(f"{'─'*50}")
        print(f"  Total alerts processed : {s['processed']}")
        print(f"  HIGH confidence        : {s['high']} → auto-remediated: {s['auto_remediated']}")
        print(f"  MEDIUM confidence      : {s['medium']} → queued for review: {s['queued_for_review']}")
        print(f"  LOW confidence         : {s['low']}")
        print(f"{'─'*50}\n")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Module 4 — SOAR Orchestration Engine",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", default=str(CONFIG_PATH))
    p.add_argument("--input", help="Scored events JSONL (default: data/scored_events.jsonl)")
    p.add_argument("--show-cases", action="store_true", help="Display recent cases and exit")
    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(Path(args.config))

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                        stream=sys.stdout)

    engine = SOAREngine(cfg)

    if args.show_cases:
        engine.show_cases()
        return

    in_path = Path(args.input) if args.input else BASE_DIR / "data" / "scored_events.jsonl"
    cases = engine.process_queue(in_path)
    engine.print_stats()
    print(f"✅  SOAR processed — {len(cases)} cases created/updated.")


if __name__ == "__main__":
    main()
