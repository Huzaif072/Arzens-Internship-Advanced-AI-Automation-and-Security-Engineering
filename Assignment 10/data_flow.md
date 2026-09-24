# Data Flow — AI Security Automation Platform

**Author:** Muhammad Huzaif Amir  
**Version:** 1.0.0

---

## Overview

Data flows sequentially through five stages. Each stage reads from a well-defined input (file, queue, or database) and writes enriched results to the next stage's input. Modules are decoupled — each can be run independently or as part of the full pipeline.

```
External Sources
    │
    ▼
┌──────────────────────────────┐
│  MODULE 1: Data Ingestion    │
│  ingest_logs.py              │
└──────────────┬───────────────┘
               │ data/ingestion_queue.jsonl
               │ (normalised JSON events)
               ▼
┌──────────────────────────────┐
│  MODULE 2: TI Enrichment     │
│  ti_enricher.py              │
└──────────────┬───────────────┘
               │ data/enriched_queue.jsonl
               │ (events + TI metadata + risk scores)
               ▼
┌──────────────────────────────┐
│  MODULE 3: ML Detection      │
│  ml_detector.py              │
└──────────────┬───────────────┘
               │ data/scored_events.jsonl
               │ (events + anomaly scores + confidence)
               ▼
┌──────────────────────────────┐
│  MODULE 4: SOAR              │
│  soar_engine.py              │
└──────────────┬───────────────┘
               │ alerts/cases.json
               │ alerts/analyst_queue.json
               │ alerts/blocked_ips.json
               ▼
┌──────────────────────────────┐
│  MODULE 5: Dashboard         │
│  dashboard.py                │
└──────────────────────────────┘
               │ (reads all data files above)
               ▼
         Browser UI
```

---

## Stage-by-Stage Data Flow

### Stage 1 — Data Ingestion (`ingest_logs.py`)

**Input Sources:**
| Source | Format | Description |
|--------|--------|-------------|
| JSON / JSONL log files | `.json` / `.jsonl` | Firewall logs, IDS alerts |
| CSV network flows | `.csv` | CICIDS-style / UNSW-NB15 flow datasets |
| Streaming simulation | In-memory | Synthetic real-time events |

**Processing:**
1. Each raw record is read and passed to `normalize_record()`.
2. Field aliases are resolved (e.g., `source_ip` → `src_ip`, `sbytes` → `bytes_sent`).
3. Missing values are set to `None` / sensible defaults.
4. A UUID event ID and UTC timestamp are assigned.
5. `source_type` is tagged (`file` | `stream` | `api`).

**Output:**  
`data/ingestion_queue.jsonl` — one JSON object per line, all events using the **Common Schema**:

```json
{
  "event_id": "uuid4",
  "timestamp": "ISO8601 UTC",
  "source_type": "file|stream|api",
  "src_ip": "string|null",
  "dst_ip": "string|null",
  "src_port": "int|null",
  "dst_port": "int|null",
  "protocol": "TCP|UDP|ICMP|null",
  "bytes_sent": "int|null",
  "bytes_recv": "int|null",
  "duration": "float|null",
  "label": "string",
  "raw": "original record JSON string"
}
```

---

### Stage 2 — TI Enrichment (`ti_enricher.py`)

**Input:** `data/ingestion_queue.jsonl`

**Processing per event:**
1. Extract `src_ip` and `dst_ip`.
2. For each IP, check JSON TTL cache (`cache/ti_cache.json`).
   - **Cache hit:** return stored result immediately.
   - **Cache miss:** call VirusTotal, AbuseIPDB, AlienVault OTX (or demo mock).
3. Compute **composite risk score** (0–100):
   ```
   score = 0.40 × VT_score + 0.35 × AbuseIPDB_score + 0.25 × AV_score
   ```
4. Classify risk level: `HIGH ≥ 70`, `MEDIUM ≥ 40`, `LOW < 40`.

**Output:** `data/enriched_queue.jsonl` — original fields + added keys:

```json
{
  "...original fields...",
  "ti_src": { "ip": "...", "risk_score": 82.5, "risk_level": "HIGH", "virustotal": {...}, ... },
  "ti_dst": { "ip": "...", "risk_score": 5.0,  "risk_level": "LOW", ... },
  "ti_max_risk": 82.5,
  "ti_risk_level": "HIGH",
  "enriched_at": "ISO8601 UTC"
}
```

**Side effect:** `cache/ti_cache.json` updated with fresh entries.

---

### Stage 3 — ML Detection (`ml_detector.py`)

**Input:** `data/enriched_queue.jsonl`

**Processing per event:**
1. Extract 6 canonical features: `[dur, spkts, dpkts, sbytes, dbytes, rate]`.
   - Resolve via alias map if original names differ.
   - Replace `NaN` / `Inf` with `0.0`.
2. Scale features using the saved `StandardScaler`.
3. Run Isolation Forest `decision_function()` → anomaly score.
   - Lower score = more anomalous.
4. Classify confidence:
   - `HIGH`: score < −0.3 (deep anomaly)
   - `MEDIUM`: −0.3 ≤ score < 0.0
   - `LOW`: score ≥ 0.0 (normal)
5. Set `ml_alert = True` for HIGH and MEDIUM.

**Output:** `data/scored_events.jsonl` — adds:

```json
{
  "...enriched fields...",
  "anomaly_score": -0.412,
  "is_anomaly": 1,
  "confidence_level": "HIGH",
  "ml_alert": true,
  "scored_at": "ISO8601 UTC"
}
```

---

### Stage 4 — SOAR Orchestration (`soar_engine.py`)

**Input:** `data/scored_events.jsonl`  
**Filter:** Only events with `ml_alert = True`

**Processing per alert:**
1. Compute **composite confidence** (0–100):
   ```
   composite = 0.6 × ML_confidence + 0.4 × TI_risk_score
   ```
   where `ML_confidence = (0.5 − anomaly_score) × 100` (clamped 0–100).

2. Route to playbook:

| composite score | Playbook | Actions |
|-----------------|----------|---------|
| ≥ 75 (HIGH) | `auto_remediate` | Block IP (blocked_ips.json), create ticket, optional email |
| 40–74 (MEDIUM) | `human_review` | Add to analyst queue, create pending ticket |
| < 40 (LOW) | `log_only` | Log and close |

**Output files:**
- `alerts/cases.json` — all SOAR cases (append-only JSON array)
- `alerts/analyst_queue.json` — MEDIUM cases awaiting human review
- `alerts/blocked_ips.json` — auto-blocked IP log

**Case schema:**
```json
{
  "case_id": "A3F7B2C1",
  "created_at": "ISO8601",
  "status": "AUTO_REMEDIATED|PENDING_REVIEW|CLOSED",
  "action_taken": "AUTO_REMEDIATED",
  "severity": "HIGH",
  "anomaly_score": -0.412,
  "composite_confidence": 88.5,
  "ti_risk_level": "HIGH",
  "src_ip": "185.220.101.34",
  "playbook": "auto_remediate",
  "notes": ["IP blocked: 185.220.101.34", "Ticket created: A3F7B2C1"]
}
```

---

### Stage 5 — Dashboard (`dashboard.py`)

**Input:** All output files from stages 1–4 (read-only, polled every 10s).

**Data consumed:**
| File | Purpose in dashboard |
|------|----------------------|
| `data/scored_events.jsonl` | Alert timeline, ML viz, live feed |
| `alerts/cases.json` | SOAR status panel |
| `alerts/analyst_queue.json` | Pending review table |
| `alerts/blocked_ips.json` | Blocked IP list |
| `cache/ti_cache.json` | TI cache stats |

**Rendering:** Streamlit + Plotly charts. No data is written by the dashboard.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **JSONL queues** | Append-only, human-readable, no DB dependency |
| **JSON file cache** | Zero infrastructure, Redis-swappable if needed |
| **Staged pipeline** | Each module independently restartable / testable |
| **Demo mode** | Platform fully functional without real API keys |
| **Configurable thresholds** | All scoring thresholds in `config.yaml`, not hard-coded |
