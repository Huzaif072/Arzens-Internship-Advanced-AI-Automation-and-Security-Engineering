# AI Security Automation Platform

**Author:** Muhammad Huzaif Amir — ArzensIntern Advanced Track  
**Version:** 1.0.0 | Assignment 10

A production-ready, modular AI Security Automation Platform integrating threat intelligence, machine learning anomaly detection, SOAR orchestration, and a real-time security dashboard into a single unified system.

---

## Quick Start

### 1. Install dependencies

```bash
cd ai_security_platform
pip install -r requirements.txt
```

### 2. Run the full pipeline (all 5 modules)

```bash
python platform.py --mode full
```

### 3. Launch the dashboard

```bash
streamlit run dashboard.py
# Open http://localhost:8501
```

### 4. Run tests

```bash
pytest tests/test_all.py -v
```

---

## Platform Architecture

```
External Sources → [Ingestion] → [TI Enrichment] → [ML Detection] → [SOAR] → [Dashboard]
                    Module 1        Module 2          Module 3        Module 4   Module 5
```

Each module is an independent Python script communicating via JSONL file queues.

---

## Module Reference

### Module 1 — Data Ingestion (`ingest_logs.py`)

Collects logs from JSON/JSONL files, CSV network-flow files, and a streaming simulation. Normalises all records to a common schema and writes to `data/ingestion_queue.jsonl`.

```bash
python ingest_logs.py                          # all sources
python ingest_logs.py --source file            # file sources only
python ingest_logs.py --source stream --stream-duration 30
```

### Module 2 — Threat Intelligence (`ti_enricher.py`)

Queries VirusTotal, AbuseIPDB, and AlienVault OTX for each IP address in the event stream. Results are cached (1-hour TTL). A composite risk score (0–100) is computed and appended to each event.

```bash
python ti_enricher.py                         # enrich ingestion queue
python ti_enricher.py --ip 185.220.101.34     # single IP lookup
```

> **Demo mode** (`demo_mode: true` in config.yaml): Full functionality without real API keys.

### Module 3 — ML Detection (`ml_detector.py`)

Loads the pre-trained Isolation Forest model from Assignment 05 (`../Assignment 05/outputs/isolation_forest_model.pkl`). Scores every event and assigns a confidence level (HIGH / MEDIUM / LOW). Falls back to training a fresh model if the pkl is not found.

```bash
python ml_detector.py                         # score enriched queue
python ml_detector.py --retrain               # force re-train
python ml_detector.py --single '{"dur":1.5,"spkts":10,...}'
```

### Module 4 — SOAR Orchestration (`soar_engine.py`)

Automated playbooks:
- **HIGH confidence (≥75):** Block IP + create ticket + optional email
- **MEDIUM confidence (40–74):** Queue for human review + pending ticket
- **LOW confidence (<40):** Log only

```bash
python soar_engine.py                         # process scored queue
python soar_engine.py --show-cases            # list recent cases
```

### Module 5 — Dashboard (`dashboard.py`)

Streamlit dark-mode dashboard with:
- Live alert feed with severity colour-coding
- Alert timeline charts
- ML anomaly score distributions
- Threat intelligence risk summaries
- Simulated world-threat geo map
- SOAR case status and blocked IP list
- Interactive event drill-down

```bash
streamlit run dashboard.py
```

---

## Configuration (`config.yaml`)

All settings for all modules are in `config.yaml`. Key sections:

| Section | Controls |
|---------|---------|
| `logging` | Log level, file path |
| `ingestion` | Source files, queue path, batch size |
| `threat_intel` | API keys, cache TTL, risk thresholds |
| `ml_detection` | Model path, decision threshold, confidence thresholds |
| `soar` | Playbook settings, email config, alert thresholds |
| `dashboard` | Port, refresh interval |

---

## Orchestrator Modes (`platform.py`)

```bash
python platform.py --mode full          # run all 5 modules
python platform.py --mode ingest        # Module 1 only
python platform.py --mode enrich        # Module 2 only
python platform.py --mode detect        # Module 3 only
python platform.py --mode soar          # Module 4 only
python platform.py --mode dashboard     # launch Module 5
python platform.py --mode status        # show pipeline health
python platform.py --mode full --loop --loop-interval 60  # continuous
```

---

## File Structure

```
ai_security_platform/
├── platform.py            # Main orchestrator
├── ingest_logs.py         # Module 1: Data Ingestion
├── ti_enricher.py         # Module 2: Threat Intelligence
├── ml_detector.py         # Module 3: ML Detection
├── soar_engine.py         # Module 4: SOAR
├── dashboard.py           # Module 5: Dashboard
├── config.yaml            # Central configuration
├── requirements.txt       # Python dependencies
├── data_flow.md           # Data flow documentation
├── tech_stack.md          # Technology choices
├── integration_plan.md    # Integration architecture
├── engineering_review.md  # Engineering reflection
├── tests/
│   └── test_all.py        # Unit + integration tests
├── data/                  # Runtime data files (JSONL queues)
├── cache/                 # TI cache
├── alerts/                # Cases, analyst queue, blocked IPs
└── logs/                  # Platform log file
```

---

## Pre-trained Model

The Isolation Forest model from Assignment 05 is used directly:
- **Model:** `../Assignment 05/outputs/isolation_forest_model.pkl`
- **Scaler:** `../Assignment 05/outputs/standard_scaler.pkl`
- **Features:** `[dur, spkts, dpkts, sbytes, dbytes, rate]`
- **Training data:** CICIDS2017-style synthetic dataset (55,110 flows)
- **Performance:** Precision 97.1%, Recall 42.6%, F1 59.3%

---

## Testing

```bash
# Run all tests
pytest tests/test_all.py -v

# Run specific module tests
pytest tests/test_all.py::TestDataIngestion -v
pytest tests/test_all.py::TestThreatIntel -v
pytest tests/test_all.py::TestMLDetector -v
pytest tests/test_all.py::TestSOAR -v
pytest tests/test_all.py::TestIntegration -v
```

Test coverage includes:
- Record normalisation and alias resolution
- TI cache TTL expiry
- Risk score calculation
- Feature extraction (canonical + alias names)
- Anomaly scoring and confidence classification
- SOAR playbook routing
- Full mini end-to-end integration test

---

## Security Notes

- **API keys** are stored only in `config.yaml` — add to `.gitignore` before committing
- Platform runs fully in **demo mode** without any real API keys
- All HTTP requests have a **10-second timeout**
- Email alerts require explicit `enabled: true` in config
