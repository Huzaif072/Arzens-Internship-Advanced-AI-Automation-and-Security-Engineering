# Integration Plan — AI Security Automation Platform

**Author:** Muhammad Huzaif Amir  
**Version:** 1.0.0

---

## Module Connection Map

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AI Security Automation Platform                       │
│                                                                         │
│  ┌─────────────┐    JSONL     ┌─────────────┐    JSONL                 │
│  │  MODULE 1   │─────────────▶│  MODULE 2   │─────────────▶            │
│  │  Ingestion  │              │  TI Enrich  │                           │
│  └─────────────┘              └──────┬──────┘                           │
│       ▲                              │ JSON cache                       │
│       │                       cache/ │ ti_cache.json                    │
│  External Sources                    │                                  │
│  • Log files                   JSONL ▼                                  │
│  • CSV flows              ┌─────────────┐    JSONL                      │
│  • Stream sim             │  MODULE 3   │─────────────▶                 │
│                           │  ML Detect  │                               │
│                           └──────┬──────┘                               │
│                                  │                                      │
│                            JSONL ▼                                      │
│                           ┌─────────────┐    JSON                       │
│                           │  MODULE 4   │─────────────▶ alerts/         │
│                           │    SOAR     │               ├ cases.json    │
│                           └──────┬──────┘               ├ analyst_queue │
│                                  │                      └ blocked_ips   │
│                                  │ email (SMTP, optional)               │
│                          Analyst │                                      │
│                           ┌──────▼──────┐                               │
│                           │  MODULE 5   │◀── All JSON/JSONL files       │
│                           │  Dashboard  │    (read-only polling)        │
│                           └─────────────┘                               │
│                                  │                                      │
│                           Browser│(HTTP)                                │
│                                  ▼                                      │
│                            SOC Analyst                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Inter-Module Interfaces

### 1 → 2: Ingestion Queue

| Attribute | Value |
|-----------|-------|
| **File** | `data/ingestion_queue.jsonl` |
| **Format** | Newline-delimited JSON (JSONL) |
| **Direction** | Module 1 writes → Module 2 reads |
| **Schema** | Common Event Schema (see `data_flow.md`) |
| **Backpressure** | Module 2 can lag; queue is append-only |

### 2 → 3: Enriched Queue

| Attribute | Value |
|-----------|-------|
| **File** | `data/enriched_queue.jsonl` |
| **Format** | JSONL — original event + TI fields |
| **Direction** | Module 2 writes → Module 3 reads |
| **New keys** | `ti_src`, `ti_dst`, `ti_max_risk`, `ti_risk_level` |

### 3 → 4: Scored Events

| Attribute | Value |
|-----------|-------|
| **File** | `data/scored_events.jsonl` |
| **Format** | JSONL — enriched event + ML scoring fields |
| **Direction** | Module 3 writes → Module 4 reads |
| **New keys** | `anomaly_score`, `is_anomaly`, `confidence_level`, `ml_alert` |

### 4 → 5: Case & Alert Files

| File | Written by | Read by |
|------|-----------|---------|
| `alerts/cases.json` | Module 4 | Module 5 |
| `alerts/analyst_queue.json` | Module 4 | Module 5 |
| `alerts/blocked_ips.json` | Module 4 | Module 5 |

### 5 ← All Modules: Dashboard Polling

Module 5 reads all data files every 10 seconds (configurable). It never writes to any data file, ensuring zero side-effects from the UI.

---

## Configuration Integration (`config.yaml`)

All 5 modules share a single YAML configuration file. Cross-cutting settings:

```yaml
# Shared logging → same log file for all modules
logging:
  file: "logs/platform.log"
  level: "INFO"

# Shared queue paths — modules reference same file paths
ingestion:
  output_queue: "data/ingestion_queue.jsonl"
```

Modules read the config at startup; no runtime config reloading required for MVP.

---

## External API Integration

### VirusTotal v3

```
GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
Headers: x-apikey: {VT_API_KEY}
```

Rate limit: 500 req/day (public). Mitigated by 1-hour TTL cache.

### AbuseIPDB v2

```
GET https://api.abuseipdb.com/api/v2/check
Headers: Key: {ABUSEIPDB_KEY}
Params: ipAddress, maxAgeInDays=90, verbose=true
```

Rate limit: 1000 req/day. Mitigated by cache.

### AlienVault OTX

```
GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
Headers: X-OTX-API-KEY: {OTX_KEY}
```

No hard rate limit for authenticated users.

### Fallback / Demo Mode

When `threat_intel.demo_mode: true` (default), all API calls are replaced by deterministic mock responses. Known-bad IP list drives realistic HIGH-risk mock scores.

---

## Email Notification Integration (SOAR)

```
Protocol: SMTP with STARTTLS
Library: Python stdlib smtplib
Config: soar.email in config.yaml
Trigger: High-confidence alerts (composite confidence ≥ 75) when auto_notify: true
```

Email is disabled by default (`enabled: false`) so the platform runs without any SMTP setup.

---

## Orchestrator (`platform.py`)

The main orchestrator imports each module's public API directly (no subprocess overhead for `full` mode):

```python
from ingest_logs  import run_ingestion
from ti_enricher  import TIEnricher
from ml_detector  import MLDetector
from soar_engine  import SOAREngine
# dashboard launched via subprocess (Streamlit requires its own process)
```

All exceptions in each stage are caught and logged; the pipeline continues to the next stage (graceful degradation).

---

## Security Controls

| Control | Mechanism |
|---------|-----------|
| **API key storage** | `config.yaml` only — never in source code |
| **API timeouts** | 10-second timeout on all HTTP requests (`requests.get(..., timeout=10)`) |
| **Cache key hashing** | SHA-256 prefix prevents key enumeration |
| **Email credential security** | SMTP credentials in config (not logged or printed) |
| **Input sanitisation** | All raw fields type-coerced; `NaN`/`Inf` replaced before ML inference |
| **No shell injection** | Dashboard launched via `subprocess.run([...])` list form, never shell=True |

---

## Deployment Topology

### Development (single machine)

```
python platform.py --mode full      # pipeline
streamlit run dashboard.py          # dashboard in separate terminal
```

### Production (recommended)

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│  Kafka      │     │  Workers     │     │  Redis         │
│  (ingest)   │────▶│  (TI+ML+SOAR)│────▶│  (TI cache)    │
└─────────────┘     └──────────────┘     └────────────────┘
                          │
                    ┌─────▼───────┐
                    │ PostgreSQL  │
                    │ (cases DB)  │
                    └─────────────┘
                          │
                    ┌─────▼───────┐
                    │  Grafana /  │
                    │  Streamlit  │
                    └─────────────┘
```

### Scaling to 10× traffic

| Stage | Current limit | 10× solution |
|-------|-------------|--------------|
| Ingestion | ~10K events/run | Kafka partitions + parallel consumers |
| TI Enrichment | ~100 IPs/min (cached) | Redis cache + async `aiohttp` queries |
| ML Inference | ~50K rows/sec (sklearn) | Ray cluster or Triton server |
| SOAR | JSON file I/O | PostgreSQL with connection pooling |
| Dashboard | Single Streamlit process | K8s deployment + CDN-cached assets |
