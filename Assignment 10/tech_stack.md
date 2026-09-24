# Technology Stack — AI Security Automation Platform

**Author:** Muhammad Huzaif Amir  
**Version:** 1.0.0

---

## Language & Runtime

| Technology | Version | Justification |
|------------|---------|---------------|
| **Python** | 3.9+ | Ecosystem richness for ML, security tooling, and automation. Widely used in SOC/SIEM tooling. |

---

## Module 1: Data Ingestion

| Technology | Role | Why chosen |
|------------|------|------------|
| **pandas** | CSV / large file reading, chunk processing | Best-in-class tabular I/O with memory-efficient chunked reading |
| **json** (stdlib) | JSONL queue writing / reading | Zero-dependency, human-readable, append-safe format |
| **pathlib** (stdlib) | File system operations | Modern, cross-platform, readable path handling |
| **uuid** (stdlib) | Event ID generation | RFC 4122 UUIDs guarantee global uniqueness without a central registry |

**Queue Format: JSONL (newline-delimited JSON)**  
- Each line is an independent JSON object → simple `tail -f` observability  
- Append-only writes are safe with concurrent readers  
- Trivially replaceable with Kafka, Redis Streams, or RabbitMQ in production

---

## Module 2: Threat Intelligence

| Technology | Role | Why chosen |
|------------|------|------------|
| **requests** | HTTP client for TI API calls | Industry standard, simple retry/timeout handling |
| **json** (stdlib) | TTL-based file cache | Portable, no Redis/Memcached dependency for dev/demo |
| **hashlib** (stdlib) | Cache key generation (SHA-256 prefix) | Deterministic, collision-resistant short keys |

**API Integrations:**

| API | What we query | Free tier |
|-----|--------------|-----------|
| **VirusTotal v3** | IP reputation, malicious engine votes | 500 req/day |
| **AbuseIPDB v2** | Abuse confidence score, country, reports | 1000 req/day |
| **AlienVault OTX** | Pulse count, threat tags, malware families | Unlimited (authenticated) |

**Demo mode** — All three APIs are mocked with realistic responses when keys are absent. Known-bad IP list (`_KNOWN_BAD`) ensures meaningful demo scores.

**Cache TTL:** 1 hour (configurable). Production recommendation: 15–30 min with Redis.

---

## Module 3: ML Detection

| Technology | Role | Why chosen |
|------------|------|------------|
| **scikit-learn** | Isolation Forest, StandardScaler | De-facto standard for production-grade ML pipelines |
| **joblib** | Model serialisation (`.pkl`) | NumPy-aware, fast binary serialisation; standard sklearn persistence |
| **numpy** | Feature array operations | Core array library, optimised C extensions |
| **pandas** | Feature DataFrame construction | Named-column access, `fillna`, `replace` for inf/NaN |

**Model: Isolation Forest**  
- Unsupervised — does not require labelled training data  
- O(n log n) training, O(log n) inference → suitable for real-time scoring  
- `decision_function()` output gives a continuous anomaly score, not just binary  
- Pre-trained model from Assignment 05 (100 estimators, contamination=0.10)

**Confidence mapping:**
```
anomaly_score < −0.30  →  HIGH confidence anomaly
−0.30 ≤ score < 0.00   →  MEDIUM confidence
score ≥ 0.00            →  LOW (normal traffic)
```

---

## Module 4: SOAR Orchestration

| Technology | Role | Why chosen |
|------------|------|------------|
| **smtplib** (stdlib) | Email alert sending | No external dependency; SMTP is universal |
| **email.mime** (stdlib) | HTML email construction | Rich notification formatting |
| **json** (stdlib) | Case/ticket persistence | Portable, version-controllable alert store |
| **uuid** (stdlib) | Case ID generation | Short (8-char hex prefix) unique case IDs |

**Ticket System:** Internal JSON file (`alerts/cases.json`).  
In production, replace with Jira REST API, ServiceNow, or TheHive integration.

**Playbook engine:** Pure Python function dispatch. Each playbook is a named function called based on composite confidence score. Extendable to n8n, Shuffle, or Cortex in production.

---

## Module 5: Dashboard

| Technology | Role | Why chosen |
|------------|------|------------|
| **Streamlit** | Web framework | Zero boilerplate for data-science dashboards; built-in reactive state |
| **Plotly** | Interactive charts | WebGL-accelerated, dark-theme ready, drill-down support |
| **pandas** | DataFrame loading and filtering | Unified data representation across the dashboard |

**Chart types used:**
- Bar charts: alert timeline, SOAR case status
- Histogram: anomaly score distribution, TI risk distribution
- Scatter geo: threat origin world map
- Scatter plot: bytes sent vs received coloured by severity
- Pie/donut: TI risk level distribution

---

## Infrastructure & Integration

| Technology | Role |
|------------|------|
| **YAML** (`pyyaml`) | Central configuration file (`config.yaml`) |
| **JSONL files** | Inter-module message queues |
| **JSON files** | Cache, case DB, analyst queue, blocked IPs |
| **Python logging** | Centralised structured logs → `logs/platform.log` |
| **pytest** | Unit and integration testing |

---

## Security Controls

| Control | Implementation |
|---------|---------------|
| **API key isolation** | Keys in `config.yaml` (not hard-coded). `.gitignore` `config.yaml` in production |
| **Input validation** | All raw records normalised; `NaN`/`Inf` replaced; type coercion |
| **Graceful degradation** | Demo mode if API keys absent; fallback model training if pkl absent |
| **No SQL injection** | No SQL layer — all storage is flat files |
| **Email credentials** | SMTP config in `config.yaml`; TLS enforced by default |

---

## Scalability Approach

| Bottleneck | Current solution | Production upgrade |
|-----------|-----------------|-------------------|
| **Ingestion throughput** | pandas CSV chunks | Apache Kafka + Flink/Spark Streaming |
| **TI cache** | JSON file (single-process) | Redis Cluster with TTL |
| **ML inference** | In-process sklearn | Triton Inference Server / ONNX Runtime |
| **SOAR case storage** | JSON files | PostgreSQL / Elasticsearch |
| **Dashboard** | Streamlit (single server) | Kubernetes + Streamlit Cloud / Grafana |
| **Parallelism** | Sequential pipeline | Celery worker pool or asyncio |
