# Assignment 02 — Security Log Parser & Validator

## Project Structure

```
assignment02/
├── log_parser.py                  Task 2 — Multi-format log parser
├── test_log_parser.py             Task 2 — pytest unit tests
├── sample_firewall_logs.csv       Task 2 — Firewall sample input (15 records)
├── sample_auth_logs.txt           Task 2 — Authentication sample input (15 records)
├── sample_dns_logs.txt            Task 2 — DNS sample input (15 records)
├── output_normalized.jsonl        Task 2 — Parser output (sample)
├── quality_validator.py           Task 3 — Data quality validator
├── test_quality_validator.py      Task 3 — pytest unit tests
├── sample_validation_report.csv   Task 3 — Example CSV report
├── sample_validation_summary.json Task 3 — Example JSON summary
├── generate_bulk_logs.py          Task 4 — Synthetic bulk log generator
├── output_bulk.jsonl              Task 4 — Parser output on 5,010 records
├── bulk_validation_report.csv     Task 4 — Validator output at scale
├── bulk_validation_summary.json   Task 4 — JSON summary at scale
├── PERFORMANCE.md                 Task 4 — Performance notes
└── README.md                      This file
```

---

## Requirements

- Python 3.10+
- pytest (`pip install pytest`)

No third-party libraries are used beyond the Python standard library and pytest.

---

## Task 2 — Log Parser

### Supported Formats

| Format | Style | Example |
|--------|-------|---------|
| Firewall | CSV | `2026-07-15T10:23:45Z,192.168.1.100,10.0.0.50,443,ALLOW,15234` |
| Auth | Space-delimited | `2026-07-15 10:23:45 alice_web corporate-vpn SUCCESS 203.0.113.45` |
| DNS | Key-value | `query_time=2026-07-15T10:23:45Z\|client=192.168.1.50\|domain=bad.com\|type=A\|response=NXDOMAIN` |

### Usage

```bash
# Parse firewall logs
python log_parser.py --input sample_firewall_logs.csv --format firewall --output out.jsonl

# Parse auth logs
python log_parser.py --input sample_auth_logs.txt --format auth --output out.jsonl

# Parse DNS logs
python log_parser.py --input sample_dns_logs.txt --format dns --output out.jsonl

# Auto-detect format per line (mixed file)
python log_parser.py --input bulk_logs_mixed.txt --output output_bulk.jsonl
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Path to input log file (required) |
| `--format`, `-f` | `firewall`, `auth`, or `dns` (optional; auto-detects if omitted) |
| `--output`, `-o` | Path for JSONL output (default: `output_normalized.jsonl`) |

### Output Schema (JSONL)

Each line is a JSON object:

```json
{
  "event_id":      "uuid4 string",
  "timestamp":     "YYYY-MM-DDTHH:MM:SSZ",
  "source_ip":     "IPv4/IPv6 or null",
  "target_ip":     "IPv4/IPv6 or null",
  "user":          "username/domain or null",
  "action":        "ALLOW|DENY|SUCCESS|FAILURE|QUERY|RESPONSE",
  "status":        "success|failure|unknown",
  "log_type":      "firewall|auth|dns",
  "original_line": "raw input line",
  "parsed_at":     "YYYY-MM-DDTHH:MM:SSZ"
}
```

### Running Tests

```bash
pytest test_log_parser.py -v
```

Expected: 20+ tests passing (covers all three formats, timestamp normalization,
IP validation, malformed-line handling, and end-to-end file output).

---

## Task 3 — Data Quality Validator

Validates the JSONL output from the log parser and produces three reports.

### Usage

```bash
python quality_validator.py --input output_normalized.jsonl
python quality_validator.py --input output_bulk.jsonl \
    --csv bulk_validation_report.csv \
    --json bulk_validation_summary.json
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--input`, `-i` | Path to JSONL file to validate (required) |
| `--csv` | Path for CSV report (default: `sample_validation_report.csv`) |
| `--json` | Path for JSON summary (default: `sample_validation_summary.json`) |

### Validation Checks

| # | Check | Severity |
|---|-------|----------|
| 1 | Missing critical fields (event_id, timestamp, source_ip, action, log_type) | ERROR |
| 2 | Invalid or private IP addresses | ERROR / WARNING |
| 3 | Future timestamps, timestamps older than 1 year, unparseable formats | WARNING / ERROR |
| 4 | Duplicate event_ids | ERROR |
| 5 | Impossible action/status combos, extreme byte counts, rapid events | WARNING / INFO |

### Running Tests

```bash
pytest test_quality_validator.py -v
```

Expected: 25+ tests passing (one per check plus end-to-end runs).

---

## Task 4 — Scale & Performance

### Generate bulk data

```bash
python generate_bulk_logs.py --count 5010 --output bulk_logs_mixed.txt
```

### Run parser at scale

```bash
python log_parser.py --input bulk_logs_mixed.txt --output output_bulk.jsonl
```

### Run validator at scale

```bash
python quality_validator.py \
    --input output_bulk.jsonl \
    --csv bulk_validation_report.csv \
    --json bulk_validation_summary.json
```

See `PERFORMANCE.md` for measured runtimes, throughput numbers, and
optimization recommendations.

---

## AI Assistance Note

This assignment was completed with AI assistance (Replit Agent). All code was
reviewed for correctness, and the author takes full responsibility for the
accuracy and originality of the final submission.
