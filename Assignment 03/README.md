# Security Feature Engineering — Usage Guide

This submission contains two scripts:

1. `feature_extractor.py` — turns raw security events into an ML-ready feature matrix.
2. `quality_validator.py` — validates a feature matrix for quality issues and distribution drift.

## Requirements

```
pip install pandas numpy scipy
```
(all other imports — `argparse`, `json`, `csv`, `hashlib`, `hmac` — are Python standard library)

## 1. feature_extractor.py

### Basic usage

```
python3 feature_extractor.py --input sample_raw_events.jsonl --output sample_features.csv --window user-hour
```

This produces `sample_features.csv` and, alongside it, `sample_features.json`
(same base filename, `.json` extension) — one row/object per (entity, hour)
window.

### Options

- `--input FILE` (required): path to a JSONL file of raw events (one JSON
  object per line). Each event must include `timestamp` and `event_type`
  (`AUTH`, `NETWORK`, or `DNS`), plus the fields specific to that type — see
  the module docstring in `feature_extractor.py` for the exact field list.
- `--output FILE` (required): path for the CSV feature matrix. The JSON
  output is written next to it with the same name, `.json` extension.
- `--window {user-hour,host-hour}` (default `user-hour`): whether to
  aggregate by username or by host/IP. See "Entity resolution" in
  `feature_dictionary.md` for how each window type sources its features from
  the three log types.
- `--rolling {1h,4h,24h}` (optional): adds trailing rolling-sum columns for
  `login_failure_count`, `login_success_count`, and `bytes_transferred` on
  top of the hourly buckets.

### Example: host-hour window with a 24h rolling aggregation

```
python3 feature_extractor.py --input sample_raw_events.jsonl \
    --output features_host_24h.csv --window host-hour --rolling 24h
```

### Regenerating the sample data (optional)

`sample_raw_events.jsonl` was generated with `generate_sample_events.py`
(seeded, so it's reproducible: `python3 generate_sample_events.py`). Not a
graded deliverable, but included for reproducibility.

## 2. quality_validator.py

### Basic usage

```
python3 quality_validator.py --input sample_features.csv \
    --reference sample_reference_features.csv \
    --output sample_quality_report.html --format html
```

This prints a console PASS/WARNING/FAIL summary, and writes:
- `sample_quality_report.html` — the human-readable report (or `.md` / `.json` depending on `--format`)
- `sample_quality_report_issues.csv` — one row per finding (`line_number, check_type, severity, description, recommended_action`)
- `sample_quality_report_summary.json` — machine-readable summary stats

### Options

- `--input FILE` (required): the feature matrix CSV to validate (as produced by `feature_extractor.py`).
- `--reference FILE` (optional): a baseline feature matrix CSV to compare against for drift detection. Drift checks are skipped if omitted.
- `--output FILE` (default `quality_report.html`): path for the main report file.
- `--format {html,markdown,json}` (default `html`): format of the main report file.
- `--threshold FLOAT` (default `0.05`): used both as the null-value-percentage threshold and the drift p-value significance threshold.
- `--csv-report FILE` (optional): override the path for the per-issue CSV log (defaults to `<output-stem>_issues.csv`).

### What's checked

See `drift_analysis.md` for the drift methodology in detail, and
`feature_dictionary.md` for the schema each check validates against.
The five checks are: schema validation, null/missing value checks,
range/sanity checks, duplicate `(window_id, entity_id)` detection, and
distribution + concept drift detection.

## AI Assistance Note

[Complete before submission: name the tool used and briefly describe how it
was used, e.g., drafting assistance, brainstorming structure, or editing.]
