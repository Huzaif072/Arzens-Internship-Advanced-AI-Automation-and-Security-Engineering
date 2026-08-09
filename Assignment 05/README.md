# Assignment 05 — Isolation Forest Anomaly Detection

**Author:** Muhammad Huzaif Amir · ArzensIntern Advanced Track (AI, Automation & Security Engineering)

Unsupervised network-anomaly detection with `sklearn.ensemble.IsolationForest`:
train a model, tune the alert threshold, and evaluate it (including a basic
robustness/evasion check) on a labeled network-flow dataset.

## Contents

| File | Purpose |
|---|---|
| `ArzensIntern_MuhammadHuzaifAmir_AnomalyConcept.pdf` | Task 1 — theory write-up (anomaly detection concepts, approach comparison) |
| `ArzensIntern_MuhammadHuzaifAmir_anomaly_detector.py` | Task 2 — train / predict / tune CLI (Steps 1–6) |
| `ArzensIntern_MuhammadHuzaifAmir_evaluation.py` | Task 3 — metrics, confusion matrix, robustness test, operational analysis |
| `evasion_test.py` | Standalone evasion/robustness check (Task 3, Part B) |
| `ArzensIntern_MuhammadHuzaifAmir_Anomaly_Detection.ipynb` | Notebook walkthrough of the full pipeline with inline plots |
| `config.yaml` | Model / feature / threshold configuration |
| `ROBUSTNESS.md` | Documented limitations and robustness findings |
| `ArzensIntern_MuhammadHuzaifAmir_AI_Assistance_Note.md` | AI assistance disclosure |
| `sample_data/network_traffic_dataset.csv` | Labeled synthetic network-flow dataset (55,110 rows) used for training/evaluation |
| `bonus/` | Bonus Practical Tasks 1 & 2 (dataset comparison + Streamlit dashboard) — see `bonus/README_bonus.md` |
| `outputs/` | Generated model, scaler, predictions, and evaluation report (produced by running the scripts below) |

## Setup

```bash
pip install pandas numpy scikit-learn matplotlib joblib
```

Python 3.9+ recommended. No GPU required.

## Dataset

The assignment allows either the UNSW-NB15 Kaggle dataset or a synthetic
generator from a previous assignment. This submission uses the synthetic
CICIDS2017-style flow dataset (`sample_data/network_traffic_dataset.csv`,
55,110 flows, ~22% attack traffic across DoS, PortScan, BruteForce,
WebAttack, Botnet, and Infiltration).

`anomaly_detector.py` requests the six canonical UNSW-NB15 features
(`dur, spkts, dpkts, sbytes, dbytes, rate`). A feature-alias map in the
script automatically resolves these to the equivalent columns in the
synthetic dataset (`flow_duration, total_fwd_packets, total_bwd_packets,
total_fwd_bytes, total_bwd_bytes, flow_packets_per_sec`), so the exact same
script also runs unmodified against a real UNSW-NB15 CSV if you drop one in.

The `label_binary` column (Benign/Attack) is carried through **only** for
evaluation and reporting — it is never used to fit the Isolation Forest,
which trains in a fully unsupervised manner.

## Usage

### 1. Train

```bash
python ArzensIntern_MuhammadHuzaifAmir_anomaly_detector.py \
  --mode train \
  --data sample_data/network_traffic_dataset.csv \
  --output outputs/isolation_forest_model.pkl \
  --output-csv outputs/train_test_predictions.csv
```

Saves `outputs/isolation_forest_model.pkl`, `outputs/standard_scaler.pkl`,
and `outputs/test_split.pkl` (the held-out test split, reused by the
evaluation scripts).

### 2. Tune the decision threshold

```bash
python ArzensIntern_MuhammadHuzaifAmir_anomaly_detector.py \
  --mode tune \
  --data sample_data/network_traffic_dataset.csv \
  --plot outputs/threshold_tuning.png
```

Sweeps thresholds `[-0.5, -0.3, -0.1, 0.0, 0.1, 0.3]`, prints a
precision/recall/F1 table, and saves a comparison plot.

### 3. Predict on new data

```bash
python ArzensIntern_MuhammadHuzaifAmir_anomaly_detector.py \
  --mode predict \
  --data sample_data/network_traffic_dataset.csv \
  --model outputs/isolation_forest_model.pkl \
  --output outputs/predict_results.csv
```

### 4. Evaluate (Task 3)

```bash
python ArzensIntern_MuhammadHuzaifAmir_evaluation.py \
  --data sample_data/network_traffic_dataset.csv \
  --model outputs/isolation_forest_model.pkl \
  --scaler outputs/standard_scaler.pkl \
  --threshold 0.0 \
  --outdir outputs/evaluation_output
```

Produces, in `outputs/evaluation_output/`:
- `confusion_matrix.png` — heatmap
- `threshold_tuning.png` + `threshold_tuning_summary.csv` — precision/recall/F1 sweep
- `per_attack_type_breakdown.csv` — detection rate by attack category
- `robustness_results.json` — evasion test results
- `metrics_summary.json` — all metrics in one file
- `evaluation_report.html` — the full human-readable report

### 5. Standalone evasion test (optional)

```bash
python evasion_test.py \
  --data sample_data/network_traffic_dataset.csv \
  --model outputs/isolation_forest_model.pkl \
  --scaler outputs/standard_scaler.pkl \
  --threshold 0.0
```

## Results summary (this submission's run)

| Metric | Value |
|---|---|
| Accuracy | 87.3% |
| Precision | 97.1% |
| Recall | 42.6% |
| F1-Score | 59.3% |
| False Positive Rate | 0.3% |
| Robustness status | FRAGILE (~46% of perturbed anomalies still caught) |
| Expected alerts/day (10k events) | ~948 (exceeds assumed 50/day analyst capacity at threshold 0.0) |

See `ROBUSTNESS.md` for a fuller discussion of these numbers, and
`outputs/evaluation_output/evaluation_report.html` for the complete report.

## Reproducibility

`random_state=42` is fixed everywhere (train/test split, Isolation Forest,
noise generation in the evasion test), so re-running the commands above
reproduces the same numbers.
