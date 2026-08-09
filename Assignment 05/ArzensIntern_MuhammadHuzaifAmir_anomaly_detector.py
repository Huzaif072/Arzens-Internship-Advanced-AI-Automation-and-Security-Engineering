#!/usr/bin/env python3
"""
anomaly_detector.py
====================
Assignment 05 - Task 2: Isolation Forest Anomaly Detector
Author: Muhammad Huzaif Amir | ArzensIntern - Advanced Track

A practical, CLI-driven anomaly detection system built on
sklearn.ensemble.IsolationForest. Implements the six steps required by the
assignment manual:

    1. Data preparation (load, clean, split)
    2. Feature engineering (select + scale numeric flow features)
    3. Model training (Isolation Forest)
    4. Prediction & scoring (predict + decision_function)
    5. Threshold tuning (precision / recall / F1 sweep)
    6. Output & saving (CSV results, model, scaler, summary stats)

Usage
-----
    # Train a model
    python anomaly_detector.py --mode train --data data.csv --output model.pkl

    # Predict on new data with a trained model
    python anomaly_detector.py --mode predict --data new_data.csv --model model.pkl --output results.csv

    # Sweep thresholds and plot precision/recall trade-offs
    python anomaly_detector.py --mode tune --data data.csv

Notes on dataset compatibility
-------------------------------
The assignment's reference dataset is UNSW-NB15, which uses the feature
names `dur, spkts, dpkts, sbytes, dbytes, rate`. This implementation instead
ships with (and defaults to) the synthetic CICIDS2017-style flow dataset
generated for Assignment 04 (`network_traffic_dataset.csv`), which the
assignment manual explicitly allows ("OR use your synthetic data generator
from previous assignments"). A feature alias map (FEATURE_ALIASES below)
translates the UNSW-NB15 names to the equivalent columns in that dataset, so
the exact same script also runs unmodified against a real UNSW-NB15 CSV.
"""

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# matplotlib is optional at import time so --mode train/predict still work
# in headless environments without a display backend already configured.
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Canonical feature set requested by the assignment manual (UNSW-NB15 names),
# mapped to the equivalent column in our CICIDS2017-style synthetic dataset.
# dur    -> flow_duration          (flow duration)
# spkts  -> total_fwd_packets      (source/forward packet count)
# dpkts  -> total_bwd_packets      (destination/backward packet count)
# sbytes -> total_fwd_bytes        (source/forward byte count)
# dbytes -> total_bwd_bytes        (destination/backward byte count)
# rate   -> flow_packets_per_sec   (flow rate, packets/sec)
FEATURE_ALIASES = {
    "dur": "flow_duration",
    "spkts": "total_fwd_packets",
    "dpkts": "total_bwd_packets",
    "sbytes": "total_fwd_bytes",
    "dbytes": "total_bwd_bytes",
    "rate": "flow_packets_per_sec",
}

CANONICAL_FEATURES = list(FEATURE_ALIASES.keys())
DEFAULT_LABEL_COLUMN = "label_binary"   # present only for evaluation, never used to fit the model
DEFAULT_THRESHOLDS = [-0.5, -0.3, -0.1, 0.0, 0.1, 0.3]
RANDOM_STATE = 42


# ---------------------------------------------------------------------------
# Step 1 + 2: Data preparation & feature engineering
# ---------------------------------------------------------------------------

def resolve_feature_columns(df: pd.DataFrame) -> dict:
    """Map the six canonical UNSW-NB15 feature names onto whatever columns
    are actually present in the supplied CSV (native UNSW-NB15 names, or
    the CICIDS2017-style alias names used by our synthetic generator)."""
    resolved = {}
    for canonical, alias in FEATURE_ALIASES.items():
        if canonical in df.columns:
            resolved[canonical] = canonical
        elif alias in df.columns:
            resolved[canonical] = alias
        else:
            raise ValueError(
                f"Could not find feature '{canonical}' (or alias '{alias}') in the "
                f"dataset. Available columns: {list(df.columns)}"
            )
    return resolved


def load_and_prepare_data(data_path: str):
    """STEP 1 - Data Preparation.

    Loads the CSV, selects the six numeric flow features (dropping
    categorical columns), imputes missing values with the column median,
    and returns the feature frame plus (if present) a ground-truth label
    series used only for evaluation/reporting - never for fitting the model.
    """
    print(f"Loading data from: {data_path}")
    df = pd.read_csv(data_path)
    print(f"  Raw shape: {df.shape[0]:,} rows x {df.shape[1]} columns")

    col_map = resolve_feature_columns(df)
    feature_df = df[[col_map[c] for c in CANONICAL_FEATURES]].copy()
    feature_df.columns = CANONICAL_FEATURES  # normalize to canonical names

    # Handle missing values -> median imputation (per assignment spec)
    n_missing = int(feature_df.isna().sum().sum())
    if n_missing > 0:
        print(f"  Filling {n_missing} missing values with column medians")
        feature_df = feature_df.fillna(feature_df.median(numeric_only=True))

    # Replace any inf values that can appear in rate/bytes-per-sec fields
    feature_df = feature_df.replace([np.inf, -np.inf], np.nan)
    feature_df = feature_df.fillna(feature_df.median(numeric_only=True))

    labels = None
    if DEFAULT_LABEL_COLUMN in df.columns:
        # Ground truth is carried along ONLY for evaluation/reporting.
        labels = (df[DEFAULT_LABEL_COLUMN].astype(str).str.lower() != "benign").astype(int)
        labels.name = "ground_truth_is_anomaly"

    print(f"  Selected features: {CANONICAL_FEATURES}")
    return feature_df, labels, df


def train_test_split_manual(X: pd.DataFrame, y, test_ratio=0.2, random_state=RANDOM_STATE):
    """80/20 train/test split (STEP 1).

    Deliberately does NOT reset the index on the returned frames: the
    original row positions from the source CSV are preserved so that
    downstream code (e.g. the per-attack-type breakdown in evaluation.py)
    can map test-set predictions back to the raw dataframe with
    `raw_df.loc[X_test.index]` without any risk of misalignment.
    """
    rng = np.random.RandomState(random_state)
    n = len(X)
    idx = rng.permutation(n)
    n_test = int(n * test_ratio)
    test_idx, train_idx = idx[:n_test], idx[n_test:]

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train = y.iloc[train_idx] if y is not None else None
    y_test = y.iloc[test_idx] if y is not None else None
    return X_train, X_test, y_train, y_test


# ---------------------------------------------------------------------------
# Step 3: Model training
# ---------------------------------------------------------------------------

def train_model(X_train_scaled, n_estimators=100, contamination=0.1, random_state=RANDOM_STATE):
    """STEP 3 - Fit Isolation Forest on the training split only."""
    print("\nTraining Isolation Forest...")
    print(f"  Samples: {X_train_scaled.shape[0]:,}")
    print(f"  Features: {X_train_scaled.shape[1]}")
    print(f"  Contamination: {contamination}")

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)
    print("  Model trained successfully!")
    return model


# ---------------------------------------------------------------------------
# Step 4: Prediction & scoring
# ---------------------------------------------------------------------------

def score_samples(model, X_scaled):
    """STEP 4 - Predict labels (1 normal / -1 anomaly) and anomaly scores
    (lower = more anomalous), then convert to binary 0/1 labels."""
    raw_pred = model.predict(X_scaled)              # 1 normal, -1 anomaly
    scores = model.decision_function(X_scaled)       # lower = more anomalous
    is_anomaly_default = (raw_pred == -1).astype(int)  # 0 normal, 1 anomaly
    return scores, is_anomaly_default


def labels_at_threshold(scores, threshold):
    """Binary anomaly labels for an arbitrary decision_function threshold:
    score < threshold => anomaly (1), else normal (0)."""
    return (scores < threshold).astype(int)


# ---------------------------------------------------------------------------
# Step 5: Threshold tuning
# ---------------------------------------------------------------------------

def precision_recall_f1(y_true, y_pred):
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1}


def tune_thresholds(scores, y_true, thresholds=DEFAULT_THRESHOLDS, plot_path=None):
    """STEP 5 - Sweep thresholds, compute precision/recall/F1, optionally plot."""
    if y_true is None:
        print("  No ground-truth labels available in this dataset -> cannot compute "
              "precision/recall/F1 for tuning. Skipping threshold sweep metrics.")
        return None

    y_true = np.asarray(y_true)
    rows = []
    for t in thresholds:
        y_pred = labels_at_threshold(scores, t)
        m = precision_recall_f1(y_true, y_pred)
        m["threshold"] = t
        rows.append(m)

    results = pd.DataFrame(rows)[["threshold", "tp", "fp", "fn", "tn", "precision", "recall", "f1"]]
    print("\nThreshold tuning results:")
    print(results.to_string(index=False, float_format=lambda x: f"{x:.3f}"))

    best_row = results.loc[results["f1"].idxmax()]
    print(f"\n  Best F1 at threshold={best_row['threshold']}: "
          f"P={best_row['precision']:.3f} R={best_row['recall']:.3f} F1={best_row['f1']:.3f}")

    if plot_path:
        fig, ax = plt.subplots(figsize=(8, 5))
        ax.plot(results["threshold"], results["precision"], marker="o", label="Precision")
        ax.plot(results["threshold"], results["recall"], marker="s", label="Recall")
        ax.plot(results["threshold"], results["f1"], marker="^", label="F1-Score")
        ax.set_xlabel("Decision function threshold (score < threshold => anomaly)")
        ax.set_ylabel("Score")
        ax.set_title("Precision / Recall / F1 vs. Threshold")
        ax.legend()
        ax.grid(alpha=0.3)
        fig.tight_layout()
        fig.savefig(plot_path, dpi=150)
        plt.close(fig)
        print(f"  Saved threshold tuning plot: {plot_path}")

    return results, float(best_row["threshold"])


# ---------------------------------------------------------------------------
# Step 6: Output & saving
# ---------------------------------------------------------------------------

def save_predictions_csv(raw_df, X, scores, is_anomaly, out_path):
    out = raw_df.copy()
    for col in CANONICAL_FEATURES:
        out[col] = X[col].values
    out["anomaly_score"] = scores
    out["is_anomaly"] = is_anomaly
    out.insert(0, "timestamp", pd.Timestamp.now("UTC").isoformat())
    out.to_csv(out_path, index=False)
    print(f"  Predictions saved: {out_path}")


def print_banner():
    print("+" + "=" * 58 + "+")
    print("|         ANOMALY DETECTION SYSTEM v1.0" + " " * 20 + "|")
    print("+" + "=" * 58 + "+")


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def run_train(args):
    print_banner()
    X, y, raw_df = load_and_prepare_data(args.data)
    X_train, X_test, y_train, y_test = train_test_split_manual(X, y, test_ratio=0.2)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = train_model(X_train_scaled, n_estimators=args.n_estimators,
                         contamination=args.contamination)

    print("\nEvaluating on test set...")
    scores, is_anomaly_default = score_samples(model, X_test_scaled)
    threshold = 0.0
    print(f"  Threshold: {threshold}")

    if y_test is not None:
        m = precision_recall_f1(y_test.values, labels_at_threshold(scores, threshold))
        print(f"  Precision: {m['precision']:.2f} ({m['precision']*100:.0f}% of alerts are real)")
        print(f"  Recall: {m['recall']:.2f} ({m['recall']*100:.0f}% of anomalies caught)")
        print(f"  F1-Score: {m['f1']:.2f}")

    n_anom = int(is_anomaly_default.sum())
    n_norm = len(is_anomaly_default) - n_anom
    print("\nAnomaly Distribution:")
    print(f"  Normal: {n_norm:,} ({n_norm/len(is_anomaly_default)*100:.0f}%)")
    print(f"  Anomaly: {n_anom:,} ({n_anom/len(is_anomaly_default)*100:.0f}%)")

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)
    scaler_path = str(Path(args.output).with_name("standard_scaler.pkl"))
    joblib.dump(scaler, scaler_path)
    print(f"\nModel saved: {args.output}")
    print(f"Scaler saved: {scaler_path}")

    # Also persist the held-out test split + labels so evaluation.py can reuse
    # the exact same test set without re-splitting.
    test_bundle_path = str(Path(args.output).with_name("test_split.pkl"))
    joblib.dump({
        "X_test": X_test, "X_test_scaled": X_test_scaled, "y_test": y_test,
        "scores": scores, "is_anomaly_default": is_anomaly_default,
    }, test_bundle_path)
    print(f"Test split saved: {test_bundle_path}")

    if args.output_csv:
        placeholder = pd.DataFrame(index=X_test.index)
        save_predictions_csv(placeholder, X_test, scores, is_anomaly_default, args.output_csv)


def run_predict(args):
    print_banner()
    model = joblib.load(args.model)
    scaler_path = Path(args.model).with_name("standard_scaler.pkl")
    if not scaler_path.exists():
        print(f"ERROR: expected scaler at {scaler_path} (saved alongside the model during training).")
        sys.exit(1)
    scaler = joblib.load(scaler_path)

    X, y, raw_df = load_and_prepare_data(args.data)
    X_scaled = scaler.transform(X)

    scores, is_anomaly_default = score_samples(model, X_scaled)

    n_anom = int(is_anomaly_default.sum())
    n_norm = len(is_anomaly_default) - n_anom
    print("\nPrediction summary:")
    print(f"  Total samples: {len(X):,}")
    print(f"  Normal: {n_norm:,} ({n_norm/len(X)*100:.1f}%)")
    print(f"  Anomaly: {n_anom:,} ({n_anom/len(X)*100:.1f}%)")

    if y is not None:
        m = precision_recall_f1(y.values, is_anomaly_default)
        print(f"  Precision: {m['precision']:.3f}  Recall: {m['recall']:.3f}  F1: {m['f1']:.3f}")

    out_path = args.output or "results.csv"
    save_predictions_csv(raw_df, X, scores, is_anomaly_default, out_path)


def run_tune(args):
    print_banner()
    X, y, raw_df = load_and_prepare_data(args.data)
    X_train, X_test, y_train, y_test = train_test_split_manual(X, y, test_ratio=0.2)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = train_model(X_train_scaled, n_estimators=args.n_estimators,
                         contamination=args.contamination)
    scores, _ = score_samples(model, X_test_scaled)

    plot_path = args.plot or "threshold_tuning.png"
    result = tune_thresholds(scores, y_test, thresholds=DEFAULT_THRESHOLDS, plot_path=plot_path)

    if result is not None:
        results_df, best_threshold = result
        summary_path = "threshold_tuning_summary.csv"
        results_df.to_csv(summary_path, index=False)
        print(f"\nSaved threshold summary table: {summary_path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Isolation Forest based network anomaly detector (Assignment 05, Task 2)"
    )
    p.add_argument("--mode", choices=["train", "predict", "tune"], required=True)
    p.add_argument("--data", required=True, help="Path to input CSV")
    p.add_argument("--model", help="Path to a trained model .pkl (required for --mode predict)")
    p.add_argument("--output", help="Output path: model .pkl for train, results .csv for predict")
    p.add_argument("--output-csv", help="(train mode) also write test-set predictions to this CSV")
    p.add_argument("--n-estimators", type=int, default=100)
    p.add_argument("--contamination", type=float, default=0.1)
    p.add_argument("--plot", help="(tune mode) path to save the precision/recall/F1 plot")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.mode == "train":
        args.output = args.output or "isolation_forest_model.pkl"
        run_train(args)
    elif args.mode == "predict":
        if not args.model:
            parser.error("--model is required for --mode predict")
        run_predict(args)
    elif args.mode == "tune":
        run_tune(args)


if __name__ == "__main__":
    start = time.time()
    main()
    print(f"\nDone in {time.time() - start:.1f}s")
