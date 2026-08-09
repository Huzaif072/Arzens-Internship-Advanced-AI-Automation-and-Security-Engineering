#!/usr/bin/env python3
"""
evasion_test.py
================
Assignment 05 - Task 3, Part B (standalone, optional deliverable).

A minimal, standalone version of the robustness/evasion check so it can be
run and read independently of the full evaluation.py report. Takes a
trained model + scaler, perturbs known test-set anomalies, and prints an
evasion success rate.

Usage:
    python evasion_test.py --data sample_data/network_traffic_dataset.csv \
                            --model outputs/isolation_forest_model.pkl \
                            --scaler outputs/standard_scaler.pkl \
                            --threshold 0.0
"""

import argparse
import joblib
import numpy as np
import pandas as pd

from ArzensIntern_MuhammadHuzaifAmir_anomaly_detector import (
    load_and_prepare_data, train_test_split_manual, labels_at_threshold, RANDOM_STATE,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--scaler", required=True)
    ap.add_argument("--threshold", type=float, default=0.0)
    args = ap.parse_args()

    model = joblib.load(args.model)
    scaler = joblib.load(args.scaler)

    X, y, raw_df = load_and_prepare_data(args.data)
    if y is None:
        raise SystemExit("Dataset has no ground-truth label column - cannot select known anomalies.")

    _, X_test, _, y_test = train_test_split_manual(X, y, test_ratio=0.2)
    X_anom = X_test.loc[y_test.values == 1]
    print(f"Testing evasion against {len(X_anom):,} known anomalies from the test set.\n")

    rng = np.random.RandomState(RANDOM_STATE)

    def detected_rate(df):
        scores = model.decision_function(scaler.transform(df))
        return labels_at_threshold(scores, args.threshold).mean()

    baseline = detected_rate(X_anom)
    print(f"Baseline detection rate (no perturbation): {baseline*100:.1f}%")

    std = X_anom.std().values

    scenarios = {
        "10% Gaussian noise": pd.DataFrame(
            X_anom.values + std * 0.10 * rng.randn(*X_anom.shape), columns=X_anom.columns
        ).clip(lower=0),
        "Scale x0.9": X_anom * 0.9,
        "Scale x1.1": X_anom * 1.1,
        "Combined (noise + scale-down)": pd.DataFrame(
            X_anom.values * 0.9 + std * 0.10 * rng.randn(*X_anom.shape), columns=X_anom.columns
        ).clip(lower=0),
    }

    rates = []
    for name, variant in scenarios.items():
        rate = detected_rate(variant)
        evasion_rate = 1 - rate
        rates.append(rate)
        print(f"  {name:35s} -> still detected: {rate*100:5.1f}%   evasion success: {evasion_rate*100:5.1f}%")

    avg_detected = float(np.mean(rates))
    if avg_detected > 0.80:
        status = "ROBUST"
    elif avg_detected < 0.50:
        status = "FRAGILE"
    else:
        status = "MODERATE"

    print(f"\nAverage still-detected rate across perturbations: {avg_detected*100:.1f}%")
    print(f"Robustness status: {status}")
    print(f'Document: "Model is {status.lower()} to simple evasion attempts."')


if __name__ == "__main__":
    main()
