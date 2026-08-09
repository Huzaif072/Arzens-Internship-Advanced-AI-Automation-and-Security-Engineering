"""
compare_datasets.py
--------------------
Practical Task 1 — Real Data Exploration (adapted).

Kaggle is unreachable from this environment, so real CICIDS2017/UNSW-NB15
CSVs could not be downloaded (see README_bonus.md). Instead, this script
trains and evaluates the SAME Isolation Forest pipeline from
anomaly_detector.py on two locally-generated, differently-shaped synthetic
datasets:

  1. network_traffic_dataset.csv   - CICIDS2017-style (Assignment 04 generator)
  2. unsw_nb15_style_dataset.csv   - UNSW-NB15-style (bonus/generate_unsw_style_dataset.py)

and reports which one is harder for the model, and why.

Usage:
    python bonus/compare_datasets.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from ArzensIntern_MuhammadHuzaifAmir_anomaly_detector import (
    load_and_prepare_data, train_test_split_manual, train_model,
    score_samples, labels_at_threshold, precision_recall_f1,
)

DATASETS = {
    "CICIDS2017-style": "sample_data/network_traffic_dataset.csv",
    "UNSW-NB15-style": "sample_data/unsw_nb15_style_dataset.csv",
}


def evaluate_dataset(name, path, threshold=0.0):
    print(f"\n{'='*60}\n{name}  ({path})\n{'='*60}")
    X, y, raw_df = load_and_prepare_data(path)
    X_train, X_test, y_train, y_test = train_test_split_manual(X, y, test_ratio=0.2)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    model = train_model(X_train_scaled, n_estimators=100, contamination=0.1)
    scores, is_anomaly_default = score_samples(model, X_test_scaled)

    m = precision_recall_f1(y_test.values, labels_at_threshold(scores, threshold))
    tn = int(np.sum((labels_at_threshold(scores, threshold) == 0) & (y_test.values == 0)))
    accuracy = (m["tp"] + tn) / len(y_test)

    # Feature-space overlap heuristic: mean absolute standardized distance
    # between the Normal and Attack class centroids across the 6 scaled
    # features. Smaller distance = more overlap = harder separation problem.
    y_arr = y_test.values
    centroid_normal = X_test_scaled[y_arr == 0].mean(axis=0)
    centroid_attack = X_test_scaled[y_arr == 1].mean(axis=0)
    centroid_distance = float(np.linalg.norm(centroid_normal - centroid_attack))

    return {
        "dataset": name,
        "n_samples": len(X),
        "attack_rate": float(y.mean()),
        "accuracy": accuracy,
        "precision": m["precision"],
        "recall": m["recall"],
        "f1": m["f1"],
        "centroid_distance": centroid_distance,
    }


def main():
    results = [evaluate_dataset(name, path) for name, path in DATASETS.items()]
    df = pd.DataFrame(results)

    print("\n\n" + "=" * 70)
    print("COMPARISON SUMMARY")
    print("=" * 70)
    print(df.to_string(index=False, float_format=lambda x: f"{x:.3f}"))

    harder = df.loc[df["f1"].idxmin(), "dataset"]
    print(f"\nHarder dataset for this Isolation Forest pipeline: {harder}")
    print("(lower F1 and/or smaller Normal-vs-Attack centroid distance in "
          "scaled feature space indicate more overlapping, harder-to-separate classes)")

    out_path = "outputs/dataset_comparison.csv"
    Path("outputs").mkdir(exist_ok=True)
    df.to_csv(out_path, index=False)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    main()
