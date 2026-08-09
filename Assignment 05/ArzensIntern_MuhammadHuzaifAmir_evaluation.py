#!/usr/bin/env python3
"""
evaluation.py
=============
Assignment 05 - Task 3: Model Evaluation & Robustness Check
Author: Muhammad Huzaif Amir | ArzensIntern - Advanced Track

Loads the Isolation Forest model + scaler produced by
anomaly_detector.py (--mode train) and runs a comprehensive evaluation:

  Part A - Standard evaluation: confusion matrix, accuracy, precision,
           recall, F1, false positive rate, per-attack-type breakdown.
  Part B - Robustness / evasion check: perturb known anomalies (noise,
           scaling, feature shuffling) and measure how many still get
           flagged.
  Part C - Operational analysis: alert-fatigue projection for a SOC and
           a simple concept-drift check (Week 1 vs. Week 4 anomaly rate).

Usage
-----
    python evaluation.py --data sample_data/network_traffic_dataset.csv \
                          --model outputs/isolation_forest_model.pkl \
                          --scaler outputs/standard_scaler.pkl \
                          --threshold 0.0 \
                          --outdir outputs/evaluation_output
"""

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from ArzensIntern_MuhammadHuzaifAmir_anomaly_detector import (
    CANONICAL_FEATURES, load_and_prepare_data, train_test_split_manual,
    labels_at_threshold, precision_recall_f1, RANDOM_STATE,
)


# ---------------------------------------------------------------------------
# Part A: Standard evaluation
# ---------------------------------------------------------------------------

def confusion_counts(y_true, y_pred):
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    return tp, fp, tn, fn


def standard_metrics(y_true, y_pred):
    tp, fp, tn, fn = confusion_counts(y_true, y_pred)
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": accuracy, "precision": precision, "recall": recall,
        "f1": f1, "fpr": fpr, "total": total,
    }


def plot_confusion_matrix(tp, fp, tn, fn, out_path):
    matrix = np.array([[tn, fp], [fn, tp]])
    fig, ax = plt.subplots(figsize=(5, 4.5))
    im = ax.imshow(matrix, cmap="Blues")
    labels = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{labels[i][j]}\n{matrix[i, j]:,}", ha="center", va="center",
                     fontsize=12, color="white" if matrix[i, j] > matrix.max() / 2 else "black")
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Predicted Normal", "Predicted Anomaly"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Actual Normal", "Actual Anomaly"])
    ax.set_title("Confusion Matrix - Isolation Forest Anomaly Detector")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def per_attack_type_breakdown(raw_df, test_index, y_pred):
    """Break down recall by attack type, using the 'label' column if present."""
    if "label" not in raw_df.columns:
        return None
    subset = raw_df.loc[test_index, "label"].reset_index(drop=True)
    df = pd.DataFrame({"label": subset, "predicted_anomaly": y_pred})
    rows = []
    for label, group in df.groupby("label"):
        n = len(group)
        if label.lower() == "benign":
            fp_rate = group["predicted_anomaly"].mean()
            rows.append({"attack_type": label, "count": n, "flagged_rate": round(fp_rate, 3),
                         "note": "false-positive rate (should be low)"})
        else:
            detect_rate = group["predicted_anomaly"].mean()
            rows.append({"attack_type": label, "count": n, "flagged_rate": round(detect_rate, 3),
                         "note": "detection rate / recall for this attack type"})
    return pd.DataFrame(rows).sort_values("flagged_rate")


# ---------------------------------------------------------------------------
# Part B: Robustness / evasion check
# ---------------------------------------------------------------------------

def evasion_test(model, scaler, X_test_raw, y_test, threshold, seed=RANDOM_STATE):
    """Perturb known anomalies with small, realistic modifications and check
    whether the (already-trained, frozen) model still flags them."""
    rng = np.random.RandomState(seed)

    anomaly_mask = (y_test.values == 1)
    X_anom = X_test_raw.loc[anomaly_mask].reset_index(drop=True)
    if len(X_anom) == 0:
        return None

    results = {}

    def detect_rate(X_variant):
        X_scaled = scaler.transform(X_variant)
        scores = model.decision_function(X_scaled)
        pred = labels_at_threshold(scores, threshold)
        return pred.mean(), pred

    baseline_rate, _ = detect_rate(X_anom)
    results["baseline_detected_rate"] = float(baseline_rate)

    feature_std = X_anom.std().values  # per-column std, shape (n_features,)

    def make_df(array):
        return pd.DataFrame(array, columns=X_anom.columns)

    # 1. Add 10% Gaussian noise proportional to each feature's std
    noise_matrix = X_anom.values + feature_std * 0.10 * rng.randn(*X_anom.shape)
    noise_rate, _ = detect_rate(make_df(noise_matrix).clip(lower=0))
    results["noise_10pct_detected_rate"] = float(noise_rate)

    # 2. Scale features down by 0.9
    scaled_down = X_anom * 0.9
    down_rate, _ = detect_rate(scaled_down)
    results["scale_0.9x_detected_rate"] = float(down_rate)

    # 3. Scale features up by 1.1
    scaled_up = X_anom * 1.1
    up_rate, _ = detect_rate(scaled_up)
    results["scale_1.1x_detected_rate"] = float(up_rate)

    # 4. Row-order shuffle sanity check: re-scores the same rows in a
    #    different order. IsolationForest scores each row independently, so
    #    the detected rate should be identical to baseline - this is a
    #    sanity check that the pipeline has no row-order leakage, not a
    #    genuine evasion vector.
    shuffle_rate, _ = detect_rate(X_anom.sample(frac=1.0, random_state=seed).reset_index(drop=True))
    results["row_shuffle_sanity_detected_rate"] = float(shuffle_rate)

    # Combined worst-case: noise + scale-down together (more aggressive evasion attempt)
    combined_matrix = (X_anom.values * 0.9) + feature_std * 0.10 * rng.randn(*X_anom.shape)
    combined_rate, _ = detect_rate(make_df(combined_matrix).clip(lower=0))
    results["combined_noise_and_scale_detected_rate"] = float(combined_rate)

    evasion_success_rates = {
        k: round(1 - v, 4) for k, v in results.items() if k != "baseline_detected_rate"
    }
    avg_still_detected = np.mean([v for k, v in results.items() if "shuffle" not in k])

    if avg_still_detected > 0.80:
        status = "ROBUST"
    elif avg_still_detected < 0.50:
        status = "FRAGILE"
    else:
        status = "MODERATE"

    return {
        "n_anomalies_tested": int(len(X_anom)),
        "detected_rates": results,
        "evasion_success_rates": evasion_success_rates,
        "average_still_detected_rate": float(avg_still_detected),
        "robustness_status": status,
    }


# ---------------------------------------------------------------------------
# Part C: Operational considerations
# ---------------------------------------------------------------------------

def alert_fatigue_analysis(anomaly_rate, events_per_day=10000, analyst_capacity=50):
    expected_alerts = anomaly_rate * events_per_day
    manageable = expected_alerts <= analyst_capacity
    return {
        "assumed_events_per_day": events_per_day,
        "anomaly_rate": round(float(anomaly_rate), 4),
        "expected_alerts_per_day": round(float(expected_alerts), 1),
        "analyst_capacity_per_day": analyst_capacity,
        "manageable": bool(manageable),
        "recommendation": (
            "Current threshold looks operationally manageable."
            if manageable else
            "Alert volume exceeds analyst capacity - raise the decision-function "
            "threshold (fewer, higher-confidence alerts) or add a triage/auto-close "
            "tier for low-severity anomalies."
        ),
    }


def concept_drift_check(model, scaler, week1_df, week4_df, threshold):
    def rate_for(df):
        X_scaled = scaler.transform(df[CANONICAL_FEATURES])
        scores = model.decision_function(X_scaled)
        pred = labels_at_threshold(scores, threshold)
        return pred.mean()

    r1 = rate_for(week1_df)
    r4 = rate_for(week4_df)
    pct_change = abs(r4 - r1) / r1 * 100 if r1 > 0 else float("inf")
    needs_retraining = pct_change > 20
    return {
        "week1_anomaly_rate": round(float(r1), 4),
        "week4_anomaly_rate": round(float(r4), 4),
        "pct_change": round(float(pct_change), 1),
        "needs_retraining": bool(needs_retraining),
        "note": (
            f"Anomaly rate changed by {pct_change:.1f}% between the two windows - "
            + ("this exceeds the 20% drift threshold; the model should be "
               "retrained/recalibrated on recent data." if needs_retraining else
               "this is within the acceptable 20% drift threshold; no immediate "
               "retraining is required.")
        ),
    }


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_html_report(context, out_path):
    m = context["metrics"]
    rob = context["robustness"]
    ops = context["alert_fatigue"]
    drift = context["concept_drift"]
    attack_table = context["attack_breakdown_html"]
    threshold_table = context["threshold_table_html"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Model Evaluation Report - Isolation Forest Anomaly Detector</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 40px auto;
         color: #1a1a2e; line-height: 1.55; padding: 0 20px; }}
  h1 {{ color: #16213e; border-bottom: 3px solid #0f3460; padding-bottom: 10px; }}
  h2 {{ color: #0f3460; margin-top: 36px; border-left: 5px solid #e94560; padding-left: 10px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
  th {{ background: #0f3460; color: white; }}
  tr:nth-child(even) {{ background: #f5f6fa; }}
  .metric-card {{ display: inline-block; background: #f5f6fa; border-radius: 8px; padding: 14px 22px;
                  margin: 6px; text-align: center; min-width: 140px; }}
  .metric-value {{ font-size: 1.6em; font-weight: bold; color: #0f3460; }}
  .metric-label {{ font-size: 0.85em; color: #555; }}
  .status-robust {{ color: #1a7f37; font-weight: bold; }}
  .status-fragile {{ color: #c0392b; font-weight: bold; }}
  .status-moderate {{ color: #b8860b; font-weight: bold; }}
  .banner {{ background: #16213e; color: white; padding: 20px; border-radius: 8px; text-align: center; }}
  img {{ max-width: 100%; border: 1px solid #ddd; border-radius: 6px; margin: 10px 0; }}
  code {{ background: #eee; padding: 2px 6px; border-radius: 4px; }}
</style>
</head>
<body>

<div class="banner">
  <h1 style="border:none; color:white; margin:0;">MODEL EVALUATION REPORT</h1>
  <p>Isolation Forest Anomaly Detector &mdash; Assignment 05, Task 3</p>
</div>

<p><strong>Dataset:</strong> {context['dataset_name']} test split ({m['total']:,} samples) &nbsp;|&nbsp;
<strong>Decision threshold:</strong> {context['threshold']} &nbsp;|&nbsp;
<strong>Author:</strong> Muhammad Huzaif Amir</p>

<h2>Part A &mdash; Standard Evaluation</h2>

<div>
  <div class="metric-card"><div class="metric-value">{m['accuracy']*100:.1f}%</div><div class="metric-label">Accuracy</div></div>
  <div class="metric-card"><div class="metric-value">{m['precision']*100:.1f}%</div><div class="metric-label">Precision</div></div>
  <div class="metric-card"><div class="metric-value">{m['recall']*100:.1f}%</div><div class="metric-label">Recall</div></div>
  <div class="metric-card"><div class="metric-value">{m['f1']*100:.1f}%</div><div class="metric-label">F1-Score</div></div>
  <div class="metric-card"><div class="metric-value">{m['fpr']*100:.1f}%</div><div class="metric-label">False Positive Rate</div></div>
</div>

<h3>Confusion Matrix</h3>
<table>
  <tr><th></th><th>Predicted Normal</th><th>Predicted Anomaly</th><th>Note</th></tr>
  <tr><td><strong>Actual Normal</strong></td><td>{m['tn']:,}</td><td>{m['fp']:,}</td><td>FPR: {m['fpr']*100:.1f}%</td></tr>
  <tr><td><strong>Actual Anomaly</strong></td><td>{m['fn']:,}</td><td>{m['tp']:,}</td><td>Recall: {m['recall']*100:.1f}%</td></tr>
</table>
<img src="confusion_matrix.png" alt="Confusion matrix heatmap">

<p><strong>Interpretation:</strong> the model catches {m['recall']*100:.1f}% of true attacks in the
test set while generating a false-positive rate of {m['fpr']*100:.1f}% on normal traffic
(roughly {m['fpr']*1000:.0f} false alarms per 1,000 normal events).</p>

<h3>Per-Attack-Type Breakdown</h3>
{attack_table}

<h2>Part B &mdash; Robustness / Evasion Check</h2>
<p>Known test-set anomalies were perturbed with small, realistic modifications
(10% Gaussian noise, &plusmn;10% feature scaling, and a combined attack) and re-scored
with the same frozen model and scaler to see whether they still get flagged.</p>
<table>
  <tr><th>Perturbation</th><th>Still Detected</th><th>Evasion Success Rate</th></tr>
  <tr><td>Baseline (no perturbation)</td><td>{rob['detected_rates']['baseline_detected_rate']*100:.1f}%</td><td>&mdash;</td></tr>
  <tr><td>+10% Gaussian noise</td><td>{rob['detected_rates']['noise_10pct_detected_rate']*100:.1f}%</td><td>{rob['evasion_success_rates']['noise_10pct_detected_rate']*100:.1f}%</td></tr>
  <tr><td>Scale &times;0.9</td><td>{rob['detected_rates']['scale_0.9x_detected_rate']*100:.1f}%</td><td>{rob['evasion_success_rates']['scale_0.9x_detected_rate']*100:.1f}%</td></tr>
  <tr><td>Scale &times;1.1</td><td>{rob['detected_rates']['scale_1.1x_detected_rate']*100:.1f}%</td><td>{rob['evasion_success_rates']['scale_1.1x_detected_rate']*100:.1f}%</td></tr>
  <tr><td>Combined noise + scale-down</td><td>{rob['detected_rates']['combined_noise_and_scale_detected_rate']*100:.1f}%</td><td>{rob['evasion_success_rates']['combined_noise_and_scale_detected_rate']*100:.1f}%</td></tr>
</table>
<p><strong>Robustness status: <span class="status-{rob['robustness_status'].lower()}">{rob['robustness_status']}</span></strong>
&mdash; averaged across perturbations, {rob['average_still_detected_rate']*100:.1f}% of previously-flagged
anomalies were still detected after modification
({rob['n_anomalies_tested']:,} anomalies tested).</p>

<h2>Part C &mdash; Operational Considerations</h2>

<h3>Alert Fatigue Analysis</h3>
<table>
  <tr><th>Assumption</th><th>Value</th></tr>
  <tr><td>Simulated daily events</td><td>{ops['assumed_events_per_day']:,}</td></tr>
  <tr><td>Observed anomaly rate</td><td>{ops['anomaly_rate']*100:.2f}%</td></tr>
  <tr><td>Expected alerts/day</td><td>{ops['expected_alerts_per_day']:.0f}</td></tr>
  <tr><td>Assumed analyst capacity</td><td>{ops['analyst_capacity_per_day']}/day</td></tr>
  <tr><td>Manageable?</td><td>{'Yes' if ops['manageable'] else 'No'}</td></tr>
</table>
<p><strong>Recommendation:</strong> {ops['recommendation']}</p>

<h3>Concept Drift Awareness</h3>
<table>
  <tr><th>Window</th><th>Anomaly Rate</th></tr>
  <tr><td>Week 1 (simulated, first half of test set)</td><td>{drift['week1_anomaly_rate']*100:.2f}%</td></tr>
  <tr><td>Week 4 (simulated, second half of test set)</td><td>{drift['week4_anomaly_rate']*100:.2f}%</td></tr>
</table>
<p>{drift['note']}</p>

<h2>Threshold Recommendation</h2>
{threshold_table}
<img src="threshold_tuning.png" alt="Precision/Recall/F1 vs threshold">

<hr>
<p style="color:#888; font-size:0.85em;">Generated automatically by evaluation.py &mdash; ArzensIntern Advanced Track, Assignment 05.</p>
</body>
</html>
"""
    Path(out_path).write_text(html)
    print(f"  HTML report saved: {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Evaluate the Isolation Forest anomaly detector")
    ap.add_argument("--data", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--scaler", required=True)
    ap.add_argument("--threshold", type=float, default=0.0)
    ap.add_argument("--outdir", default="evaluation_output")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("+" + "=" * 58 + "+")
    print("|         MODEL EVALUATION REPORT" + " " * 26 + "|")
    print("+" + "=" * 58 + "+")

    model = joblib.load(args.model)
    scaler = joblib.load(args.scaler)

    X, y, raw_df = load_and_prepare_data(args.data)
    if y is None:
        raise SystemExit("This dataset has no ground-truth label column ('label_binary') - "
                          "evaluation requires labeled data.")

    X_train, X_test, y_train, y_test = train_test_split_manual(X, y, test_ratio=0.2)
    X_test_scaled = scaler.transform(X_test)
    scores = model.decision_function(X_test_scaled)
    y_pred = labels_at_threshold(scores, args.threshold)

    print(f"Dataset: {Path(args.data).name} test set ({len(X_test):,} samples)\n")

    # ---- Part A ----
    m = standard_metrics(y_test.values, y_pred)
    print("Confusion Matrix")
    print(f"  TN={m['tn']:,}  FP={m['fp']:,}  FN={m['fn']:,}  TP={m['tp']:,}")
    print(f"Metrics:")
    print(f"  Accuracy:  {m['accuracy']*100:.1f}%")
    print(f"  Precision: {m['precision']*100:.1f}%")
    print(f"  Recall:    {m['recall']*100:.1f}%")
    print(f"  F1-Score:  {m['f1']*100:.1f}%")
    print(f"  FPR:       {m['fpr']*100:.1f}%")

    plot_confusion_matrix(m['tp'], m['fp'], m['tn'], m['fn'], outdir / "confusion_matrix.png")

    attack_df = per_attack_type_breakdown(raw_df, X_test.index, y_pred)
    if attack_df is not None:
        attack_df.to_csv(outdir / "per_attack_type_breakdown.csv", index=False)
        print("\nPer-attack-type breakdown saved.")
        attack_table_html = attack_df.to_html(index=False)
    else:
        attack_table_html = "<p><em>No per-attack-type labels available in this dataset.</em></p>"

    # ---- Part B ----
    print("\nRobustness Test:")
    rob = evasion_test(model, scaler, X_test, y_test, args.threshold)
    if rob:
        print(f"  Evasion success rate (avg): {(1-rob['average_still_detected_rate'])*100:.1f}% "
              f"({rob['average_still_detected_rate']*100:.1f}% still detected)")
        print(f"  Status: {rob['robustness_status']}")
    with open(outdir / "robustness_results.json", "w") as f:
        json.dump(rob, f, indent=2)

    # ---- Part C ----
    overall_anomaly_rate = y_pred.mean()
    ops = alert_fatigue_analysis(overall_anomaly_rate)
    print("\nOperational Impact:")
    print(f"  Expected alerts/day: {ops['expected_alerts_per_day']:.0f} (on {ops['assumed_events_per_day']:,} events)")
    print(f"  Analyst capacity: {ops['analyst_capacity_per_day']}/day")
    print(f"  RECOMMENDATION: {ops['recommendation']}")

    half = len(X_test) // 2
    week1_df = X_test.iloc[:half]
    week4_df = X_test.iloc[half:]
    drift = concept_drift_check(model, scaler, week1_df, week4_df, args.threshold)
    print("\nConcept Drift Check:")
    print(f"  {drift['note']}")

    # ---- Threshold recap (reuse tune_thresholds from anomaly_detector) ----
    from ArzensIntern_MuhammadHuzaifAmir_anomaly_detector import tune_thresholds, DEFAULT_THRESHOLDS
    tune_result = tune_thresholds(scores, y_test, thresholds=DEFAULT_THRESHOLDS,
                                   plot_path=outdir / "threshold_tuning.png")
    if tune_result:
        results_df, best_threshold = tune_result
        results_df.to_csv(outdir / "threshold_tuning_summary.csv", index=False)
        threshold_table_html = results_df.to_html(index=False, float_format=lambda x: f"{x:.3f}")
        print(f"\nThreshold Recommendation:")
        print(f"  Current: {args.threshold} -> F1={m['f1']*100:.1f}%, Alerts={ops['expected_alerts_per_day']:.0f}/day")
        best_row = results_df.loc[results_df['threshold'] == best_threshold].iloc[0]
        best_alerts = alert_fatigue_analysis((best_row['tp'] + best_row['fp']) / m['total'])
        print(f"  Optimal:  {best_threshold} -> F1={best_row['f1']*100:.1f}%, Alerts={best_alerts['expected_alerts_per_day']:.0f}/day")
    else:
        threshold_table_html = "<p><em>Threshold sweep unavailable.</em></p>"

    # ---- Save full metrics + generate report ----
    with open(outdir / "metrics_summary.json", "w") as f:
        json.dump({"standard_metrics": m, "robustness": rob, "alert_fatigue": ops,
                    "concept_drift": drift, "threshold_used": args.threshold}, f, indent=2)

    context = {
        "dataset_name": Path(args.data).name,
        "threshold": args.threshold,
        "metrics": m,
        "robustness": rob,
        "alert_fatigue": ops,
        "concept_drift": drift,
        "attack_breakdown_html": attack_table_html,
        "threshold_table_html": threshold_table_html,
    }
    generate_html_report(context, outdir / "evaluation_report.html")
    print(f"\nAll evaluation artifacts saved to: {outdir}/")


if __name__ == "__main__":
    main()
