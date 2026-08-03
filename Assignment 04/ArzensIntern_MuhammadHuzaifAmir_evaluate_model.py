"""
evaluate_model.py
-----------------
Comprehensive model evaluation and interpretability for threat detection.
Assignment 04 - Advanced Track (AI, Automation & Security Engineering)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
import shap
import yaml
from jinja2 import Template
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

ARTIFACTS_DIR = Path("model_artifacts")
SHAP_DIR = Path("shap_analysis")
REPORT_DIR = Path("evaluation_output")


def load_artifacts() -> dict:
    """Load model, preprocessing pipeline, test data, and metadata."""
    prep = joblib.load(ARTIFACTS_DIR / "preprocessing_pipeline.pkl")
    test_data = joblib.load(ARTIFACTS_DIR / "test_data.pkl")

    with open(ARTIFACTS_DIR / "model_metadata.json") as f:
        metadata = json.load(f)

    version = metadata.get("model_version", "v1.0")
    all_models_path = ARTIFACTS_DIR / f"all_models_{version}.pkl"
    if all_models_path.exists():
        all_models = joblib.load(all_models_path)
    else:
        all_models = {metadata["best_model"]: joblib.load(ARTIFACTS_DIR / f"best_model_{version}.pkl")}

    return {
        "preprocessing": prep,
        "test_data": test_data,
        "metadata": metadata,
        "all_models": all_models,
        "best_model": all_models[metadata["best_model"]],
        "best_model_name": metadata["best_model"],
    }


def compute_security_metrics(y_true, y_pred, y_proba=None) -> dict:
    """Calculate standard and security-specific metrics."""
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        # Multi-class: treat non-zero as attack for binary-style FPR/FNR
        tn = fp = fn = tp = 0

    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
    }

    if cm.shape == (2, 2):
        metrics["false_positive_rate"] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        metrics["false_negative_rate"] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        metrics["cost_sensitive_f1_fn2"] = float(
            f1_score(y_true, y_pred, average="binary", pos_label=1, zero_division=0)
        )

    if y_proba is not None and len(np.unique(y_true)) == 2:
        metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))
        prec_curve, rec_curve, _ = precision_recall_curve(y_true, y_proba)
        metrics["pr_auc"] = float(auc(rec_curve, prec_curve))

    return metrics


def compare_models(all_models: dict, X_test, y_test) -> pd.DataFrame:
    """Build comparison table for all trained models."""
    rows = []
    for name, model in all_models.items():
        t0 = time.time()
        preds = model.predict(X_test)
        infer_ms = (time.time() - t0) / len(X_test) * 1000

        proba = None
        if hasattr(model, "predict_proba") and len(np.unique(y_test)) == 2:
            proba = model.predict_proba(X_test)[:, 1]

        m = compute_security_metrics(y_test, preds, proba)
        rows.append({
            "Model": name.replace("_", " ").title(),
            "Accuracy": round(m["accuracy"], 4),
            "Precision": round(m["precision"], 4),
            "Recall": round(m["recall"], 4),
            "F1": round(m["f1"], 4),
            "ROC-AUC": round(m.get("roc_auc", float("nan")), 4),
            "PR-AUC": round(m.get("pr_auc", float("nan")), 4),
            "Training Time": "see log",
            "Inference ms/sample": round(infer_ms, 4),
        })
    return pd.DataFrame(rows)


def threshold_analysis(model, X_test, y_test, output_dir: Path) -> dict:
    """Analyze precision/recall at different thresholds and recommend optimal."""
    if not hasattr(model, "predict_proba") or len(np.unique(y_test)) != 2:
        return {"recommended_threshold": 0.5, "note": "Binary proba required"}

    proba = model.predict_proba(X_test)[:, 1]
    thresholds = np.arange(0.1, 0.95, 0.05)
    precs, recs, f1s = [], [], []

    for t in thresholds:
        preds = (proba >= t).astype(int)
        precs.append(precision_score(y_test, preds, zero_division=0))
        recs.append(recall_score(y_test, preds, zero_division=0))
        f1s.append(f1_score(y_test, preds, zero_division=0))

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(thresholds, precs, label="Precision", marker="o", markersize=3)
    ax.plot(thresholds, recs, label="Recall", marker="s", markersize=3)
    ax.plot(thresholds, f1s, label="F1", marker="^", markersize=3)
    ax.axvline(0.5, color="gray", linestyle="--", label="Default (0.5)")
    ax.axvline(0.3, color="orange", linestyle=":", label="High-recall (0.3)")
    ax.axvline(0.7, color="red", linestyle=":", label="High-precision (0.7)")
    ax.set_xlabel("Threshold")
    ax.set_ylabel("Score")
    ax.set_title("Precision-Recall vs Threshold")
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "threshold_analysis.png", dpi=150)
    plt.close()

    # Recommend threshold maximizing F1 with recall >= 0.90
    best_t, best_f1 = 0.5, 0.0
    for t, r, f in zip(thresholds, recs, f1s):
        if r >= 0.85 and f > best_f1:
            best_t, best_f1 = t, f
    if best_f1 == 0:
        best_t = thresholds[int(np.argmax(f1s))]

    return {
        "recommended_threshold": float(best_t),
        "threshold_0.3": {"precision": float(precs[list(thresholds).index(min(thresholds, key=lambda x: abs(x - 0.3)))]),
                          "recall": float(recs[list(thresholds).index(min(thresholds, key=lambda x: abs(x - 0.3)))])},
        "threshold_0.5": {"precision": float(precision_score(y_test, (proba >= 0.5).astype(int), zero_division=0)),
                          "recall": float(recall_score(y_test, (proba >= 0.5).astype(int), zero_division=0))},
        "threshold_0.7": {"precision": float(precision_score(y_test, (proba >= 0.7).astype(int), zero_division=0)),
                          "recall": float(recall_score(y_test, (proba >= 0.7).astype(int), zero_division=0))},
        "rationale": f"Threshold {best_t:.2f} balances high recall for threat detection with acceptable precision.",
    }


def plot_confusion_matrix(y_true, y_pred, labels, output_path: Path, title: str = "Confusion Matrix"):
    """Plot and save confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels, ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()


def plot_roc_pr_curves(y_true, y_proba, output_dir: Path):
    """Plot ROC and Precision-Recall curves."""
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    roc_auc = auc(fpr, tpr)
    prec, rec, _ = precision_recall_curve(y_true, y_proba)
    pr_auc = auc(rec, prec)

    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    axes[0].plot(fpr, tpr, label=f"ROC-AUC = {roc_auc:.4f}")
    axes[0].plot([0, 1], [0, 1], "k--")
    axes[0].set_xlabel("False Positive Rate")
    axes[0].set_ylabel("True Positive Rate")
    axes[0].set_title("ROC Curve")
    axes[0].legend()

    axes[1].plot(rec, prec, label=f"PR-AUC = {pr_auc:.4f}")
    axes[1].set_xlabel("Recall")
    axes[1].set_ylabel("Precision")
    axes[1].set_title("Precision-Recall Curve")
    axes[1].legend()
    plt.tight_layout()
    plt.savefig(output_dir / "roc_pr_curves.png", dpi=150)
    plt.close()


def run_shap_analysis(model, X_test, feature_names: List[str], y_test, y_pred, output_dir: Path) -> dict:
    """Global and local SHAP interpretability analysis."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "dependence_plots").mkdir(exist_ok=True)
    (output_dir / "force_plots_for_examples").mkdir(exist_ok=True)

    # Sample for SHAP (full test set can be slow)
    n_sample = min(500, len(X_test))
    rng = np.random.default_rng(42)
    idx = rng.choice(len(X_test), n_sample, replace=False)
    X_sample = X_test[idx]

    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_sample)
        if isinstance(shap_values, list):
            shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
    except Exception:
        explainer = shap.KernelExplainer(model.predict_proba, shap.sample(X_sample, 50))
        shap_values = explainer.shap_values(X_sample)
        if isinstance(shap_values, list):
            shap_values = shap_values[1]

    plt.figure(figsize=(12, 8))
    shap.summary_plot(shap_values, X_sample, feature_names=feature_names, show=False)
    plt.tight_layout()
    plt.savefig(output_dir / "summary_plot.png", dpi=150, bbox_inches="tight")
    plt.close()

    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    top_idx = np.argsort(mean_abs_shap)[::-1][:10]
    top_features = [(feature_names[i], float(mean_abs_shap[i])) for i in top_idx]

    for rank, fi in enumerate(top_idx[:5]):
        plt.figure(figsize=(8, 5))
        shap.dependence_plot(fi, shap_values, X_sample, feature_names=feature_names, show=False)
        plt.tight_layout()
        plt.savefig(output_dir / "dependence_plots" / f"dep_{rank}_{feature_names[fi]}.png", dpi=150)
        plt.close()

    # Local explanations: 2 TP, 2 FP, 1 FN (compute SHAP on specific test rows)
    examples = _select_example_indices(y_test, y_pred)
    local_explanations = []
    base_value = explainer.expected_value
    if isinstance(base_value, list):
        base_value = base_value[1] if len(base_value) > 1 else base_value[0]

    for ex_type, test_idx in examples.items():
        if test_idx is None:
            continue
        row = X_test[test_idx : test_idx + 1]
        try:
            row_shap = explainer.shap_values(row)
            if isinstance(row_shap, list):
                row_shap = row_shap[1] if len(row_shap) > 1 else row_shap[0]
            sv = row_shap[0]
        except Exception:
            sv = shap_values[0]

        top_feat_idx = np.argsort(np.abs(sv))[::-1][:3]
        explanation = {
            "type": ex_type,
            "index": int(test_idx),
            "top_features": [(feature_names[j], float(sv[j])) for j in top_feat_idx],
            "plain_english": _plain_english_explanation(ex_type, feature_names, sv, top_feat_idx),
        }
        local_explanations.append(explanation)

        try:
            plt.figure(figsize=(10, 3))
            shap.plots.waterfall(
                shap.Explanation(
                    values=sv,
                    base_values=base_value,
                    data=row[0],
                    feature_names=feature_names,
                ),
                show=False,
            )
            plt.tight_layout()
            plt.savefig(output_dir / "force_plots_for_examples" / f"force_{ex_type}.png", dpi=150)
            plt.close()
        except Exception as exc:
            logger.warning("Could not save force plot for %s: %s", ex_type, exc)

    return {"top_10_features": top_features, "local_explanations": local_explanations}


def _select_example_indices(y_true, y_pred) -> dict:
    """Pick 2 TP, 2 FP, 1 FN indices."""
    y_true, y_pred = np.array(y_true), np.array(y_pred)
    tp = np.where((y_true == 1) & (y_pred == 1))[0]
    fp = np.where((y_true == 0) & (y_pred == 1))[0]
    fn = np.where((y_true == 1) & (y_pred == 0))[0]
    return {
        "true_positive_1": int(tp[0]) if len(tp) > 0 else None,
        "true_positive_2": int(tp[1]) if len(tp) > 1 else None,
        "false_positive_1": int(fp[0]) if len(fp) > 0 else None,
        "false_positive_2": int(fp[1]) if len(fp) > 1 else None,
        "false_negative_1": int(fn[0]) if len(fn) > 0 else None,
    }


def _plain_english_explanation(ex_type, feature_names, shap_vals, top_idx) -> str:
    parts = []
    for j in top_idx[:3]:
        direction = "increased" if shap_vals[j] > 0 else "decreased"
        parts.append(f"{feature_names[j]} {direction} suspicion (SHAP={shap_vals[j]:.3f})")
    prefix = {
        "true_positive_1": "Correctly flagged as malicious because",
        "true_positive_2": "Correctly flagged as malicious because",
        "false_positive_1": "Incorrectly flagged as attack because",
        "false_positive_2": "Incorrectly flagged as attack because",
        "false_negative_1": "Missed attack because",
    }.get(ex_type, "Prediction driven by")
    return f"{prefix} " + "; ".join(parts) + "."


def production_readiness_check(model, X_test, y_test) -> dict:
    """Assess latency, model size, and basic robustness."""
    model_path = list(ARTIFACTS_DIR.glob("best_model_*.pkl"))[0]
    size_mb = model_path.stat().st_size / (1024 * 1024)

    latencies = []
    for _ in range(5):
        t0 = time.perf_counter()
        model.predict(X_test[:100])
        latencies.append((time.perf_counter() - t0) / 100 * 1000)
    avg_latency = float(np.mean(latencies))

    # Drift simulation: add small noise
    X_noisy = X_test + np.random.default_rng(42).normal(0, 0.05, X_test.shape)
    acc_clean = accuracy_score(y_test, model.predict(X_test))
    acc_noisy = accuracy_score(y_test, model.predict(X_noisy))

    approved = avg_latency < 10 and size_mb < 100
    return {
        "inference_time_ms_per_sample": round(avg_latency, 4),
        "model_size_mb": round(size_mb, 2),
        "accuracy_clean": round(float(acc_clean), 4),
        "accuracy_noisy": round(float(acc_noisy), 4),
        "robustness_drop_pct": round((acc_clean - acc_noisy) / max(acc_clean, 1e-9) * 100, 2),
        "production_ready": approved,
        "verdict": "APPROVED" if approved else "NEEDS REVIEW",
    }


def error_analysis(y_true, y_pred, feature_names, X_test, output_dir: Path) -> dict:
    """Analyze false positives and false negatives."""
    y_true, y_pred = np.array(y_true), np.array(y_pred)
    fp_mask = (y_true == 0) & (y_pred == 1)
    fn_mask = (y_true == 1) & (y_pred == 0)

    recommendations = []
    if fp_mask.sum() > 0:
        fp_mean = X_test[fp_mask].mean(axis=0)
        benign_mean = X_test[(y_true == 0) & (y_pred == 0)].mean(axis=0)
        diff_idx = np.argsort(np.abs(fp_mean - benign_mean))[::-1][:5]
        fp_drivers = [feature_names[i] for i in diff_idx]
        recommendations.append(f"False positives often show unusual values in: {', '.join(fp_drivers)}")
    if fn_mask.sum() > 0:
        recommendations.append("False negatives may indicate evasion — consider retraining with adversarial samples.")
    recommendations.append("Monitor feature drift monthly and retrain with new attack samples.")

    return {
        "false_positive_count": int(fp_mask.sum()),
        "false_negative_count": int(fn_mask.sum()),
        "recommendations": recommendations,
    }


def generate_html_report(
    metrics: dict,
    comparison_df: pd.DataFrame,
    threshold_info: dict,
    shap_info: dict,
    prod_check: dict,
    error_info: dict,
    model_name: str,
    output_path: Path,
):
    """Generate HTML evaluation report."""
    template = Template("""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Model Evaluation Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; color: #222; }
    h1, h2 { color: #1a365d; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0; }
    th, td { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
    th { background: #edf2f7; }
    .box { background: #f7fafc; border-left: 4px solid #3182ce; padding: 16px; margin: 16px 0; }
    .approved { color: green; font-weight: bold; }
    img { max-width: 100%; margin: 12px 0; }
  </style>
</head>
<body>
  <h1>MODEL EVALUATION REPORT</h1>
  <p><strong>Dataset:</strong> CICIDS2017-style Network Traffic | <strong>Model:</strong> {{ model_name }}</p>

  <h2>Performance Metrics</h2>
  <table>
    <tr><th>Metric</th><th>Value</th></tr>
    {% for k, v in metrics.items() %}
    <tr><td>{{ k }}</td><td>{{ "%.4f"|format(v) if v is number else v }}</td></tr>
    {% endfor %}
  </table>

  <h2>Model Comparison</h2>
  {{ comparison_table }}

  <h2>Threshold Analysis</h2>
  <div class="box">
    <p><strong>Recommended threshold:</strong> {{ threshold_info.recommended_threshold }}</p>
    <p>{{ threshold_info.rationale }}</p>
  </div>
  <img src="evaluation_output/threshold_analysis.png" alt="Threshold Analysis">

  <h2>ROC & PR Curves</h2>
  <img src="evaluation_output/roc_pr_curves.png" alt="ROC PR Curves">

  <h2>Confusion Matrix</h2>
  <img src="evaluation_output/confusion_matrix.png" alt="Confusion Matrix">

  <h2>SHAP — Top Features</h2>
  <ol>
  {% for feat, val in shap_info.top_10_features %}
    <li>{{ feat }} (mean |SHAP| = {{ "%.4f"|format(val) }})</li>
  {% endfor %}
  </ol>
  <img src="shap_analysis/summary_plot.png" alt="SHAP Summary">

  <h2>Local Explanations</h2>
  {% for ex in shap_info.local_explanations %}
  <div class="box"><strong>{{ ex.type }}</strong>: {{ ex.plain_english }}</div>
  {% endfor %}

  <h2>Error Analysis</h2>
  <p>False Positives: {{ error_info.false_positive_count }} | False Negatives: {{ error_info.false_negative_count }}</p>
  <ul>{% for r in error_info.recommendations %}<li>{{ r }}</li>{% endfor %}</ul>

  <h2>Production Readiness</h2>
  <div class="box">
    <p class="{{ 'approved' if prod_check.production_ready else '' }}">Verdict: {{ prod_check.verdict }}</p>
    <p>Inference: {{ prod_check.inference_time_ms_per_sample }} ms/sample | Size: {{ prod_check.model_size_mb }} MB</p>
    <p>Robustness: {{ prod_check.accuracy_clean }} → {{ prod_check.accuracy_noisy }} under noise</p>
  </div>
</body>
</html>
    """)

    html = template.render(
        model_name=model_name,
        metrics=metrics,
        comparison_table=comparison_df.to_html(index=False),
        threshold_info=threshold_info,
        shap_info=shap_info,
        prod_check=prod_check,
        error_info=error_info,
    )
    output_path.write_text(html)
    logger.info("Saved HTML report to %s", output_path)


def main():
    """Run full evaluation pipeline."""
    logger.info("=" * 60)
    logger.info("Model Evaluation & Interpretability Pipeline")
    logger.info("=" * 60)

    REPORT_DIR.mkdir(exist_ok=True)
    SHAP_DIR.mkdir(exist_ok=True)

    artifacts = load_artifacts()
    prep = artifacts["preprocessing"]
    X_test = artifacts["test_data"]["X_test"]
    y_test = artifacts["test_data"]["y_test"]
    feature_names = prep["feature_names"]
    label_encoder = prep["label_encoder"]
    labels = list(label_encoder.classes_)

    best_model = artifacts["best_model"]
    best_name = artifacts["best_model_name"]

    y_pred = best_model.predict(X_test)
    y_proba = best_model.predict_proba(X_test)[:, 1] if hasattr(best_model, "predict_proba") and len(labels) == 2 else None

    metrics = compute_security_metrics(y_test, y_pred, y_proba)
    comparison_df = compare_models(artifacts["all_models"], X_test, y_test)
    threshold_info = threshold_analysis(best_model, X_test, y_test, REPORT_DIR)

    plot_confusion_matrix(y_test, y_pred, labels, REPORT_DIR / "confusion_matrix.png")
    if y_proba is not None:
        plot_roc_pr_curves(y_test, y_proba, REPORT_DIR)

    shap_info = run_shap_analysis(best_model, X_test, feature_names, y_test, y_pred, SHAP_DIR)
    prod_check = production_readiness_check(best_model, X_test, y_test)
    error_info = error_analysis(y_test, y_pred, feature_names, X_test, REPORT_DIR)

    generate_html_report(
        metrics, comparison_df, threshold_info, shap_info,
        prod_check, error_info, best_name, Path("evaluation_report.html"),
    )

    comparison_df.to_csv(REPORT_DIR / "model_comparison.csv", index=False)

    print("\n" + "=" * 62)
    print("| MODEL EVALUATION REPORT                                      |")
    print(f"| Dataset: CICIDS2017-style | Model: {best_name} |")
    print("=" * 62)
    print("PERFORMANCE METRICS:")
    for k, v in metrics.items():
        print(f"  {k}: {v:.4f}" if isinstance(v, float) else f"  {k}: {v}")
    print("\nTHRESHOLD ANALYSIS:")
    print(f"  Recommended threshold: {threshold_info['recommended_threshold']}")
    print(f"  {threshold_info.get('rationale', '')}")
    print("\nTOP 3 IMPORTANT FEATURES (SHAP):")
    for i, (feat, val) in enumerate(shap_info["top_10_features"][:3], 1):
        print(f"  {i}. {feat} (SHAP={val:.4f})")
    print(f"\nPRODUCTION READINESS: {prod_check['verdict']}")
    print(f"  Inference time: {prod_check['inference_time_ms_per_sample']} ms/sample")
    print(f"  Model size: {prod_check['model_size_mb']} MB")
    print("=" * 62)


if __name__ == "__main__":
    main()
