"""
dashboard.py
============
Assignment 05 — Bonus Practical Task 2: Dashboard Creation.

A simple Streamlit dashboard for the Isolation Forest anomaly detector:
upload a CSV -> see anomaly scores -> visualize results.

Run:
    pip install streamlit
    streamlit run bonus/dashboard.py

Behavior:
- If outputs/isolation_forest_model.pkl + outputs/standard_scaler.pkl exist
  (produced by `anomaly_detector.py --mode train`), the dashboard scores
  uploaded data with that pretrained pipeline.
- Otherwise, it trains a fresh Isolation Forest on the uploaded file itself
  (unsupervised - no labels required), so the dashboard also works as a
  standalone demo with no prior training step.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import joblib
import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

from ArzensIntern_MuhammadHuzaifAmir_anomaly_detector import (
    resolve_feature_columns, CANONICAL_FEATURES, labels_at_threshold, precision_recall_f1,
)

st.set_page_config(page_title="Anomaly Detection Dashboard", layout="wide")

MODEL_PATH = Path(__file__).resolve().parent.parent / "outputs" / "isolation_forest_model.pkl"
SCALER_PATH = Path(__file__).resolve().parent.parent / "outputs" / "standard_scaler.pkl"


@st.cache_resource
def load_pretrained():
    if MODEL_PATH.exists() and SCALER_PATH.exists():
        return joblib.load(MODEL_PATH), joblib.load(SCALER_PATH)
    return None, None


def prepare_features(df):
    col_map = resolve_feature_columns(df)
    X = df[[col_map[c] for c in CANONICAL_FEATURES]].copy()
    X.columns = CANONICAL_FEATURES
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median(numeric_only=True))
    return X


def main():
    st.title("🔍 Network Anomaly Detection Dashboard")
    st.caption("Assignment 05 — Isolation Forest anomaly detector · Muhammad Huzaif Amir")

    with st.sidebar:
        st.header("Settings")
        threshold = st.slider(
            "Decision threshold (score < threshold ⇒ anomaly)",
            min_value=-0.5, max_value=0.3, value=0.0, step=0.05,
        )
        st.markdown("---")
        st.markdown(
            "**Expected columns** (or UNSW-NB15/CICIDS2017-style aliases — "
            "see `anomaly_detector.py`):\n\n"
            f"`{', '.join(CANONICAL_FEATURES)}`"
        )

    uploaded = st.file_uploader("Upload a network-flow CSV", type=["csv"])
    if uploaded is None:
        st.info("Upload a CSV to see anomaly scores. "
                 "You can use `sample_data/network_traffic_dataset.csv` to try it out.")
        return

    df = pd.read_csv(uploaded)
    st.write(f"Loaded **{len(df):,} rows × {df.shape[1]} columns**")

    try:
        X = prepare_features(df)
    except ValueError as e:
        st.error(str(e))
        return

    model, scaler = load_pretrained()
    if model is not None:
        st.success("Using the pretrained Isolation Forest model from `outputs/`.")
        X_scaled = scaler.transform(X)
    else:
        st.warning("No pretrained model found in `outputs/` — training a fresh "
                    "Isolation Forest on the uploaded data instead.")
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
        model.fit(X_scaled)

    scores = model.decision_function(X_scaled)
    is_anomaly = labels_at_threshold(scores, threshold)

    results = df.copy()
    results["anomaly_score"] = scores
    results["is_anomaly"] = is_anomaly

    n_anom = int(is_anomaly.sum())
    n_total = len(df)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total rows", f"{n_total:,}")
    col2.metric("Flagged anomalies", f"{n_anom:,}", f"{n_anom/n_total*100:.1f}% of traffic")
    col3.metric("Threshold", f"{threshold:.2f}")

    # If a ground-truth label column is present, show live metrics
    label_col = None
    for candidate in ("label_binary", "label"):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col:
        y_true = (df[label_col].astype(str).str.lower() != "benign").astype(int) \
            if label_col == "label_binary" else (df[label_col].astype(str).str.lower() != "normal").astype(int)
        m = precision_recall_f1(y_true.values, is_anomaly)
        st.subheader("Live metrics (ground-truth label detected)")
        c1, c2, c3 = st.columns(3)
        c1.metric("Precision", f"{m['precision']*100:.1f}%")
        c2.metric("Recall", f"{m['recall']*100:.1f}%")
        c3.metric("F1-Score", f"{m['f1']*100:.1f}%")

    st.subheader("Anomaly score distribution")
    fig, ax = plt.subplots(figsize=(9, 3.5))
    ax.hist(scores, bins=60, color="#0f3460")
    ax.axvline(threshold, color="#e94560", linestyle="--", label=f"threshold = {threshold:.2f}")
    ax.set_xlabel("Anomaly score (lower = more anomalous)")
    ax.set_ylabel("Count")
    ax.legend()
    st.pyplot(fig)

    left, right = st.columns(2)
    with left:
        st.subheader("Normal vs. anomaly split")
        fig2, ax2 = plt.subplots(figsize=(4, 4))
        ax2.pie([n_total - n_anom, n_anom], labels=["Normal", "Anomaly"],
                colors=["#0f3460", "#e94560"], autopct="%1.1f%%")
        st.pyplot(fig2)
    with right:
        st.subheader("Top 10 most anomalous rows")
        top10 = results.sort_values("anomaly_score").head(10)
        st.dataframe(top10[CANONICAL_FEATURES + ["anomaly_score", "is_anomaly"]])

    st.subheader("Full results")
    st.dataframe(results.head(500))
    st.download_button(
        "Download full results as CSV",
        data=results.to_csv(index=False).encode("utf-8"),
        file_name="anomaly_dashboard_results.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
