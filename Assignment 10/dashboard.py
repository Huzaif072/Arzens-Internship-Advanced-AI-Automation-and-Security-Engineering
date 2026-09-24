#!/usr/bin/env python3
"""
dashboard.py — Module 5: Real-Time Security Dashboard
======================================================
AI Security Automation Platform
Author: Muhammad Huzaif Amir

A Streamlit-based security operations dashboard with:
  • Live alert feed with severity badges
  • Threat intelligence summary and world-threat map simulation
  • ML anomaly score histogram and scatter plots
  • SOAR playbook status and KPIs
  • Interactive drill-down on individual alerts

Run
---
    streamlit run dashboard.py
    streamlit run dashboard.py -- --config /path/to/config.yaml
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import yaml

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"

# ─────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────

@st.cache_resource(ttl=60)
def load_config() -> dict:
    try:
        return yaml.safe_load(CONFIG_PATH.read_text())
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────
# Data loaders
# ─────────────────────────────────────────────────────────────

def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    except Exception:
        return []


def _read_json(path: Path) -> list | dict:
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


@st.cache_data(ttl=10)
def load_scored_events() -> pd.DataFrame:
    path = BASE_DIR / "data" / "scored_events.jsonl"
    records = _read_jsonl(path)
    if not records:
        return pd.DataFrame()
    df = pd.json_normalize(records)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


@st.cache_data(ttl=10)
def load_cases() -> pd.DataFrame:
    path = BASE_DIR / "alerts" / "cases.json"
    records = _read_json(path)
    if not records:
        return pd.DataFrame()
    df = pd.DataFrame(records)
    if "created_at" in df.columns:
        df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce", utc=True)
    return df


@st.cache_data(ttl=10)
def load_analyst_queue() -> pd.DataFrame:
    path = BASE_DIR / "alerts" / "analyst_queue.json"
    records = _read_json(path)
    if not isinstance(records, list):
        records = [records] if records else []
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)


@st.cache_data(ttl=10)
def load_blocked_ips() -> pd.DataFrame:
    path = BASE_DIR / "alerts" / "blocked_ips.json"
    records = _read_json(path)
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)


@st.cache_data(ttl=10)
def load_ti_cache() -> dict:
    path = BASE_DIR / "cache" / "ti_cache.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────
# Styling helpers
# ─────────────────────────────────────────────────────────────

SEVERITY_COLOR = {"HIGH": "#ff4444", "MEDIUM": "#ffaa00", "LOW": "#44cc44", "UNKNOWN": "#888888"}
STATUS_ICON = {
    "AUTO_REMEDIATED": "🛡️",
    "PENDING_REVIEW": "⏳",
    "OPEN": "🔴",
    "CLOSED": "✅",
}


def severity_badge(level: str) -> str:
    color = SEVERITY_COLOR.get(level, "#888")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold">{level}</span>'


def _kpi(label: str, value, delta=None, delta_color="normal") -> None:
    st.metric(label=label, value=value, delta=delta, delta_color=delta_color)


# ─────────────────────────────────────────────────────────────
# Page sections
# ─────────────────────────────────────────────────────────────

def render_kpis(events_df: pd.DataFrame, cases_df: pd.DataFrame,
                blocked_df: pd.DataFrame) -> None:
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        _kpi("Total Events", len(events_df))
    with col2:
        alerts = int(events_df["ml_alert"].sum()) if "ml_alert" in events_df.columns else 0
        _kpi("Alerts Raised", alerts)
    with col3:
        high = int((events_df["confidence_level"] == "HIGH").sum()) if "confidence_level" in events_df.columns else 0
        _kpi("HIGH Severity", high, delta_color="inverse")
    with col4:
        _kpi("Open Cases", len(cases_df))
    with col5:
        _kpi("Blocked IPs", len(blocked_df))


def render_alert_timeline(events_df: pd.DataFrame) -> None:
    st.subheader("📅 Alert Timeline")
    if events_df.empty or "timestamp" not in events_df.columns:
        st.info("No event data available yet. Run `python platform.py --mode full` to generate data.")
        return

    alert_df = events_df[events_df.get("ml_alert", False) == True].copy() if "ml_alert" in events_df.columns else pd.DataFrame()
    if alert_df.empty:
        st.info("No alerts in the current dataset.")
        return

    alert_df["hour"] = alert_df["timestamp"].dt.floor("1h")
    timeline = alert_df.groupby(["hour", "confidence_level"]).size().reset_index(name="count")

    fig = px.bar(
        timeline, x="hour", y="count", color="confidence_level",
        color_discrete_map=SEVERITY_COLOR,
        title="Alerts per Hour by Severity",
        labels={"hour": "Time", "count": "Alert Count", "confidence_level": "Severity"},
    )
    fig.update_layout(template="plotly_dark", height=300,
                      legend=dict(orientation="h", yanchor="bottom", y=1.02))
    st.plotly_chart(fig, use_container_width=True)


def render_threat_map(events_df: pd.DataFrame) -> None:
    """Simulated geo-threat map using lat/lon approximations for known IP prefixes."""
    st.subheader("🌍 Threat Origin Map (Simulated)")

    # Country lat/lon lookup by first octet approximation
    GEO_MAP = {
        "45": (37.09, -95.71, "United States"),
        "192": (51.5, -0.12, "United Kingdom"),
        "185": (55.75, 37.62, "Russia"),
        "23": (35.68, 139.69, "Japan"),
        "198": (48.85, 2.35, "France"),
        "203": (35.69, 104.19, "China"),
        "91": (48.20, 16.37, "Austria"),
        "149": (55.75, 37.62, "Russia"),
        "8": (37.09, -95.71, "United States"),
        "1": (-33.86, 151.21, "Australia"),
        "104": (37.09, -95.71, "United States"),
        "172": (37.09, -95.71, "United States"),
    }

    if events_df.empty or "src_ip" not in events_df.columns:
        st.info("No IP data available.")
        return

    alert_ips = events_df[events_df.get("ml_alert", False) == True]["src_ip"].dropna() if "ml_alert" in events_df.columns else pd.Series()
    rows = []
    for ip in alert_ips:
        prefix = str(ip).split(".")[0]
        geo = GEO_MAP.get(prefix)
        if geo:
            rows.append({"lat": geo[0] + (hash(ip) % 5 - 2.5), "lon": geo[1] + (hash(ip[::-1]) % 5 - 2.5),
                         "country": geo[2], "ip": ip})

    if not rows:
        st.info("No geo-mappable IP addresses in current alerts.")
        return

    geo_df = pd.DataFrame(rows)
    fig = px.scatter_geo(
        geo_df, lat="lat", lon="lon", hover_name="ip", hover_data=["country"],
        color_discrete_sequence=["#ff4444"],
        projection="natural earth", title="Threat Source Locations",
    )
    fig.update_layout(template="plotly_dark", height=350,
                      geo=dict(showframe=False, showcoastlines=True,
                               bgcolor="rgba(0,0,0,0)"))
    st.plotly_chart(fig, use_container_width=True)


def render_ml_anomaly_viz(events_df: pd.DataFrame) -> None:
    st.subheader("🤖 ML Anomaly Detection")
    if events_df.empty or "anomaly_score" not in events_df.columns:
        st.info("No scored events available.")
        return

    col1, col2 = st.columns(2)

    with col1:
        fig = px.histogram(
            events_df, x="anomaly_score", color="confidence_level",
            color_discrete_map=SEVERITY_COLOR, nbins=50,
            title="Anomaly Score Distribution",
            labels={"anomaly_score": "Decision Function Score"},
        )
        fig.add_vline(x=0.0, line_dash="dash", line_color="white", annotation_text="Threshold")
        fig.update_layout(template="plotly_dark", height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        if "sbytes" in events_df.columns and "dbytes" in events_df.columns:
            sample = events_df.sample(min(500, len(events_df)), random_state=42)
            fig2 = px.scatter(
                sample, x="sbytes", y="dbytes",
                color="confidence_level", color_discrete_map=SEVERITY_COLOR,
                title="Bytes Sent vs Received (sampled)",
                labels={"sbytes": "Bytes Sent", "dbytes": "Bytes Received"},
                hover_data=["src_ip", "anomaly_score"],
            )
            fig2.update_layout(template="plotly_dark", height=300)
            st.plotly_chart(fig2, use_container_width=True)
        else:
            # fallback: score over index
            sample = events_df.sample(min(300, len(events_df)), random_state=42).reset_index(drop=True)
            fig2 = px.scatter(
                sample, x=sample.index, y="anomaly_score",
                color="confidence_level", color_discrete_map=SEVERITY_COLOR,
                title="Anomaly Score per Event",
            )
            fig2.update_layout(template="plotly_dark", height=300)
            st.plotly_chart(fig2, use_container_width=True)


def render_ti_summary(events_df: pd.DataFrame) -> None:
    st.subheader("🔍 Threat Intelligence Summary")
    if events_df.empty or "ti_risk_level" not in events_df.columns:
        st.info("No TI data available.")
        return

    col1, col2 = st.columns(2)
    with col1:
        ti_counts = events_df["ti_risk_level"].value_counts().reset_index()
        ti_counts.columns = ["Risk Level", "Count"]
        fig = px.pie(
            ti_counts, names="Risk Level", values="Count",
            color="Risk Level",
            color_discrete_map={"HIGH": "#ff4444", "MEDIUM": "#ffaa00",
                                "LOW": "#44cc44", "unknown": "#888"},
            title="TI Risk Level Distribution",
            hole=0.4,
        )
        fig.update_layout(template="plotly_dark", height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        if "ti_max_risk" in events_df.columns:
            fig2 = px.histogram(
                events_df, x="ti_max_risk", nbins=20,
                color_discrete_sequence=["#7b61ff"],
                title="TI Risk Score Distribution",
                labels={"ti_max_risk": "Composite Risk Score (0-100)"},
            )
            fig2.update_layout(template="plotly_dark", height=300)
            st.plotly_chart(fig2, use_container_width=True)


def render_soar_status(cases_df: pd.DataFrame, analyst_df: pd.DataFrame,
                       blocked_df: pd.DataFrame) -> None:
    st.subheader("⚙️ SOAR Playbook Status")
    if cases_df.empty:
        st.info("No SOAR cases yet.")
        return

    col1, col2 = st.columns(2)
    with col1:
        status_counts = cases_df["status"].value_counts().reset_index()
        status_counts.columns = ["Status", "Count"]
        fig = px.bar(
            status_counts, x="Status", y="Count",
            color="Status",
            color_discrete_map={
                "AUTO_REMEDIATED": "#44cc44", "PENDING_REVIEW": "#ffaa00",
                "CLOSED": "#888888", "OPEN": "#ff4444",
            },
            title="Case Status Distribution",
        )
        fig.update_layout(template="plotly_dark", height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        if not blocked_df.empty:
            st.markdown("**🚫 Recently Blocked IPs**")
            show = blocked_df[["ip", "blocked_at", "case_id"]].tail(10)
            st.dataframe(show, use_container_width=True, hide_index=True)
        elif not analyst_df.empty:
            st.markdown("**⏳ Analyst Review Queue**")
            cols = [c for c in ["case_id", "severity", "src_ip", "anomaly_score"] if c in analyst_df.columns]
            st.dataframe(analyst_df[cols].tail(10), use_container_width=True, hide_index=True)
        else:
            st.info("No blocked IPs or analyst queue entries yet.")


def render_live_feed(events_df: pd.DataFrame) -> None:
    st.subheader("🔴 Live Alert Feed")
    if events_df.empty or "ml_alert" not in events_df.columns:
        st.info("No alerts yet.")
        return

    alerts = events_df[events_df["ml_alert"] == True].copy()
    if alerts.empty:
        st.success("No active alerts — system nominal.")
        return

    if "timestamp" in alerts.columns:
        alerts = alerts.sort_values("timestamp", ascending=False)

    alerts = alerts.head(50)
    display_cols = [c for c in ["timestamp", "src_ip", "dst_ip", "protocol",
                                 "anomaly_score", "confidence_level", "ti_risk_level", "label"]
                    if c in alerts.columns]

    # colour rows by severity
    def _row_style(row):
        level = row.get("confidence_level", "LOW")
        bg = {"HIGH": "background-color: #3d1414", "MEDIUM": "background-color: #3d2e14",
              "LOW": "background-color: #1a3d1a"}.get(level, "")
        return [bg] * len(row)

    styled = alerts[display_cols].style.apply(_row_style, axis=1)
    st.dataframe(styled, use_container_width=True, hide_index=True, height=350)


def render_drill_down(events_df: pd.DataFrame) -> None:
    st.subheader("🔬 Event Drill-Down")
    if events_df.empty or "event_id" not in events_df.columns:
        st.info("No events to inspect.")
        return

    alert_events = events_df[events_df.get("ml_alert", False) == True] if "ml_alert" in events_df.columns else events_df
    if alert_events.empty:
        st.info("No alerts available for inspection.")
        return

    event_ids = alert_events["event_id"].dropna().tolist()
    selected_id = st.selectbox("Select Event ID to inspect", event_ids[:100])
    row = alert_events[alert_events["event_id"] == selected_id]
    if not row.empty:
        st.json(row.iloc[0].to_dict())


# ─────────────────────────────────────────────────────────────
# Main dashboard
# ─────────────────────────────────────────────────────────────

def main() -> None:
    st.set_page_config(
        page_title="AI Security Automation Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # ── Custom CSS ────────────────────────────────────────────
    st.markdown("""
    <style>
    .main { background-color: #0d1117; }
    .stApp { background-color: #0d1117; }
    h1, h2, h3 { color: #c9d1d9; }
    .stMetric > div { background: #161b22; border-radius: 8px; padding: 12px; }
    .stMetric label { color: #8b949e !important; }
    .stMetric [data-testid="stMetricValue"] { color: #58a6ff !important; font-size: 2rem !important; }
    div[data-testid="stSidebar"] { background-color: #161b22; }
    </style>
    """, unsafe_allow_html=True)

    cfg = load_config()

    # ── Header ────────────────────────────────────────────────
    st.markdown("""
    <div style="background:linear-gradient(135deg,#1a237e,#0d1117);padding:20px;border-radius:12px;margin-bottom:20px">
    <h1 style="color:#58a6ff;margin:0">🛡️ AI Security Automation Platform</h1>
    <p style="color:#8b949e;margin:4px 0 0">Real-time threat detection · TI enrichment · SOAR orchestration</p>
    </div>
    """, unsafe_allow_html=True)

    # ── Sidebar ───────────────────────────────────────────────
    with st.sidebar:
        st.image("https://via.placeholder.com/200x60/1a237e/58a6ff?text=ASAP+v1.0", use_column_width=True)
        st.markdown("---")
        refresh = st.slider("Auto-refresh (seconds)", 5, 60, 10)
        st.markdown("---")
        st.markdown("**Navigation**")
        page = st.radio("", ["Overview", "Alerts", "Threat Intel", "ML Detection",
                              "SOAR", "Drill-Down"], label_visibility="collapsed")
        st.markdown("---")
        st.markdown(f"🕐 **Last refresh:** {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")
        if st.button("🔄 Refresh Now"):
            st.cache_data.clear()
            st.rerun()

    # ── Load data ─────────────────────────────────────────────
    events_df = load_scored_events()
    cases_df = load_cases()
    analyst_df = load_analyst_queue()
    blocked_df = load_blocked_ips()

    # ── Pages ─────────────────────────────────────────────────
    if page == "Overview":
        render_kpis(events_df, cases_df, blocked_df)
        st.markdown("---")
        render_alert_timeline(events_df)
        st.markdown("---")
        c1, c2 = st.columns(2)
        with c1:
            render_ti_summary(events_df)
        with c2:
            render_soar_status(cases_df, analyst_df, blocked_df)
        st.markdown("---")
        render_threat_map(events_df)

    elif page == "Alerts":
        render_kpis(events_df, cases_df, blocked_df)
        st.markdown("---")
        render_live_feed(events_df)
        st.markdown("---")
        render_alert_timeline(events_df)

    elif page == "Threat Intel":
        render_ti_summary(events_df)
        render_threat_map(events_df)

    elif page == "ML Detection":
        render_ml_anomaly_viz(events_df)

    elif page == "SOAR":
        render_soar_status(cases_df, analyst_df, blocked_df)
        if not cases_df.empty:
            st.markdown("---")
            st.subheader("📋 All Cases")
            st.dataframe(cases_df.tail(100), use_container_width=True, hide_index=True)

    elif page == "Drill-Down":
        render_drill_down(events_df)

    # ── Auto-refresh ──────────────────────────────────────────
    time.sleep(0.1)
    st.markdown(f"<div style='text-align:right;color:#444;font-size:0.75em'>Auto-refresh every {refresh}s</div>",
                unsafe_allow_html=True)


if __name__ == "__main__":
    main()
