#!/usr/bin/env python3
"""
feature_extractor.py

Aggregates raw security telemetry (authentication, network, and DNS events)
into ML-ready feature matrices, keyed by (entity, hour) windows.

Input
-----
A JSONL file where each line is one raw event. Recognized event_type values
and their fields:

  AUTH:    timestamp, user, source_ip, host, status, event_type
  NETWORK: timestamp, source_ip, dest_ip, port, bytes, protocol, event_type
  DNS:     timestamp, client_ip, query_domain, record_type, response, event_type

Output
------
A feature matrix (CSV + JSON), one row per (entity_id, hour) window, with
the 12+ features described in feature_dictionary.md, plus pseudonymization
and a privacy-risk column.

Design notes (non-obvious choices -- also explained in feature_dictionary.md)
------------------------------------------------------------------------------
* Entity resolution differs by window type, because the three log types
  don't all carry the same identity fields:
    - 'user-hour' windows use the AUTH event's 'user' field. NETWORK and DNS
      events have no username in this dataset, so they do not contribute to
      user-hour windows.
    - 'host-hour' windows use AUTH's 'host' field, or NETWORK's 'source_ip',
      or DNS's 'client_ip' -- i.e. whatever network-facing identifier the
      event carries. DNS's 'client_ip' is treated as equivalent to
      'source_ip' for this purpose.
* Missing values are imputed with 0 for count/sum-style features (a bucket
  with no DNS traffic really did see zero DNS queries) and left as the
  bucket-local mean for the one genuinely continuous feature that has no
  natural "zero" (time_since_last_login for an entity's first-ever event
  in the dataset has no prior event to compare to).
* peer_deviation's "peer group" is defined as every entity active in the
  same hour bucket, because this synthetic dataset has no org/team mapping.
  A production deployment would scope this to an actual team roster.
* Pseudonymization: entity_id is hashed with HMAC-SHA256 by default. For
  grading/debugging transparency, this sample run also emits the raw label
  in an 'entity_label' column -- in a real deployment that column would not
  leave the security team's access-controlled environment.
"""

import argparse
import hashlib
import hmac
import json
import math
import sys
from collections import Counter

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Secret key used for HMAC pseudonymization. In production this must come
# from a secrets manager / environment variable, never be hard-coded, and
# must be rotated according to policy. Kept as an obvious placeholder here
# so it is not mistaken for a real secret.
PSEUDONYM_KEY = b"CHANGE_ME_IN_PRODUCTION_secret_key"

BUSINESS_HOUR_START = 9
BUSINESS_HOUR_END = 18  # exclusive

# Per-feature privacy risk, used for the feature_dictionary output and to
# derive the row-level privacy_risk column. Mirrors the Task 1 brief.
FEATURE_PRIVACY_RISK = {
    "login_success_count": "LOW",
    "login_failure_count": "LOW",
    "unique_source_ips": "MEDIUM",
    "failure_ratio": "LOW",
    "success_rate": "LOW",
    "time_since_last_login_min": "MEDIUM",
    "hour_of_day": "LOW",
    "is_business_hours": "LOW",
    "dns_query_entropy": "LOW",
    "domain_length": "LOW",
    "bytes_transferred": "MEDIUM",
    "unique_dest_ports": "LOW",
    "peer_deviation": "HIGH",
}


# ---------------------------------------------------------------------------
# Pseudonymization
# ---------------------------------------------------------------------------

def pseudonymize(value):
    """
    Return a short, deterministic, non-reversible token for a raw identity
    value (username, hostname, or IP), using HMAC-SHA256 truncated to 16
    hex characters. Deterministic so the same real entity always maps to
    the same token, which is required for grouping/joining on it.
    """
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return None
    digest = hmac.new(PSEUDONYM_KEY, str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"ps_{digest[:16]}"


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

def shannon_entropy(s):
    """
    Shannon entropy (base 2) of the characters in a string. Returns 0.0 for
    an empty/missing string. Used for DNS domain entropy (DGA detection).
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# Loading and normalizing raw events
# ---------------------------------------------------------------------------

def load_events(path):
    """
    Load a JSONL file of raw events into a single normalized DataFrame.
    Malformed lines (bad JSON) are skipped with a warning rather than
    crashing the run.
    """
    rows = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                skipped += 1
                print(f"WARNING: skipping malformed JSON at line {line_number}: {exc}",
                      file=sys.stderr)

    if skipped:
        print(f"WARNING: skipped {skipped} malformed line(s) while loading {path}",
              file=sys.stderr)

    df = pd.DataFrame(rows)

    required_cols = [
        "timestamp", "event_type", "user", "source_ip", "host", "status",
        "dest_ip", "port", "bytes", "protocol", "client_ip", "query_domain",
        "record_type", "response",
    ]
    for col in required_cols:
        if col not in df.columns:
            df[col] = np.nan

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    before = len(df)
    df = df.dropna(subset=["timestamp"]).copy()
    dropped = before - len(df)
    if dropped:
        print(f"WARNING: dropped {dropped} event(s) with unparseable timestamps",
              file=sys.stderr)

    # DNS events carry 'client_ip' instead of 'source_ip'; unify so every
    # event type has a single "source_ip" column to key off of.
    df["source_ip"] = df["source_ip"].where(df["source_ip"].notna(), df["client_ip"])

    df["hour_bucket"] = df["timestamp"].dt.floor("h")
    df["hour_of_day"] = df["timestamp"].dt.hour

    # Deterministic ordering, as required: sorted by timestamp then a
    # stable secondary key.
    df = df.sort_values(by=["timestamp"]).reset_index(drop=True)
    return df


def resolve_entity(df, window):
    """
    Vectorized entity resolution. Returns a Series of entity_id values (or
    NaN for events that can't contribute to this window type).
    """
    if window == "user-hour":
        # Only AUTH events carry a username in this dataset.
        return df["user"]
    elif window == "host-hour":
        # Prefer 'host' (AUTH), fall back to the unified source_ip
        # (NETWORK's source_ip / DNS's client_ip).
        return df["host"].where(df["host"].notna(), df["source_ip"])
    else:
        raise ValueError(f"unknown window type: {window!r}")


# ---------------------------------------------------------------------------
# Feature computation
# ---------------------------------------------------------------------------

def compute_features(df, window):
    """
    Compute the full feature matrix for the requested window type.
    Returns a DataFrame with one row per (entity_id, hour_bucket).
    """
    work = df.copy()
    work["entity_id"] = resolve_entity(work, window)
    work = work.dropna(subset=["entity_id"]).copy()

    if work.empty:
        raise ValueError(
            f"No events resolve to an entity for window={window!r}; "
            "check that the input has the expected fields."
        )

    # Pre-compute per-row helper values used by several aggregations.
    work["is_success"] = work["status"] == "SUCCESS"
    work["is_failure"] = work["status"] == "FAILURE"
    work["is_auth"] = work["event_type"] == "AUTH"
    work["is_network"] = work["event_type"] == "NETWORK"
    work["is_dns"] = work["event_type"] == "DNS"

    # Domain entropy / length computed once per unique domain (efficient:
    # avoids recomputing entropy for repeated domains row-by-row).
    unique_domains = work.loc[work["is_dns"], "query_domain"].dropna().unique()
    entropy_map = {d: shannon_entropy(d) for d in unique_domains}
    length_map = {d: len(d) for d in unique_domains}
    work["domain_entropy_val"] = work["query_domain"].map(entropy_map)
    work["domain_length_val"] = work["query_domain"].map(length_map)

    grouped = work.groupby(["entity_id", "hour_bucket"], sort=True)

    # --- Count features ---
    login_success_count = grouped["is_success"].apply(lambda s: int((s & work.loc[s.index, "is_auth"]).sum()))
    login_failure_count = grouped["is_failure"].apply(lambda s: int((s & work.loc[s.index, "is_auth"]).sum()))
    unique_source_ips = grouped["source_ip"].nunique()
    total_events = grouped.size()

    # --- Ratio features ---
    denom = (login_success_count + login_failure_count).replace(0, np.nan)
    failure_ratio = (login_failure_count / denom).fillna(0.0)
    success_rate = (login_success_count / total_events.replace(0, np.nan)).fillna(0.0)

    # --- Temporal features ---
    hour_of_day = grouped["hour_bucket"].first().dt.hour
    is_business_hours = hour_of_day.between(BUSINESS_HOUR_START, BUSINESS_HOUR_END - 1)

    # time_since_last_login: computed at the individual AUTH-event level
    # (minutes since that entity's previous AUTH event anywhere in the
    # dataset), then averaged into each entity-hour bucket.
    auth_events = work[work["is_auth"]].sort_values(["entity_id", "timestamp"]).copy()
    auth_events["prev_ts"] = auth_events.groupby("entity_id")["timestamp"].shift(1)
    auth_events["gap_minutes"] = (
        (auth_events["timestamp"] - auth_events["prev_ts"]).dt.total_seconds() / 60.0
    )
    time_since_last = (
        auth_events.groupby(["entity_id", "hour_bucket"])["gap_minutes"].mean()
    )

    # --- Entropy features ---
    dns_query_entropy = grouped["domain_entropy_val"].mean()
    domain_length = grouped["domain_length_val"].mean()

    # --- Behavioral features ---
    bytes_transferred = grouped.apply(
        lambda g: g.loc[g["is_network"], "bytes"].fillna(0).sum(), include_groups=False
    )
    unique_dest_ports = grouped.apply(
        lambda g: g.loc[g["is_network"], "port"].nunique(), include_groups=False
    )

    features = pd.DataFrame({
        "login_success_count": login_success_count,
        "login_failure_count": login_failure_count,
        "unique_source_ips": unique_source_ips,
        "failure_ratio": failure_ratio,
        "success_rate": success_rate,
        "time_since_last_login_min": time_since_last,
        "hour_of_day": hour_of_day,
        "is_business_hours": is_business_hours,
        "dns_query_entropy": dns_query_entropy,
        "domain_length": domain_length,
        "bytes_transferred": bytes_transferred,
        "unique_dest_ports": unique_dest_ports,
    }).reset_index()

    # Documented imputation: count/sum-style features default to 0 when a
    # bucket has no relevant events of that type; time_since_last_login has
    # no natural zero (0 would misleadingly mean "logged in again
    # instantly"), so it is imputed with the column mean instead.
    zero_impute_cols = [
        "login_success_count", "login_failure_count", "unique_source_ips",
        "dns_query_entropy", "domain_length", "bytes_transferred",
        "unique_dest_ports",
    ]
    for col in zero_impute_cols:
        features[col] = features[col].fillna(0)

    if features["time_since_last_login_min"].notna().any():
        mean_gap = features["time_since_last_login_min"].mean()
    else:
        mean_gap = 0.0
    features["time_since_last_login_min"] = features["time_since_last_login_min"].fillna(mean_gap)

    # --- Aggregational feature: peer_deviation ---
    # Peer group = all entities active in the same hour bucket (see module
    # docstring). Z-score of login_failure_count within that hour.
    def _zscore(group):
        mean = group.mean()
        std = group.std(ddof=0)
        if std == 0 or np.isnan(std):
            return pd.Series(0.0, index=group.index)
        return (group - mean) / std

    features["peer_deviation"] = (
        features.groupby("hour_bucket")["login_failure_count"]
        .transform(_zscore)
    )

    # --- Window bookkeeping columns ---
    features["hour_bucket_str"] = features["hour_bucket"].dt.strftime("%Y-%m-%d_%H")
    features["window_id"] = (
        features["hour_bucket_str"] + "_" + features["entity_id"].astype(str)
    )

    # --- Privacy controls ---
    features["entity_label"] = features["entity_id"]  # raw value, see module docstring
    features["entity_id"] = features["entity_id"].map(pseudonymize)
    features["window_id"] = (
        features["hour_bucket_str"] + "_" + features["entity_id"].astype(str)
    )
    features["privacy_risk"] = np.where(
        features["peer_deviation"].abs() > 0, "HIGH",
        np.where(window == "user-hour", "MEDIUM", "LOW"),
    )

    ordered_cols = [
        "window_id", "entity_id", "entity_label", "hour_bucket_str", "hour_of_day",
        "login_success_count", "login_failure_count", "unique_source_ips",
        "failure_ratio", "success_rate", "time_since_last_login_min",
        "is_business_hours", "dns_query_entropy", "domain_length",
        "bytes_transferred", "unique_dest_ports", "peer_deviation", "privacy_risk",
    ]
    features = features.rename(columns={"hour_bucket_str": "hour"})
    ordered_cols[ordered_cols.index("hour_bucket_str")] = "hour"

    features = features[ordered_cols].sort_values(["hour", "entity_id"]).reset_index(drop=True)
    return features


def apply_rolling(features, rolling):
    """
    Add rolling-window aggregations (sum over the trailing N hours per
    entity) for the three headline count/volume features. `rolling` is one
    of '1h', '4h', '24h'.
    """
    hours_map = {"1h": 1, "4h": 4, "24h": 24}
    if rolling not in hours_map:
        raise ValueError(f"unsupported --rolling value: {rolling!r}")
    window_size = hours_map[rolling]

    features = features.sort_values(["entity_id", "hour"]).copy()
    roll_cols = ["login_failure_count", "login_success_count", "bytes_transferred"]
    for col in roll_cols:
        features[f"{col}_rolling_{rolling}"] = (
            features.groupby("entity_id")[col]
            .transform(lambda s: s.rolling(window=window_size, min_periods=1).sum())
        )
    return features


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_outputs(features, output_csv, output_json):
    features.to_csv(output_csv, index=False)

    records = json.loads(features.to_json(orient="records"))
    payload = {
        "metadata": {
            "record_count": len(records),
            "features": [c for c in features.columns if c not in
                         ("window_id", "entity_id", "entity_label", "hour")],
        },
        "records": records,
    }
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def print_summary(features, window):
    print("=" * 60)
    print("FEATURE EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Window type:      {window}")
    print(f"Rows (entity-hr): {len(features)}")
    print(f"Unique entities:  {features['entity_id'].nunique()}")
    print(f"Hour buckets:     {features['hour'].nunique()}")
    print("-" * 60)
    numeric_cols = features.select_dtypes(include=[np.number]).columns
    print(features[numeric_cols].describe().T[["mean", "std", "min", "max"]])
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Aggregate raw security events into ML-ready feature matrices."
    )
    parser.add_argument("--input", required=True, help="Path to input JSONL event file.")
    parser.add_argument("--output", required=True, help="Path to output CSV feature matrix.")
    parser.add_argument(
        "--window", choices=["user-hour", "host-hour"], default="user-hour",
        help="Aggregation window type (default: user-hour).",
    )
    parser.add_argument(
        "--rolling", choices=["1h", "4h", "24h"], default=None,
        help="Optional rolling aggregation window to add on top of the hourly buckets.",
    )
    args = parser.parse_args()

    df = load_events(args.input)
    features = compute_features(df, args.window)

    if args.rolling:
        features = apply_rolling(features, args.rolling)

    output_csv = args.output
    output_json = output_csv.rsplit(".", 1)[0] + ".json" if "." in output_csv else output_csv + ".json"

    write_outputs(features, output_csv, output_json)
    print_summary(features, args.window)
    print(f"\nWrote {len(features)} rows to {output_csv} and {output_json}")


if __name__ == "__main__":
    main()
