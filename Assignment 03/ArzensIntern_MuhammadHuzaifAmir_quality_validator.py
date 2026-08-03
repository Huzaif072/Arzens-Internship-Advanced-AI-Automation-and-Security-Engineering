#!/usr/bin/env python3
"""
quality_validator.py

Validates a feature matrix (as produced by feature_extractor.py) for schema
compliance, missing values, range/sanity issues, duplicates, and
distribution drift against a reference baseline. Produces a console report,
a CSV issue log, and a file-based report (HTML, Markdown, or JSON).

CLI usage
---------
    python3 quality_validator.py --input features.csv \\
        --reference reference_features.csv \\
        --output report.html --format html --threshold 0.05

Design notes
------------
* "Line number" for an issue is the 1-indexed row number as it would appear
  in the input CSV, including the header row (so the first data row is
  line 2) — this matches how a person would open the file in a spreadsheet
  or text editor to find the flagged row.
* Range checks use each feature's own values to compute a mean/std for the
  ">5 std" outlier check, rather than hard-coded thresholds, since normal
  ranges differ a lot between features (e.g. bytes_transferred vs.
  failure_ratio).
* Drift detection uses a two-sample Kolmogorov-Smirnov test per numeric
  feature (scipy.stats.ks_2samp) comparing the current file's distribution
  to the reference file's distribution for that same column. "Concept
  drift" is approximated by comparing the pairwise correlation matrix of a
  few related feature pairs between current and reference data; a large
  swing in correlation suggests the *relationship* between features
  changed, not just their individual distributions.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from scipy import stats

# ---------------------------------------------------------------------------
# Schema definition (mirrors feature_extractor.py / feature_dictionary.md)
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS = [
    "window_id", "entity_id", "hour", "hour_of_day",
    "login_success_count", "login_failure_count", "unique_source_ips",
    "failure_ratio", "success_rate", "time_since_last_login_min",
    "is_business_hours", "dns_query_entropy", "domain_length",
    "bytes_transferred", "unique_dest_ports", "peer_deviation",
]

# Columns allowed to be present in addition to REQUIRED_COLUMNS without
# being flagged as "unexpected" (metadata / privacy columns, and the
# dynamically-named rolling-window columns).
ALLOWED_EXTRA_COLUMNS_EXACT = {"entity_label", "privacy_risk"}
ALLOWED_EXTRA_COLUMN_PREFIXES = (
    "login_failure_count_rolling_",
    "login_success_count_rolling_",
    "bytes_transferred_rolling_",
)

NON_NEGATIVE_COLUMNS = [
    "login_success_count", "login_failure_count", "unique_source_ips",
    "dns_query_entropy", "domain_length", "bytes_transferred",
    "unique_dest_ports",
]

RATIO_COLUMNS_0_1 = ["failure_ratio", "success_rate"]

NUMERIC_COLUMNS_FOR_DRIFT = [
    "login_success_count", "login_failure_count", "unique_source_ips",
    "failure_ratio", "success_rate", "time_since_last_login_min",
    "dns_query_entropy", "domain_length", "bytes_transferred",
    "unique_dest_ports", "peer_deviation",
]

# Feature pairs checked for a change in relationship ("concept drift").
CONCEPT_DRIFT_PAIRS = [
    ("login_failure_count", "failure_ratio"),
    ("bytes_transferred", "unique_dest_ports"),
    ("login_success_count", "time_since_last_login_min"),
]


# ---------------------------------------------------------------------------
# Issue record helper
# ---------------------------------------------------------------------------

def make_issue(line_number, check_type, severity, description, recommended_action):
    """A single validation finding, shaped to match the required CSV columns."""
    return {
        "line_number": line_number,
        "check_type": check_type,
        "severity": severity,  # ERROR / WARNING / INFO
        "description": description,
        "recommended_action": recommended_action,
    }


def is_allowed_column(col):
    if col in REQUIRED_COLUMNS or col in ALLOWED_EXTRA_COLUMNS_EXACT:
        return True
    return any(col.startswith(p) for p in ALLOWED_EXTRA_COLUMN_PREFIXES)


# ---------------------------------------------------------------------------
# 1. Schema validation
# ---------------------------------------------------------------------------

def check_schema(df):
    issues = []
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    for col in missing_cols:
        issues.append(make_issue(
            None, "schema", "ERROR",
            f"Required column '{col}' is missing from the input file.",
            "Re-run feature_extractor.py or check for a truncated export; "
            "this column is required for downstream checks.",
        ))

    unexpected_cols = [c for c in df.columns if not is_allowed_column(c)]
    for col in unexpected_cols:
        issues.append(make_issue(
            None, "schema", "FAIL" if False else "WARNING",
            f"Unexpected column present: '{col}'.",
            f"Remove '{col}' from the pipeline output if it is not an "
            "intentional addition, or add it to the validator's allowed list.",
        ))

    # Type sanity: numeric columns should actually be numeric; boolean
    # column should be boolean-like.
    numeric_expected = [c for c in REQUIRED_COLUMNS
                         if c not in ("window_id", "entity_id", "hour", "is_business_hours")]
    for col in numeric_expected:
        if col in df.columns and not pd.api.types.is_numeric_dtype(df[col]):
            issues.append(make_issue(
                None, "schema", "ERROR",
                f"Column '{col}' expected to be numeric but has type {df[col].dtype}.",
                "Check the extractor for a serialization issue (e.g. a stray "
                "string value written into a numeric column).",
            ))

    if "is_business_hours" in df.columns:
        non_bool = ~df["is_business_hours"].isin([True, False, 0, 1])
        if non_bool.any():
            issues.append(make_issue(
                None, "schema", "ERROR",
                "Column 'is_business_hours' contains non-boolean values.",
                "Confirm the extractor writes a strict boolean for this column.",
            ))

    return issues


# ---------------------------------------------------------------------------
# 2. Null / missing value checks
# ---------------------------------------------------------------------------

def check_nulls(df, threshold=0.05):
    issues = []
    null_summary = {}
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            continue
        pct = df[col].isna().mean()
        null_summary[col] = pct
        if pct > threshold:
            issues.append(make_issue(
                None, "null_check", "WARNING",
                f"Column '{col}' has {pct:.1%} missing values (threshold: {threshold:.0%}).",
                f"Investigate the source of missing '{col}' values; consider "
                "imputing with 0 (count-style features) or the column mean "
                "(continuous features) if missingness is expected.",
            ))
    return issues, null_summary


# ---------------------------------------------------------------------------
# 3. Range and sanity checks
# ---------------------------------------------------------------------------

def check_ranges(df):
    issues = []

    for col in NON_NEGATIVE_COLUMNS:
        if col not in df.columns:
            continue
        bad_rows = df.index[df[col] < 0]
        for idx in bad_rows:
            issues.append(make_issue(
                idx + 2, "range_check", "ERROR",
                f"Column '{col}' has a negative value ({df.at[idx, col]}) at row {idx + 2}.",
                "Counts/sums should never be negative; check the extractor "
                "for a subtraction or sign error upstream.",
            ))

    for col in RATIO_COLUMNS_0_1:
        if col not in df.columns:
            continue
        bad_rows = df.index[(df[col] < 0) | (df[col] > 1)]
        for idx in bad_rows:
            issues.append(make_issue(
                idx + 2, "range_check", "ERROR",
                f"Column '{col}' has an out-of-range value ({df.at[idx, col]}) "
                f"at row {idx + 2}; expected 0-1.",
                f"'{col}' is a ratio and must stay within [0, 1]; check the "
                "denominator calculation for a divide-by-zero or logic error.",
            ))

    for col in NUMERIC_COLUMNS_FOR_DRIFT:
        if col not in df.columns:
            continue
        series = df[col].dropna()
        if len(series) < 2 or series.std(ddof=0) == 0:
            continue
        mean, std = series.mean(), series.std(ddof=0)
        z_scores = (df[col] - mean) / std
        outlier_rows = df.index[z_scores.abs() > 5]
        for idx in outlier_rows:
            issues.append(make_issue(
                idx + 2, "range_check", "WARNING",
                f"Column '{col}' has an extreme outlier ({df.at[idx, col]:.2f}, "
                f"z={z_scores.at[idx]:.1f}) at row {idx + 2}.",
                "Confirm this is a real event (e.g. a genuine large data "
                "transfer) rather than a parsing error before alerting on it.",
            ))

    return issues


# ---------------------------------------------------------------------------
# 4. Duplicate detection
# ---------------------------------------------------------------------------

def check_duplicates(df):
    issues = []
    if "window_id" not in df.columns or "entity_id" not in df.columns:
        return issues

    dup_mask = df.duplicated(subset=["window_id", "entity_id"], keep=False)
    if not dup_mask.any():
        return issues

    dup_df = df[dup_mask]
    for (window_id, entity_id), group in dup_df.groupby(["window_id", "entity_id"]):
        line_numbers = [idx + 2 for idx in group.index]
        issues.append(make_issue(
            ",".join(str(n) for n in line_numbers), "duplicate_check", "ERROR",
            f"Duplicate (window_id, entity_id) pair found at lines "
            f"{line_numbers}: window_id={window_id!r}, entity_id={entity_id!r}.",
            "Investigate the upstream pipeline for double-processing of the "
            "same events (e.g. a re-run that appended instead of overwrote).",
        ))
    return issues


# ---------------------------------------------------------------------------
# 5. Drift detection
# ---------------------------------------------------------------------------

def check_drift(df, reference_df, threshold=0.05):
    issues = []
    drift_details = []

    for col in NUMERIC_COLUMNS_FOR_DRIFT:
        if col not in df.columns or col not in reference_df.columns:
            continue
        current = df[col].dropna()
        reference = reference_df[col].dropna()
        if len(current) < 2 or len(reference) < 2:
            continue

        ks_stat, p_value = stats.ks_2samp(current, reference)
        mean_shift_pct = None
        if reference.mean() != 0:
            mean_shift_pct = (current.mean() - reference.mean()) / abs(reference.mean()) * 100

        detail = {
            "feature": col, "ks_statistic": ks_stat, "p_value": p_value,
            "mean_shift_pct": mean_shift_pct,
        }
        drift_details.append(detail)

        if p_value < threshold:
            issues.append(make_issue(
                None, "drift_check", "WARNING",
                f"'{col}': KS={ks_stat:.2f}, p={p_value:.3f} (significant "
                f"distribution drift vs. reference).",
                "Investigate whether this reflects a real behavior change "
                "(e.g. an attack campaign) or an upstream data issue; "
                "consider retraining any model that depends on this feature "
                "if the drift persists.",
            ))
        if mean_shift_pct is not None and abs(mean_shift_pct) > 30:
            issues.append(make_issue(
                None, "drift_check", "WARNING",
                f"'{col}': mean shifted {mean_shift_pct:+.0f}% vs. reference.",
                "Compare against known events (deployment changes, incidents) "
                "for the same period; a large shift concentrated in one "
                "feature can indicate a real security event rather than drift noise.",
            ))

    # Concept drift approximation: compare correlation between related
    # feature pairs in current vs. reference data.
    concept_drift_notes = []
    for col_a, col_b in CONCEPT_DRIFT_PAIRS:
        if col_a not in df.columns or col_b not in df.columns:
            continue
        if col_a not in reference_df.columns or col_b not in reference_df.columns:
            continue
        cur_corr = df[[col_a, col_b]].corr().iloc[0, 1]
        ref_corr = reference_df[[col_a, col_b]].corr().iloc[0, 1]
        if pd.isna(cur_corr) or pd.isna(ref_corr):
            continue
        delta = cur_corr - ref_corr
        concept_drift_notes.append((col_a, col_b, cur_corr, ref_corr, delta))
        if abs(delta) > 0.3:
            issues.append(make_issue(
                None, "drift_check", "WARNING",
                f"Concept drift: correlation between '{col_a}' and '{col_b}' "
                f"changed from {ref_corr:.2f} (reference) to {cur_corr:.2f} "
                f"(current), a shift of {delta:+.2f}.",
                "A changing relationship between two features (rather than "
                "a shift in either one alone) can mean the underlying attack "
                "pattern or user behavior has changed; review before trusting "
                "a model trained on the old relationship.",
            ))

    return issues, drift_details, concept_drift_notes


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_all_checks(df, reference_df=None, threshold=0.05):
    """Run all five validation components and return a structured result dict."""
    schema_issues = check_schema(df)
    null_issues, null_summary = check_nulls(df, threshold=threshold)
    range_issues = check_ranges(df)
    duplicate_issues = check_duplicates(df)

    if reference_df is not None:
        drift_issues, drift_details, concept_drift_notes = check_drift(
            df, reference_df, threshold=threshold
        )
    else:
        drift_issues, drift_details, concept_drift_notes = [], [], []

    all_issues = schema_issues + null_issues + range_issues + duplicate_issues + drift_issues

    error_count = sum(1 for i in all_issues if i["severity"] == "ERROR")
    warning_count = sum(1 for i in all_issues if i["severity"] == "WARNING")

    # A record is "valid" if it's not implicated in any ERROR-severity issue
    # tied to a specific line number.
    error_lines = set()
    for issue in all_issues:
        if issue["severity"] == "ERROR" and issue["line_number"] is not None:
            for part in str(issue["line_number"]).split(","):
                try:
                    error_lines.add(int(part))
                except ValueError:
                    pass
    valid_records = len(df) - len(error_lines)

    return {
        "total_records": len(df),
        "valid_records": valid_records,
        "error_count": error_count,
        "warning_count": warning_count,
        "issues": all_issues,
        "by_check": {
            "schema": schema_issues,
            "null_check": null_issues,
            "range_check": range_issues,
            "duplicate_check": duplicate_issues,
            "drift_check": drift_issues,
        },
        "null_summary": null_summary,
        "drift_details": drift_details,
        "concept_drift_notes": concept_drift_notes,
    }


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------

def _check_status(issues, error_only_fails=True):
    """PASS if no issues; FAIL if any ERROR present; WARNING otherwise."""
    if not issues:
        return "PASS"
    if error_only_fails and any(i["severity"] == "ERROR" for i in issues):
        return "FAIL"
    return "WARNING"


def print_console_report(results, input_path, reference_path):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_check = results["by_check"]

    print("=" * 60)
    print("DATA QUALITY VALIDATION REPORT")
    print(f"Generated: {now}")
    print(f"Input: {input_path}")
    if reference_path:
        print(f"Reference: {reference_path}")
    print("=" * 60)

    schema_status = _check_status(by_check["schema"])
    print(f"Check 1: Schema Validation      {schema_status} "
          f"({len(by_check['schema'])} issue(s))")

    null_status = _check_status(by_check["null_check"], error_only_fails=False)
    print(f"Check 2: Null / Missing Values  {null_status} "
          f"({len(by_check['null_check'])} feature(s) over threshold)")

    range_status = _check_status(by_check["range_check"])
    print(f"Check 3: Range / Sanity Checks  {range_status} "
          f"({len(by_check['range_check'])} issue(s))")

    dup_status = _check_status(by_check["duplicate_check"])
    print(f"Check 4: Duplicate Detection    {dup_status} "
          f"({len(by_check['duplicate_check'])} duplicate group(s))")

    drift_status = _check_status(by_check["drift_check"], error_only_fails=False)
    print(f"Check 5: Drift Detection        {drift_status} "
          f"({len(by_check['drift_check'])} alert(s))")

    print("-" * 60)
    print("SUMMARY:")
    print(f"Total Records: {results['total_records']}  "
          f"Valid Records: {results['valid_records']}  "
          f"Errors: {results['error_count']}  "
          f"Warnings: {results['warning_count']}")

    if results["issues"]:
        print("\nRecommendations:")
        seen = set()
        n = 1
        for issue in results["issues"]:
            key = issue["recommended_action"]
            if key in seen:
                continue
            seen.add(key)
            print(f"  {n}. {issue['recommended_action']}")
            n += 1
            if n > 5:
                break
    print("=" * 60)


# ---------------------------------------------------------------------------
# CSV report
# ---------------------------------------------------------------------------

def write_csv_report(results, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["line_number", "check_type", "severity", "description", "recommended_action"])
        for issue in results["issues"]:
            writer.writerow([
                issue["line_number"] if issue["line_number"] is not None else "",
                issue["check_type"], issue["severity"],
                issue["description"], issue["recommended_action"],
            ])


# ---------------------------------------------------------------------------
# JSON summary
# ---------------------------------------------------------------------------

def build_json_summary(results):
    return {
        "total_records": results["total_records"],
        "valid_records": results["valid_records"],
        "error_count": results["error_count"],
        "warning_count": results["warning_count"],
        "by_check": {
            name: len(issues) for name, issues in results["by_check"].items()
        },
        "null_summary": results["null_summary"],
        "drift_details": results["drift_details"],
    }


# ---------------------------------------------------------------------------
# HTML / Markdown file report
# ---------------------------------------------------------------------------

def build_markdown_report(results, input_path, reference_path):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_check = results["by_check"]
    lines = []
    lines.append("# Data Quality Report")
    lines.append(f"Generated: {now}  ")
    lines.append(f"Input: {input_path}  ")
    if reference_path:
        lines.append(f"Reference: {reference_path}  ")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Total Records: {results['total_records']}")
    lines.append(f"- Valid Records: {results['valid_records']}")
    lines.append(f"- Errors: {results['error_count']}")
    lines.append(f"- Warnings: {results['warning_count']}")
    lines.append(f"- Drift Alerts: {len(by_check['drift_check'])}")
    lines.append("")

    section_titles = {
        "schema": "Schema Validation",
        "null_check": "Null Checks",
        "range_check": "Range Checks",
        "duplicate_check": "Duplicate Detection",
        "drift_check": "Drift Detection",
    }
    for key, title in section_titles.items():
        issues = by_check[key]
        status = _check_status(issues, error_only_fails=(key != "null_check" and key != "drift_check"))
        lines.append(f"## {title}")
        lines.append(f"Status: **{status}**")
        if not issues:
            lines.append("- OK: no issues found.")
        else:
            for issue in issues:
                loc = f" (line {issue['line_number']})" if issue["line_number"] else ""
                lines.append(f"- **{issue['severity']}**{loc}: {issue['description']}")
        lines.append("")

    lines.append("## Recommendations")
    seen = set()
    n = 1
    for issue in results["issues"]:
        if issue["recommended_action"] in seen:
            continue
        seen.add(issue["recommended_action"])
        lines.append(f"{n}. {issue['recommended_action']}")
        n += 1
    if n == 1:
        lines.append("1. No issues found — no action required.")

    return "\n".join(lines)


def build_html_report(results, input_path, reference_path):
    md_lines = build_markdown_report(results, input_path, reference_path).split("\n")
    body_parts = []
    in_list = False
    for line in md_lines:
        if line.startswith("# "):
            if in_list:
                body_parts.append("</ul>")
                in_list = False
            body_parts.append(f"<h1>{line[2:]}</h1>")
        elif line.startswith("## "):
            if in_list:
                body_parts.append("</ul>")
                in_list = False
            body_parts.append(f"<h2>{line[3:]}</h2>")
        elif line.startswith("- ") or (line and line[0].isdigit() and line[1] == "."):
            if not in_list:
                body_parts.append("<ul>")
                in_list = True
            content = line[2:] if line.startswith("- ") else line.split(".", 1)[1].strip()
            content = content.replace("**", "")
            body_parts.append(f"<li>{content}</li>")
        elif line.strip() == "":
            if in_list:
                body_parts.append("</ul>")
                in_list = False
        else:
            if in_list:
                body_parts.append("</ul>")
                in_list = False
            body_parts.append(f"<p>{line}</p>")
    if in_list:
        body_parts.append("</ul>")

    body = "\n".join(body_parts)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Data Quality Report</title>
<style>
  body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 2rem auto; color: #222; }}
  h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.3rem; }}
  h2 {{ margin-top: 1.5rem; color: #234; }}
  li {{ margin-bottom: 0.3rem; }}
  p {{ margin: 0.2rem 0; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate a feature matrix for quality issues and distribution drift."
    )
    parser.add_argument("--input", required=True, help="Path to the feature matrix CSV to validate.")
    parser.add_argument("--reference", default=None, help="Path to a reference feature matrix CSV for drift comparison.")
    parser.add_argument("--output", default="quality_report.html", help="Path to write the file-based report.")
    parser.add_argument("--format", choices=["html", "markdown", "json"], default="html",
                         help="Format for the file-based report (default: html).")
    parser.add_argument("--threshold", type=float, default=0.05,
                         help="Drift significance threshold (p-value) and null-rate threshold (default: 0.05).")
    parser.add_argument("--csv-report", default=None,
                         help="Optional path for the per-issue CSV report (default: <output-stem>_issues.csv).")
    args = parser.parse_args()

    df = pd.read_csv(args.input)
    reference_df = pd.read_csv(args.reference) if args.reference else None

    results = run_all_checks(df, reference_df=reference_df, threshold=args.threshold)

    print_console_report(results, args.input, args.reference)

    csv_path = args.csv_report or (args.output.rsplit(".", 1)[0] + "_issues.csv")
    write_csv_report(results, csv_path)
    print(f"\nWrote issue log to {csv_path}")

    if args.format == "html":
        content = build_html_report(results, args.input, args.reference)
    elif args.format == "markdown":
        content = build_markdown_report(results, args.input, args.reference)
    else:
        content = json.dumps(build_json_summary(results), indent=2)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote {args.format} report to {args.output}")

    json_summary_path = args.output.rsplit(".", 1)[0] + "_summary.json"
    with open(json_summary_path, "w", encoding="utf-8") as f:
        json.dump(build_json_summary(results), f, indent=2)
    print(f"Wrote JSON summary to {json_summary_path}")


if __name__ == "__main__":
    main()
