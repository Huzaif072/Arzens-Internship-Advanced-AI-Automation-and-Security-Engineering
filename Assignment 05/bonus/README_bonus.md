# Bonus Practical Tasks — Notes

Assignment 05 · Muhammad Huzaif Amir

## A note on data access

Both Practical Tasks reference Kaggle-hosted datasets (CICIDS2017,
UNSW-NB15). The execution environment used for this submission only has
network access to a small allowlist (PyPI, npm, GitHub, crates.io, and a
few OS package mirrors) and **cannot reach kaggle.com**. Rather than skip
the practical tasks, I adapted them using the assignment's explicit
fallback ("use your synthetic data generator from previous assignments")
extended to both benchmark datasets — see below.

---

## Practical Task 1 — Real Data Exploration (adapted)

**Files:** `bonus/generate_unsw_style_dataset.py`, `bonus/compare_datasets.py`

Since I already had a CICIDS2017-style synthetic generator from Assignment
04 (`network_traffic_dataset.csv`), I built a second generator that mirrors
UNSW-NB15's **native column names** (`dur, spkts, dpkts, sbytes, dbytes,
rate`) and its real `attack_cat` categories (Generic, Exploits, Fuzzers,
DoS, Reconnaissance, Analysis, Backdoor, Shellcode, Worms), with class
proportions and per-class distributions loosely modeled on the well-known
shape of the real dataset — in particular, giving several "quiet" attack
categories (Fuzzers, Analysis, Backdoor, Worms) feature distributions that
deliberately overlap with Normal traffic, since that overlap is a
documented reason UNSW-NB15 is considered harder to model than
CICIDS2017-style traffic dominated by loud DoS/PortScan attacks.

`compare_datasets.py` trains and evaluates the exact same Isolation Forest
pipeline from `anomaly_detector.py` on both datasets and reports:

| Dataset | Samples | Attack Rate | Accuracy | Precision | Recall | F1 | Normal↔Attack Centroid Distance |
|---|---|---|---|---|---|---|---|
| CICIDS2017-style | 55,110 | 22.0% | 87.3% | 97.1% | 42.6% | 0.593 | 2.067 |
| UNSW-NB15-style | 55,000 | 32.0% | 72.9% | 73.8% | 23.5% | 0.357 | 1.248 |

**Which dataset is harder? The UNSW-NB15-style dataset.** Its F1 (0.357) is
well below the CICIDS2017-style dataset's F1 (0.593), and the standardized
distance between the Normal and Attack class centroids (1.248 vs. 2.067) is
noticeably smaller — meaning the two classes sit closer together in the
six-dimensional scaled feature space, which is exactly what makes them
harder for an unsupervised, distance/isolation-based method to separate.

**Why:** the UNSW-style generator intentionally gives several attack
categories (Fuzzers, Analysis, Backdoor, Worms — together about 9% of all
traffic) flow statistics very close to Normal traffic, mirroring how those
categories behave in the real UNSW-NB15 dataset. In contrast, the
CICIDS2017-style generator's dominant attack types (DoS, PortScan) are
statistically loud outliers (very high packet rates or very short/empty
flows), which Isolation Forest isolates easily. This matches a pattern
reported in the broader intrusion-detection literature: models that do
well on CICIDS2017 often see a meaningful accuracy/F1 drop when evaluated
on UNSW-NB15, because UNSW-NB15's attack diversity includes several
"quiet" categories that don't stand out on simple flow statistics alone.

**Caveat:** these are synthetic proxies, not the real datasets, so the
exact numbers should not be treated as benchmark results — the point of
this exercise is the *comparative* finding (harder vs. easier, and why),
which should hold directionally against the real data given how the
generators were designed.

---

## Practical Task 2 — Dashboard Creation

**File:** `bonus/dashboard.py`

A Streamlit dashboard: upload a CSV → the app scores every row with the
trained Isolation Forest pipeline → view anomaly counts, a score
distribution histogram, a flagged-rows table, and (if a label column is
present) live precision/recall/F1. Results are downloadable as CSV.

Run it with:

```bash
pip install streamlit
streamlit run bonus/dashboard.py
```

See `bonus/README_dashboard.md` for a walkthrough and a screenshot
description (a live screenshot could not be captured in this text-only
execution environment, since Streamlit's UI requires a running browser
session — the script has been tested end-to-end via `streamlit run` to
confirm it launches and scores data correctly).
