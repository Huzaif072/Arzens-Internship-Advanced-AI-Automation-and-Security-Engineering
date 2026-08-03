# Drift Analysis Methodology

This document explains how `quality_validator.py` detects drift, why the
Kolmogorov-Smirnov (KS) test was chosen, and how to read the results.

## What we're comparing

Every numeric feature in the current feature matrix (`login_success_count`,
`failure_ratio`, `bytes_transferred`, etc.) is compared against the same
column in a reference feature matrix — a baseline captured from an earlier,
"known good" period. The goal is to catch two different kinds of change:

1. **Data drift** — the distribution of a single feature has shifted (e.g.
   `login_failure_count` is now much higher on average than the baseline).
2. **Concept drift** — the *relationship* between two features has changed,
   even if neither feature's own distribution moved much on its own.

## Why the Kolmogorov-Smirnov test

The KS test compares two samples without assuming either is normally
distributed, which matters here because count-style security features
(failed logins, byte counts) are often skewed, not bell-shaped. It reports:

- **KS statistic**: the maximum distance between the two samples' empirical
  cumulative distribution functions. 0 means identical distributions; larger
  values mean the distributions differ more.
- **p-value**: the probability of seeing a KS statistic this large if the
  two samples actually came from the same underlying distribution. A small
  p-value (below the `--threshold`, default 0.05) means the difference is
  unlikely to be random noise — the distribution has likely genuinely shifted.

We also report a **mean shift percentage** alongside the KS test. The KS
test can be significant on a large sample even for a small, practically
unimportant shift, so the mean shift gives a second, more intuitive number
for a human reviewer: "login failures are up 45% vs. baseline" is easier to
act on than a raw KS statistic.

## Concept drift approximation

True concept drift detection (the relationship between features and an
actual outcome label changing) requires labeled data, which this synthetic
dataset does not have. As a practical proxy, the validator computes the
Pearson correlation between a few security-meaningful feature pairs (e.g.
`login_failure_count` vs. `failure_ratio`) in both the current and reference
data, and flags a pair whose correlation has shifted by more than 0.3. A
large change in how two features move together suggests the underlying
behavior pattern has changed, not just its scale — for example, if failed
logins used to correlate closely with unique source IPs (many attackers,
few attempts each) but now don't (fewer sources, many attempts each), that
points to a different kind of attack (credential stuffing vs. brute force
from one host) even if the raw failure count looks similar.

## Interpreting drift alerts

- A KS/p-value alert on its own, with a small mean shift, is often worth a
  quick look but not urgent — it may reflect natural week-to-week variation.
- A KS alert **combined with** a large mean shift (as seen for
  `login_failure_count` and `failure_ratio` in the sample report, both driven
  by a synthetic brute-force burst) is a stronger signal and worth
  investigating as a possible real security event before assuming "model
  drift."
- Persistent drift across multiple validation runs (e.g. the same feature
  flagged for 3+ consecutive days) is the trigger point for retraining any
  downstream ML model, since a model trained on the old distribution will
  degrade in accuracy the longer the drift continues unaddressed.

## Limitations

- KS test power depends on sample size; with only ~30 rows per run (as in
  the sample data here), only fairly large shifts will reach statistical
  significance. Production deployments with thousands of daily rows will
  detect smaller, subtler shifts.
- The concept-drift correlation check only covers a small, hand-picked list
  of feature pairs (`CONCEPT_DRIFT_PAIRS` in `quality_validator.py`). A more
  complete implementation would monitor the full pairwise correlation matrix
  or use a dedicated concept-drift detector (e.g. a windowed classifier
  accuracy tracker), which is beyond this assignment's scope.
