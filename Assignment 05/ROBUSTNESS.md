# ROBUSTNESS.md — Limitations & Improvement Notes

Assignment 05 · Task 3, Part B · Muhammad Huzaif Amir

## Summary

At the default decision threshold (0.0), the Isolation Forest model is rated
**FRAGILE**: on average across four perturbation scenarios (10% Gaussian
noise, ±10% feature scaling, and a combined noise+scale attack), only
**~45.7%** of previously-detected anomalies were still flagged after a small,
realistic modification to their feature values — well below the assignment's
80% "robust" bar and close to the 50% "fragile" bar.

| Perturbation | Still detected | Evasion success |
|---|---|---|
| Baseline (no perturbation) | 42.6% (of all anomalies) | — |
| +10% Gaussian noise | 51.1% | 48.9% |
| Scale ×0.9 | 36.4% | 63.6% |
| Scale ×1.1 | 50.0% | 50.0% |
| Combined noise + scale-down | 45.4% | 54.6% |

(Rates are relative to *anomalies the model would flag before perturbation*
where noted, and to the perturbed population directly for the scenario
table above — see `outputs/evaluation_output/robustness_results.json` for
exact figures.)

**Conclusion: the model is fragile to simple evasion attempts.**

## Why this happens

1. **Low baseline recall.** At threshold 0.0 the model only catches 42.6% of
   real attacks in the unperturbed test set to begin with (precision is high
   at 97.1%, but that's a precision/recall trade-off, not robustness). A
   detector that is already missing most attacks has little margin left to
   absorb further perturbation before its remaining detections start
   slipping across the decision boundary too.
2. **Six raw flow features, not a rich feature space.** The assignment
   scopes the model down to `dur, spkts, dpkts, sbytes, dbytes, rate` for
   simplicity. With only six inputs, a 10% shift on all of them can move a
   borderline anomaly's isolation depth enough to cross the threshold —
   there's little redundancy across correlated features to "outvote" a
   perturbation, unlike a 40+ feature CICIDS2017-style pipeline.
3. **Isolation Forest splits on raw feature magnitude.** Because trees split
   on scaled feature values directly, uniform percentage scaling
   (×0.9 / ×1.1) is a fairly direct lever on which side of a split an
   instance lands on — this is a known theoretical weakness of
   axis-aligned isolation trees against adversaries who can shift several
   correlated features together, and is consistent with what the evasion
   test shows here (scale ×0.9 was the single most effective evasion
   scenario, at 63.6% success).
4. **Anomalies near the decision boundary are inherently easiest to evade.**
   The evasion test only perturbs anomalies the model *already* found
   somewhat anomalous; those are disproportionately the "quiet" attacks
   sitting close to the threshold — sophisticated attacks that already look
   closer to normal traffic (e.g., low-and-slow scans, blended-in botnet
   beacons) are exactly the ones most susceptible to being pushed back over
   the line by trivial changes.

## Practical implications

- Do **not** rely on this detector as a sole control against an adaptive
  adversary who can observe and adjust to detection outcomes. It is best
  used as one signal among several (e.g., paired with signature-based
  detection, rate limiting, and human triage) rather than an automated
  block/allow gate.
- The current precision/recall/robustness balance (threshold 0.0) favors
  precision. Lowering the threshold trades false positives for recall and
  would likely *improve* apparent robustness numbers too, since anomalies
  would need a larger perturbation to cross a more permissive boundary —
  but this comes at the operational cost analyzed in Part C (alert
  fatigue).

## Suggested improvements (not implemented in this submission)

- **Feature engineering**: add engineered/derived features (e.g., ratios,
  rolling statistics per source IP) so a single-dimension perturbation
  can't move as many decision-relevant signals at once.
- **Ensemble with a second detection method** (e.g., a density-based
  method like LOF, or simple statistical thresholds) so an attacker has to
  simultaneously evade multiple, differently-shaped decision boundaries.
- **Periodic retraining / adversarial retraining**: include perturbed
  variants of known attacks in a retraining set to harden the model against
  the exact evasion patterns tested here.
- **Ensemble contamination sweep**: re-run threshold tuning jointly with a
  perturbed validation set, rather than tuning purely against the clean
  test set, so the chosen threshold already accounts for some expected
  evasion.

## Other known limitations

- The evasion test in this assignment is intentionally simple (uniform
  noise/scaling), as specified by the assignment manual. It does **not**
  represent a worst-case, gradient-based, or query-optimized adversarial
  attack, and a truly adaptive attacker with model access could likely do
  meaningfully better than the ~55–64% evasion success rates measured here.
- Concept-drift and alert-fatigue checks (Part C) use a simple 50/50 split
  of the existing test set to simulate "Week 1" vs. "Week 4" traffic, since
  no genuinely time-stamped multi-week capture was available; a production
  deployment should validate drift against real chronological data.
