# ML Threat Detection Design Brief
## Scenario A: Network Intrusion Detection (CICIDS2017)

**Author:** Arzens Intern  
**Date:** August 2026  
**Word Count:** ~950 words

---

## 1. Introduction: AI in Threat Detection

Modern Security Operations Centers (SOCs) face millions of network events daily. Traditional signature-based tools like Snort or Suricata match known attack patterns, but they miss zero-day exploits and polymorphic malware. Machine learning (ML) fills this gap by learning normal behavior and flagging deviations.

AI in threat detection means using algorithms to analyze flow records, logs, and packets at scale — faster and more consistently than human analysts. Intelligent security automation then routes high-confidence alerts to SOAR playbooks (e.g., auto-blocking an IP or isolating a host), while low-confidence events go to human review.

Real-world examples include CrowdStrike Falcon (endpoint ML), Darktrace (unsupervised network anomaly detection), and Google's TensorFlow Extended pipelines for phishing classification. The global AI cybersecurity market exceeded $24B in 2024 and continues growing as organizations adopt ML-driven detection (MarketsandMarkets, 2024).

---

## 2. Problem Definition

### What is the security threat?

Network intrusion covers attacks such as Denial of Service (DoS), Port Scanning, Brute Force login attempts, Web Application attacks (SQL injection, XSS), Infiltration (lateral movement), and Botnet command-and-control traffic. These appear as abnormal network flows — unusually high packet rates, short scan-like connections, or suspicious flag patterns.

### Why is ML suitable?

Signature-based IDS rules cannot keep up with evolving attack variants. ML models trained on flow features (duration, byte counts, TCP flags, protocol) can generalize to unseen attack behaviors. Supervised learning works well here because labeled datasets like CICIDS2017 provide ground truth for known attack families.

### False Positives vs. False Negatives

| Error Type | Impact | Example |
|------------|--------|---------|
| **False Positive (FP)** | Alert fatigue; analyst burnout; ignored real alerts | Benign backup traffic flagged as DoS |
| **False Negative (FN)** | Missed breach; data exfiltration; regulatory failure | Slow infiltration evades detection |

In high-security environments (finance, healthcare), **false negatives are costlier** — we prioritize recall. In high-volume SOCs with limited staff, **false positives drain resources** — we balance with precision. Production systems typically use a lower decision threshold (e.g., 0.35 instead of 0.5) to catch more threats at the cost of more alerts.

---

## 3. Dataset Analysis

**Source:** CICIDS2017 — Canadian Institute for Cybersecurity intrusion detection dataset, captured over five days with labeled attack scenarios (Sharafaldin et al., 2018).

**Size:** ~2.8 million flow records in the full dataset; our working subset contains 55,000+ anonymized flow records with 52 features.

**Feature Types:**
- **Numerical:** flow duration, packet/byte counts, inter-arrival times, flag counts (40+ features)
- **Categorical:** protocol (TCP/UDP/ICMP), destination port

**Class Distribution:** Severely imbalanced — Benign traffic dominates (~78%), while rare classes like Infiltration (~1%) and Botnet (~1.5%) are minority classes. This reflects real networks where attacks are uncommon.

**Data Quality Issues:**
- Missing values in timing features (~1%) from capture gaps
- Duplicate flows (~0.2%) from retransmissions
- Outliers in flow duration from long idle connections
- **Concept drift:** attack patterns evolve; models need periodic retraining

---

## 4. Model Selection

We evaluate three candidate algorithms:

### Random Forest (Algorithm A)
- **Why suitable:** Handles mixed feature types, robust to outliers, provides feature importance for analyst trust
- **Trade-off:** Fast training (~45s), good interpretability, slightly lower accuracy than boosting

### XGBoost (Algorithm B)
- **Why suitable:** State-of-the-art on tabular security data; handles class imbalance via `scale_pos_weight`; strong regularization
- **Trade-off:** Best accuracy/recall balance (~120s training), less interpretable than RF but supports SHAP

### Neural Network (Algorithm C)
- **Architecture:** Input → Dense(128) → Dropout(0.3) → Dense(64) → Softmax output
- **Why suitable:** High capacity for complex non-linear patterns
- **Trade-off:** Slowest training (~300s), needs more data and tuning; lower interpretability

---

## 5. Evaluation Strategy

| Metric | Security Relevance |
|--------|-------------------|
| **Accuracy** | Overall correctness; misleading when classes are imbalanced |
| **Precision** | Of alerts fired, how many are real? Controls alert volume |
| **Recall** | Of real attacks, how many did we catch? Critical for breach prevention |
| **F1-Score** | Harmonic balance of precision and recall |
| **ROC-AUC** | Threshold-independent ranking ability |
| **PR-AUC** | Better for imbalanced data — focuses on minority (attack) class |

**Cross-validation:** Stratified 5-fold CV preserves class ratios in each fold.  
**Test holdout:** 15% held-out test set, never seen during training or tuning, simulates production deployment.

**Class imbalance handling:** SMOTE oversampling on training data + balanced class weights in Random Forest and XGBoost.

---

## 6. ML Pipeline Diagram

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────┐    ┌─────────┐
│  Raw PCAP   │───▶│   Feature    │───▶│  Preprocess │───▶│  ML Model │───▶│  Alert  │
│  / Flow     │    │  Engineering │    │  & SMOTE    │    │  (RF/XGB) │    │  to SOC │
│  Records    │    │  (40+ feats) │    │  & Scaling  │    │           │    │         │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────┘    └─────────┘
       │                  │                    │                  │
       ▼                  ▼                    ▼                  ▼
  CICIDS2017         Duration,            Train/Val/Test      Threshold
  CSV Dataset        Packets, Bytes,      Split 70/15/15      Tuning + SHAP
                     Flags, Protocol                           Explainability
```

---

## 7. Supervised vs. Unsupervised Detection

**Supervised** (our approach): Requires labeled attack/benign data. High precision when labels are accurate; struggles with novel zero-day attacks not in training set.

**Unsupervised** (e.g., Isolation Forest, autoencoders): Learns normal baseline, flags anomalies. Catches unknown attacks but produces many false positives on legitimate unusual traffic (e.g., software updates).

A hybrid SOC architecture uses supervised models for known attack families and unsupervised models for anomaly hunting — combining both reduces blind spots.

---

## 8. Ethical and Responsible AI

- **Bias:** Training data may under-represent certain attack types or geographies, causing uneven detection
- **Transparency:** SHAP explanations help analysts understand why an alert fired — required for accountability
- **Privacy:** Flow metadata should be anonymized (IP hashing) before model training
- **Human oversight:** ML augments analysts; automated blocking should require human approval for high-impact actions
- **Adversarial ML:** Attackers may craft traffic to evade models — continuous red-team testing is essential

---

## 9. Real-World SOC Use Cases

1. **DoS mitigation:** Real-time flow scoring triggers automatic rate limiting when recall-optimized threshold fires
2. **Port scan detection:** Short-duration, low-byte flows classified within milliseconds at network edge
3. **Insider threat correlation:** ML network scores combined with user behavior analytics for unified risk view
4. **Incident triage:** SHAP explanations reduce mean-time-to-investigate by showing top contributing features upfront

---

## 10. Conclusion

Network intrusion detection with ML on CICIDS2017-style flow features provides a practical, production-ready approach to complement signature-based tools. XGBoost with SMOTE and recall-optimized thresholds offers the best balance for SOC deployment, while SHAP interpretability builds analyst trust. Continuous monitoring for concept drift and ethical governance ensure the system remains effective and responsible over time.

---

## References

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSp.
2. Buczak, A. L., & Guven, E. (2016). *A Survey of Data Mining and Machine Learning Methods for Cyber Security Intrusion Detection.* IEEE Communications Surveys & Tutorials, 18(2).
3. MarketsandMarkets (2024). *AI in Cybersecurity Market — Global Forecast to 2028.*
4. Lundberg, S. M., & Lee, S.-I. (2017). *A Unified Approach to Interpreting Model Predictions (SHAP).* NeurIPS.

---

## AI Assistance Note

Claude (Cursor AI) was used to help structure this document, suggest evaluation metrics rationale, and format the pipeline diagram. All technical decisions and scenario analysis were reviewed and validated independently.
