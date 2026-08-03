# Model Card: Network Intrusion Detection Model

## Model Details

- **Model name:** Network Intrusion Detector v1.0
- **Version:** v1.0_20260801
- **Type:** Supervised binary classifier (Benign vs Attack)
- **Algorithm:** XGBoost (primary), with Random Forest and Neural Network benchmarks
- **Framework:** scikit-learn, XGBoost
- **Training date:** August 2026

## Intended Use

- **Primary use:** Detect malicious network traffic in enterprise SOC environments
- **Users:** Security analysts, SOC engineers, incident responders
- **Deployment context:** Batch scoring of network flow records; near-real-time inference at network sensors
- **Out-of-scope:** Endpoint malware detection, phishing email classification, encrypted traffic deep inspection

## Training Data

- **Dataset:** CICIDS2017-style synthetic network flow dataset (55,000+ records, 52 features)
- **Attack types represented:** DoS, PortScan, BruteForce, WebAttack, Infiltration, Botnet
- **Split:** 70% train / 15% validation / 15% test (stratified)
- **Preprocessing:** StandardScaler, mutual information feature selection (top 35), SMOTE on training set

## Performance

| Metric | Value (test set) |
|--------|-----------------|
| Accuracy | 0.9972 |
| Precision | 0.9972 |
| Recall | 0.9972 |
| F1-Score | 0.9972 |
| ROC-AUC | 0.9999 |
| PR-AUC | 1.0000 |
| False Positive Rate | 0.77% |
| False Negative Rate | 0.14% |

**Best model:** XGBoost (selected over Random Forest and Neural Network by validation F1)

**Recommended production threshold:** 0.40 (prioritizes recall for threat detection)

## Limitations

- Trained on synthetic/anonymized data — performance may differ on live network captures
- Binary classification collapses attack types; multi-class model needed for attack-family-specific response
- Cannot detect attacks in fully encrypted traffic without TLS fingerprinting features
- Concept drift: attack techniques evolve; model requires monthly retraining
- Minority classes (Infiltration, Botnet) may have lower per-class recall

## Ethical Considerations

- Flow data must be anonymized before inference to protect user privacy
- Automated blocking based on model output should include human review for high-impact actions
- False positives can disproportionately affect certain network segments (e.g., backup servers)
- Model explanations (SHAP) should be provided to analysts for accountability

## Maintenance

- Retrain monthly with new labeled attack samples
- Monitor Flow Duration, Packet Count, and Flag features for drift
- Validate on holdout data from production captures before deployment
- Version all model artifacts with checksums

## Contact

Arzens Intern — Advanced Track (AI, Automation & Security Engineering)
