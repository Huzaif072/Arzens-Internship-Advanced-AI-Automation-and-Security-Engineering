# Assignment 04 — ML Threat Detection for Cybersecurity

**Advanced Track:** AI, Automation & Security Engineering  
**Scenario:** Network Intrusion Detection (CICIDS2017-style)

## Project Structure

```
Assignment 04/
├── network_traffic_dataset.csv      # Dataset (55,000+ flow records)
├── config.yaml                      # Hyperparameters and pipeline settings
├── ArzensIntern_MuhammadHuzaifAmir_MLDesignBrief.pdf   # Task 1: Design brief
├── ArzensIntern_MuhammadHuzaifAmir_train_model.py      # Task 2: ML training pipeline
├── ArzensIntern_MuhammadHuzaifAmir_evaluate_model.py   # Task 3: Evaluation pipeline
├── ArzensIntern_MuhammadHuzaifAmir_ML_Threat_Detection.ipynb
├── model_card.md                    # Model documentation
├── AI_Assistance_Report.md          # AI disclosure report
├── requirements_ml.txt              # Pinned dependencies
├── model_artifacts/                 # Saved models and logs (after training)
├── shap_analysis/                   # SHAP plots (after evaluation)
└── evaluation_output/               # Metrics, curves, confusion matrix
```

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements_ml.txt

# 2. Train models (RF, XGBoost, Neural Network)
python ArzensIntern_MuhammadHuzaifAmir_train_model.py

# 3. Evaluate best model with SHAP analysis
python ArzensIntern_MuhammadHuzaifAmir_evaluate_model.py

# 4. Open notebook for EDA
jupyter notebook ArzensIntern_MuhammadHuzaifAmir_ML_Threat_Detection.ipynb
```

## Tasks Completed

| Task | Deliverable | Status |
|------|-------------|--------|
| Task 1 | Design Brief (Scenario A: Network Intrusion Detection) | ✅ |
| Task 2 | train_model.py, config.yaml, notebook, model artifacts | ✅ |
| Task 3 | evaluate_model.py, evaluation report, SHAP, model_card | ✅ |

## Models Trained

1. **Random Forest** — interpretable baseline with balanced class weights
2. **XGBoost** — gradient boosting with scale_pos_weight for imbalance
3. **Neural Network** — MLP (128→64) with dropout and early stopping

## Key Features

- Schema validation and data quality checks
- SMOTE + mutual information feature selection
- RandomizedSearchCV with StratifiedKFold
- Security metrics: FPR, FNR, PR-AUC, threshold analysis
- SHAP global and local interpretability
- Production readiness check (latency, size, robustness)

## GitHub Repository

https://github.com/Huzaif072/Arzens-Internship-Advanced-AI-Automation-and-Security-Engineering

## AI Assistance

See `AI_Assistance_Report.md` for disclosure of Claude (Cursor) usage.
