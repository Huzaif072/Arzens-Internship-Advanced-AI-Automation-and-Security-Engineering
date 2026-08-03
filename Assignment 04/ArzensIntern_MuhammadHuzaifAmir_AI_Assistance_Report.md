# AI Assistance Report — Assignment 04

## AI Platform Used

- **Tool:** Claude
- **Date:** August 2026

## How AI Assisted My Work

| Task | AI Assistance | Independent Work |
|------|--------------|------------------|
| Task 1 — Design Brief | Helped structure sections, suggested citation topics, formatted pipeline diagram | Chose Scenario A, wrote threat analysis, defined FP/FN trade-offs, reviewed all content |
| Task 2 — train_model.py | Generated modular pipeline skeleton, suggested hyperparameter grids | Validated dataset schema, ran training, verified metrics, adjusted config.yaml |
| Task 3 — evaluate_model.py | Helped scaffold SHAP analysis and HTML report template | Ran evaluation, interpreted SHAP plots, wrote threshold recommendations |
| EDA Notebook | Assisted with visualization code patterns | Ran all cells, analyzed correlation heatmap and class distribution |
| README & model_card | Drafted documentation structure | Reviewed and customized for my submission |

## Prompts / Questions Asked

1. "How should I handle class imbalance in CICIDS2017 for intrusion detection?"
2. "What security metrics matter most when recall is prioritized over precision?"
3. "Help me structure train_model.py with load_data, preprocess, train_models, save_artifacts functions."
4. "How do I generate SHAP force plots for false positives and false negatives?"
5. "Write a 2-page design brief for network intrusion detection using CICIDS2017."

## Challenges Encountered

- **Class imbalance:** Benign traffic dominated ~78% of records; SMOTE and balanced class weights were needed to improve attack recall.
- **SHAP performance:** Full test-set SHAP was slow; sampling 500 records balanced speed and accuracy of explanations.
- **Threshold tuning:** Default 0.5 threshold missed some attacks; lowering to ~0.35 improved recall with acceptable false positive rate.
- **Data quality:** Missing values in timing features required median imputation before scaling.

## Lessons Learned

- Accuracy alone is misleading on imbalanced security datasets — PR-AUC and recall are more meaningful.
- Feature selection (mutual information) reduced noise and improved training speed without hurting F1.
- SHAP explanations build analyst trust and help debug false positives in production.
- Reproducibility (fixed seeds, config.yaml, versioned artifacts) is essential for production ML pipelines.
- AI tools accelerate boilerplate code and documentation, but understanding metrics and security trade-offs requires independent study.

## Tasks Completed Independently

- Dataset exploration and understanding of feature meanings
- Choosing Scenario A and justifying ML over signature-based detection
- Running the full pipeline end-to-end and verifying outputs
- Interpreting evaluation results and writing production recommendations
- Final review of all submission files

---

*This report fulfills the assignment requirement to disclose AI assistance transparently.*
