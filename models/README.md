# Models Directory

Pre-trained model artifacts are stored here after running `vulnscanner train`.

## Files

| File | Description |
|------|-------------|
| `vuln_classifier.joblib` | Trained XGBoost/GradientBoosting classifier |
| `model_meta.json` | Model metadata (version, AUC, feature names) |
| `training_metrics.json` | Cross-validation and training metrics |

## Training

```bash
# Generate synthetic dataset and train
vulnscanner train

# Train on custom dataset (CSV with columns: code_snippet, language, label)
vulnscanner train --data datasets/my_dataset.csv

# Generate dataset first
python datasets/generate_dataset.py --synthetic
vulnscanner train --data datasets/synthetic_training.csv
```

## Model Architecture

- **Algorithm**: XGBoost (falls back to sklearn GradientBoosting if XGBoost unavailable)
- **Features**: 18 hand-crafted security-relevant features (see `vulnscanner/ml/features.py`)
- **Explainability**: SHAP TreeExplainer for per-prediction feature importance
- **Validation**: 5-fold stratified cross-validation

## Performance (Synthetic Dataset)

| Metric | Value |
|--------|-------|
| CV ROC-AUC | ~0.95 |
| Precision (vuln) | ~0.92 |
| Recall (vuln) | ~0.88 |

*Retrain on real-world datasets (Big-Vul, Devign) for production-grade performance.*
