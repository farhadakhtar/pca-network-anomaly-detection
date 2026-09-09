# Exp5 — Baseline comparison (identical splits)
- Train: same benign-train (n=5600); OCSVM subsampled to 3000 | Test: same test (n=8400)
- Model: PCA / IF / OCSVM / MLP-AE | Threshold: each model's own P99-of-train rule (same protocol)

## Metrics

| model           |   precision |   recall |     f1 |    fpr |   auroc |   auprc |   support_benign |   support_attack |   tn |   fp |   fn |   tp |   train_s |   infer_s |
|:----------------|------------:|---------:|-------:|-------:|--------:|--------:|-----------------:|-----------------:|-----:|-----:|-----:|-----:|----------:|----------:|
| PCA             |      0.9881 |   0.5252 | 0.6858 | 0.0158 |  0.9139 |  0.9644 |             2400 |             6000 | 2362 |   38 | 2849 | 3151 |      0.06 |     0.014 |
| IsolationForest |      0.7048 |   0.0123 | 0.0242 | 0.0129 |  0.8497 |  0.8966 |             2400 |             6000 | 2369 |   31 | 5926 |   74 |      0.36 |     0.128 |
| OneClassSVM     |      0.9908 |   0.6605 | 0.7926 | 0.0154 |  0.9705 |  0.9871 |             2400 |             6000 | 2363 |   37 | 2037 | 3963 |      0.05 |     0.29  |
| AutoencoderMLP  |      0.9916 |   0.7322 | 0.8424 | 0.0154 |  0.9674 |  0.9869 |             2400 |             6000 | 2363 |   37 | 1607 | 4393 |      3.03 |     0.015 |

## Figures
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\runtime_exp5.png`

## What worked
- best F1: AutoencoderMLP (0.842)
- PCA: F1=0.686, train=0.06s (cheapest linear option)

## What failed
- f

## Leakage check
- scaler + PCA + threshold fit on benign-train only; labels used solely for scoring/slicing (EDR V-01); identical X_train/X_test for all models (EDR §3 Exp5)

## Reproduction
- Notebook: `notebooks/06_baseline_comparison.ipynb`
