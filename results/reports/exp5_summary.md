# Exp5 — Baseline comparison (identical splits)
- Train: same benign-train (n=5600); OCSVM subsampled to 3000 | Test: same test (n=8400)
- Model: PCA / IF / OCSVM / MLP-AE | Threshold: each model's own P99-of-train rule (same protocol)

## Metrics

| model           |   precision |   recall |     f1 |    fpr |   auroc |   auprc |   support_benign |   support_attack |   tn |   fp |   fn |   tp |   train_s |   infer_s |
|:----------------|------------:|---------:|-------:|-------:|--------:|--------:|-----------------:|-----------------:|-----:|-----:|-----:|-----:|----------:|----------:|
| PCA             |      0.9914 |   0.6522 | 0.7868 | 0.0142 |  0.9437 |  0.9781 |             2400 |             6000 | 2366 |   34 | 2087 | 3913 |      0.11 |     0.014 |
| IsolationForest |      0.717  |   0.0127 | 0.0249 | 0.0125 |  0.8829 |  0.9107 |             2400 |             6000 | 2370 |   30 | 5924 |   76 |      0.63 |     0.29  |
| One-Class SVM   |      0.9914 |   0.6937 | 0.8162 | 0.015  |  0.9835 |  0.9928 |             2400 |             6000 | 2364 |   36 | 1838 | 4162 |      0.12 |     0.439 |
| Autoencoder     |      0.994  |   0.8582 | 0.9211 | 0.0129 |  0.9916 |  0.9966 |             2400 |             6000 | 2369 |   31 |  851 | 5149 |      5.33 |     0.019 |

## Figures
- `runtime_exp5.png`

## What worked
- best F1: Autoencoder (0.921); PCA trains in 0.11s

## What failed
- f

## Leakage check
- identical X_train/X_test for all models (EDR §3 Exp5)

## Reproduction
- Notebook: `notebooks/06_baseline_comparison.ipynb`
