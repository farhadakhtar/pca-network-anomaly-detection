# Exp1 — Basic anomaly detection
- Train: synthetic_A benign-train (n=5600, seed=42) | Test: benign-test + mixed attacks (n=8400)
- Model: PCA k=19, variance=0.956 | Threshold: P99 = 22.25

## Metrics

|   k | strategy   |   threshold |   precision |   recall |     f1 |    fpr |   auroc |   auprc |   support_benign |   support_attack |   tn |   fp |   fn |   tp |
|----:|:-----------|------------:|------------:|---------:|-------:|-------:|--------:|--------:|-----------------:|-----------------:|-----:|-----:|-----:|-----:|
|  19 | p95        |      5.2534 |      0.969  |   0.6347 | 0.767  | 0.0508 |  0.9139 |  0.9644 |             2400 |             6000 | 2278 |  122 | 2192 | 3808 |
|  19 | p99        |     22.2493 |      0.9881 |   0.5252 | 0.6858 | 0.0158 |  0.9139 |  0.9644 |             2400 |             6000 | 2362 |   38 | 2849 | 3151 |
|  19 | p99.5      |     40.0233 |      0.9958 |   0.5098 | 0.6744 | 0.0054 |  0.9139 |  0.9644 |             2400 |             6000 | 2387 |   13 | 2941 | 3059 |
|  19 | mean+2std  |     22.7707 |      0.9881 |   0.525  | 0.6857 | 0.0158 |  0.9139 |  0.9644 |             2400 |             6000 | 2362 |   38 | 2850 | 3150 |
|  19 | mean+3std  |     33.2768 |      0.9936 |   0.514  | 0.6775 | 0.0083 |  0.9139 |  0.9644 |             2400 |             6000 | 2380 |   20 | 2916 | 3084 |
|  19 | mad        |      1.658  |      0.9215 |   0.8137 | 0.8642 | 0.1733 |  0.9139 |  0.9644 |             2400 |             6000 | 1984 |  416 | 1118 | 4882 |

## Figures
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\score_hist_exp1.png`
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\exp1_roc.png`
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\exp1_pr.png`
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\variance_elbow.png`
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\threshold_frontier_exp1.png`

## What worked
- AUROC=0.914, AUPRC=0.964: scores separate
- median attack SPE >> benign (see score_hist_exp1.png)

## What failed
- f

## Leakage check
- scaler + PCA + threshold fit on benign-train only; labels used solely for scoring/slicing (EDR V-01) (train_benign n=5600)

## Reproduction
- Notebook: `notebooks/03_pca_baseline.ipynb`
