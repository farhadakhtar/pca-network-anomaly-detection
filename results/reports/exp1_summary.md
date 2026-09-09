# Exp1 — Basic anomaly detection
- Train: synthetic_A benign-train (n=5600) | Test: benign-test + mixed attacks (n=8400)
- Model: PCA k=19, variance=0.954 | Threshold: P99 = 23.90

## Metrics

|   k | strategy   |   threshold |   precision |   recall |     f1 |    fpr |   auroc |   auprc |   support_benign |   support_attack |   tn |   fp |   fn |   tp |
|----:|:-----------|------------:|------------:|---------:|-------:|-------:|--------:|--------:|-----------------:|-----------------:|-----:|-----:|-----:|-----:|
|  19 | p95        |      5.0619 |      0.9727 |   0.8077 | 0.8825 | 0.0567 |  0.9437 |  0.9781 |             2400 |             6000 | 2264 |  136 | 1154 | 4846 |
|  19 | p99        |     23.9011 |      0.9914 |   0.6522 | 0.7868 | 0.0142 |  0.9437 |  0.9781 |             2400 |             6000 | 2366 |   34 | 2087 | 3913 |
|  19 | p99.5      |     42.5282 |      0.9962 |   0.5672 | 0.7228 | 0.0054 |  0.9437 |  0.9781 |             2400 |             6000 | 2387 |   13 | 2597 | 3403 |
|  19 | mean+2std  |     25.6552 |      0.9921 |   0.6492 | 0.7848 | 0.0129 |  0.9437 |  0.9781 |             2400 |             6000 | 2369 |   31 | 2105 | 3895 |
|  19 | mean+3std  |     37.5643 |      0.9957 |   0.6173 | 0.7621 | 0.0067 |  0.9437 |  0.9781 |             2400 |             6000 | 2384 |   16 | 2296 | 3704 |
|  19 | mad        |      1.661  |      0.9295 |   0.8838 | 0.9061 | 0.1675 |  0.9437 |  0.9781 |             2400 |             6000 | 1998 |  402 |  697 | 5303 |

## Figures
- `score_hist_exp1.png`
- `exp1_roc.png`
- `exp1_pr.png`
- `threshold_frontier_exp1.png`

## What worked
- AUROC=0.944, AUPRC=0.978

## What failed
- f

## Leakage check
- scaler + PCA + threshold fit on benign-train only (EDR V-01)

## Reproduction
- Notebook: `notebooks/03_pca_baseline.ipynb`
