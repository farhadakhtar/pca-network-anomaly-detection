# Exp2 — Per-attack evaluation
- Train: frozen Exp1 PCA (benign-train only) | Test: benign-test vs each attack separately
- Model: frozen PCA | Threshold: frozen P99

## Metrics

| attack     |   mean_spe |   median_spe |   detection_rate |   auroc |   auprc |   support |   precision |   recall |     f1 |    fpr |   support_benign |   support_attack |   tn |   fp |   fn |   tp |
|:-----------|-----------:|-------------:|-----------------:|--------:|--------:|----------:|------------:|---------:|-------:|-------:|-----------------:|-----------------:|-----:|-----:|-----:|-----:|
| Botnet     |  2853.56   |    2867.94   |           1      |  1      |  0.9999 |      1500 |      0.9778 |   1      | 0.9888 | 0.0142 |             2400 |             1500 | 2366 |   34 |    0 | 1500 |
| DDoS       |  9516.49   |    1200.73   |           0.9987 |  0.9993 |  0.9987 |      1500 |      0.9778 |   0.9987 | 0.9881 | 0.0142 |             2400 |             1500 | 2366 |   34 |    2 | 1498 |
| PortScan   |    31.8249 |      35.5205 |           0.5727 |  0.9845 |  0.9476 |      1500 |      0.9619 |   0.5727 | 0.7179 | 0.0142 |             2400 |             1500 | 2366 |   34 |  641 |  859 |
| BruteForce |     6.5221 |       1.9071 |           0.0373 |  0.7912 |  0.646  |      1500 |      0.6222 |   0.0373 | 0.0704 | 0.0142 |             2400 |             1500 | 2366 |   34 | 1444 |   56 |

## Figures
- `recall_by_attack.png`

## What worked
- easiest: Botnet (recall=1.00)

## What failed
- f

## Leakage check
- no refit on any attack slice (EDR V-01)

## Reproduction
- Notebook: `notebooks/04_unseen_attack_evaluation.ipynb`
