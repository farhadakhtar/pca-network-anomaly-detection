# Exp2 — Per-attack evaluation
- Train: frozen Exp1 PCA (benign-train only) | Test: benign-test vs each attack separately
- Model: frozen PCA | Threshold: frozen P99

## Metrics

| attack     |   mean_spe |   median_spe |   detection_rate |   auroc |   auprc |   support |   precision |   recall |     f1 |    fpr |   support_benign |   support_attack |   tn |   fp |   fn |   tp |
|:-----------|-----------:|-------------:|-----------------:|--------:|--------:|----------:|------------:|---------:|-------:|-------:|-----------------:|-----------------:|-----:|-----:|-----:|-----:|
| Botnet     |  2771.81   |    2788.02   |           1      |  1      |  0.9999 |      1500 |      0.9753 |   1      | 0.9875 | 0.0158 |             2400 |             1500 | 2362 |   38 |    0 | 1500 |
| DDoS       | 10428.3    |    1369.29   |           0.9987 |  0.9994 |  0.9989 |      1500 |      0.9753 |   0.9987 | 0.9868 | 0.0158 |             2400 |             1500 | 2362 |   38 |    2 | 1498 |
| PortScan   |     7.8396 |       2.9637 |           0.058  |  0.8568 |  0.7255 |      1500 |      0.696  |   0.058  | 0.1071 | 0.0158 |             2400 |             1500 | 2362 |   38 | 1413 |   87 |
| BruteForce |     6.3131 |       2.0122 |           0.044  |  0.7994 |  0.6562 |      1500 |      0.6346 |   0.044  | 0.0823 | 0.0158 |             2400 |             1500 | 2362 |   38 | 1434 |   66 |

## Figures
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\recall_by_attack.png`

## What worked
- median recall=0.53 across categories
- easiest: Botnet (recall=1.00)
- hardest: BruteForce (recall=0.04)

## What failed
- f

## Leakage check
- scaler + PCA + threshold fit on benign-train only; labels used solely for scoring/slicing (EDR V-01)

## Reproduction
- Notebook: `notebooks/04_unseen_attack_evaluation.ipynb`
