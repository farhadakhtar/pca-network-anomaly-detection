# Exp3 — Unseen-attack (leave-one-out) framing
- Train: frozen Exp1 PCA (benign-train only) | Test: benign-test vs each attack separately
- Model: frozen PCA | Threshold: frozen P99

## Metrics

| held_out_attack   |   recall_at_P99 |   auroc |
|:------------------|----------------:|--------:|
| Botnet            |          1      |  1      |
| DDoS              |          0.9987 |  0.9994 |
| PortScan          |          0.058  |  0.8568 |
| BruteForce        |          0.044  |  0.7994 |

## Figures
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\recall_by_attack.png`

## What worked
- median recall=0.53 across categories
- worst-case held-out recall=0.04 bounds the open-world claim

## What failed
- f

## Leakage check
- scaler + PCA + threshold fit on benign-train only; labels used solely for scoring/slicing (EDR V-01)

## Reproduction
- Notebook: `notebooks/04_unseen_attack_evaluation.ipynb`
