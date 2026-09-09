# Exp3 — Unseen-attack (leave-one-out) framing
- Train: frozen Exp1 PCA (benign-train only) | Test: per-category holdout reporting
- Model: frozen PCA | Threshold: frozen P99

## Metrics

| held_out_attack   |   recall_at_P99 |   auroc |
|:------------------|----------------:|--------:|
| Botnet            |          1      |  1      |
| DDoS              |          0.9987 |  0.9993 |
| PortScan          |          0.5727 |  0.9845 |
| BruteForce        |          0.0373 |  0.7912 |

## Figures
- `recall_by_attack.png`

## What worked
- worst-case held-out recall=0.04 bounds the open-world claim

## What failed
- f

## Leakage check
- PCA uses no labels at any stage (EDR V-01)

## Reproduction
- Notebook: `notebooks/04_unseen_attack_evaluation.ipynb`
