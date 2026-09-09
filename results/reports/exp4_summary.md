# Exp4 — Distribution-shift robustness
- Train: frozen M40 (Exp1) + frozen M38-common | Test: drifted t1 benign; env-B benign + B attacks
- Model: frozen PCA, frozen P99 thresholds | Threshold: M40 P99=22.25; M38 P99=20.49

## Metrics

| shift                            | model      |   FPR_source |   FPR_target |   dFPR | recall_src   |   recall_tgt |   AUROC_tgt |   AUPRC_tgt |
|:---------------------------------|:-----------|-------------:|-------------:|-------:|:-------------|-------------:|------------:|------------:|
| temporal (t0->t1 drift)          | M40        |       0.0158 |       0.0183 | 0.0025 |              |       0.5252 |      0.9043 |      0.9606 |
| environment (A->B)               | M38-common |       0.0154 |       0.0203 | 0.0048 |              |       0.5337 |      0.8647 |      0.8719 |
| cross-dataset (A->B, aligned 38) | M38-common |       0.0154 |       0.0203 | 0.0048 |              |       0.5337 |      0.8647 |      0.8719 |

## Figures
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\shift_overlay_temporal.png`
- `D:\Study\Sem 5\AIML lab\pca-network-anomaly-detection-clone\results\figures\shift_overlay_env.png`

## What worked
- temporal dFPR=+0.003, env dFPR=+0.005
- attack recall retained at 0.53: geometry holds

## What failed
- f

## Leakage check
- scaler + PCA + threshold fit on benign-train only; labels used solely for scoring/slicing (EDR V-01); thresholds never fit on target (EDR V-02)

## Reproduction
- Notebook: `notebooks/05_distribution_shift.ipynb`
