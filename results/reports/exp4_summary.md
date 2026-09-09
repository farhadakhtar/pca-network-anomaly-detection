# Exp4 — Distribution-shift robustness
- Train: frozen M40 (Exp1) + frozen M38-common | Test: drifted t1 benign; env-B benign + B attacks
- Model: frozen PCA, frozen P99 thresholds | Threshold: M40 P99=23.90; M38 P99=22.76

## Metrics

| shift                            | model      |   FPR_source |   FPR_target |   dFPR |   recall_tgt |   AUROC_tgt |   AUPRC_tgt |
|:---------------------------------|:-----------|-------------:|-------------:|-------:|-------------:|------------:|------------:|
| temporal (t0->t1 drift)          | M40        |       0.0142 |       0.0304 | 0.0163 |       0.6522 |      0.9089 |      0.9653 |
| environment (A->B)               | M38-common |       0.0142 |       0.0835 | 0.0693 |       0.6525 |      0.8113 |      0.8493 |
| cross-dataset (A->B, aligned 38) | M38-common |       0.0142 |       0.0835 | 0.0693 |       0.6525 |      0.8113 |      0.8493 |

## Figures
- `shift_overlay_temporal.png`
- `shift_overlay_env.png`

## What worked
- attack recall retained while FPR inflates: geometry holds

## What failed
- f

## Leakage check
- thresholds never fit on target (EDR V-02)

## Reproduction
- Notebook: `notebooks/05_distribution_shift.ipynb`
