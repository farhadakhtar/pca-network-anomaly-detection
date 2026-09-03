# PCA-Based Network Anomaly Detection

Research implementation for the question:

> Can a low-dimensional representation of benign network behavior detect previously unseen attacks while remaining robust to benign distribution shifts?

This repository implements a defensive, unsupervised/one-class network anomaly detection pipeline. PCA is trained on benign flow records only; anomaly scores are reconstruction errors; labels are used for evaluation and experiment construction, not for fitting PCA.

## Implemented architecture

```text
configs/                 Reproducible experiment configs
data/raw/README.md       Dataset placement and semantics
data/processed/          Optional processed data outputs
src/                     Reusable implementation modules
tests/                   Unit and integration tests
results/                 Generated run artifacts (not committed)
```

Core modules:

- `src.data_loader`: CSV/synthetic loading, label inference, benign/attack splitting.
- `src.synthetic`: deterministic flow-like smoke dataset with benign, attacks, and shifted benign traffic.
- `src.feature_selection`: numeric feature validation, constant/NaN/inf/leakage/correlation filtering.
- `src.preprocessing`: leakage-safe imputation and `StandardScaler` fitted on benign training only.
- `src.pca_detector`: PCA transform, inverse transform, reconstruction error scoring (`mse` or `spe`).
- `src.thresholding`: percentile, mean+std, and robust thresholds fitted on benign calibration scores.
- `src.evaluation`: confusion matrix, precision, recall, F1, FPR, AUROC, AUPRC, per-attack summaries.
- `src.visualization`: explained variance, score histograms, confusion matrix, ROC/PR, per-attack plots.
- `src.baseline_models`: Isolation Forest, One-Class SVM, and small sklearn MLP autoencoder baselines.
- `src.experiments`: one-command experiment runner.

## Dataset requirements

Use public flow-based intrusion datasets such as CICIDS-family datasets, UNSW-NB15, or compatible CSV flow datasets. Configure:

```yaml
dataset:
  synthetic: false
  path: data/raw/your_dataset.csv
  label_column: Label
  benign_label: BENIGN
```

Raw datasets are not committed. See `data/raw/README.md`.

If no real dataset is present, use `configs/synthetic_baseline.yaml`. Synthetic runs are **only smoke tests / CI evidence**, not real cybersecurity findings.

## Installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Running experiments

Synthetic smoke baseline plus model comparison:

```bash
python -m src.experiments --config configs/synthetic_baseline.yaml
```

Example real dataset config:

```bash
cp configs/example_real_dataset.yaml configs/my_dataset.yaml
# edit path/label/benign/features as needed
python -m src.experiments --config configs/my_dataset.yaml
```

The runner performs:

```text
load data -> split benign train/calibration/test and attack test -> fit preprocessing on benign train -> train PCA -> calibrate threshold on benign calibration -> evaluate -> save metrics/tables/figures/report
```

Outputs are written under `results/runs/<timestamp>_<experiment>/`:

- `metrics.json`
- `tables/metrics.csv`
- `tables/predictions.csv`
- `tables/per_attack_summary.csv`
- `tables/threshold_sensitivity.csv`
- `tables/baseline_comparison.csv`
- `figures/*.png`
- `reports/report.md`

## PCA methodology

For standardized feature vector `x`, PCA projects to `z ∈ R^k`, reconstructs `x_hat`, and scores:

- `mse`: mean squared reconstruction error (default)
- `spe`: squared prediction error sum

`n_components` supports integer component counts or explained variance targets (`0.90`, `0.95`, `0.99`).

## Threshold methodology

Thresholds are separate experiment parameters and are fit on benign calibration scores, not test scores:

- `percentile` (e.g., 99th percentile)
- `mean_std` (`mean + k*std`)
- `robust` (`median + k*1.4826*MAD`)

Decision rule: `score > threshold` means anomaly.

## Leakage prevention

- PCA is fit only on benign training rows.
- Scaler/imputer are fit only on benign training rows.
- Threshold is fit only on benign calibration scores.
- Attack labels are excluded from PCA training.
- Feature filtering is unsupervised and excludes likely label/attack/ID/time leakage columns by name.
- Temporal experiments can disable shuffling via config; metadata is not fabricated.

## Experiments implemented

Implemented framework support:

- PCA baseline: benign test + attack test.
- Per-attack / unseen attack evaluation: per-label score and detection summaries.
- Distribution shift smoke path: shifted benign false-positive evaluation when genuine shifted-benign rows exist.
- Baseline comparison: PCA, Isolation Forest, One-Class SVM, sklearn MLP autoencoder.
- Failure-analysis artifacts: threshold sensitivity, false-positive/false-negative helper utilities.

Not yet executed on a real dataset in this repository because no real raw dataset is committed.

## Running tests

```bash
pytest
```

Tests cover data loading, missing labels/files, preprocessing, PCA reconstruction/scoring, thresholding, metrics, leakage invariants, and synthetic end-to-end execution.

## Limitations

- Real CICIDS/UNSW results are not included until a real dataset is supplied and experiments are run.
- Distribution-shift experiments require real temporal/environment/cross-dataset metadata; the code will not fabricate it.
- The autoencoder baseline is intentionally lightweight (`sklearn.neural_network.MLPRegressor`) to avoid heavy deep-learning dependencies.
- Adaptive thresholding and online drift adaptation are extension points, not claimed research improvements.

## Research roadmap

1. Run PCA baseline on a real dataset.
2. Inspect per-attack failures and threshold sensitivity.
3. Run legitimate temporal/environment/cross-dataset shift experiments where supported.
4. Compare against Isolation Forest, One-Class SVM, and autoencoder under identical splits.
5. Form an evidence-driven hypothesis about the dominant PCA failure mode.
6. Implement the smallest justified improvement and compare it against the PCA baseline.

## Security scope

This is defensive anomaly detection research. It does not implement exploitation, unauthorized scanning, credential theft, malware, persistence, or evasion tooling.

## License

MIT recommended; see `LICENSE`.
