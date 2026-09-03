# Notebooks

Notebooks are reserved for exploratory analysis and research interpretation. Core implementation lives in `src/` and should be imported from notebooks rather than duplicated.

Suggested notebook sequence after real data is supplied:

1. `01_data_exploration.ipynb` — inspect schema, labels, missing/inf values, class imbalance.
2. `02_preprocessing.ipynb` — review selected/dropped features and preprocessing diagnostics.
3. `03_pca_baseline.ipynb` — inspect PCA variance and reconstruction score distributions.
4. `04_unseen_attack_evaluation.ipynb` — analyze per-attack failures.
5. `05_distribution_shift.ipynb` — study benign temporal/environment/cross-dataset shift.
6. `06_baseline_comparison.ipynb` — compare PCA against other one-class baselines.

Do not report notebook findings unless the underlying experiment artifacts exist in `results/runs/`.
