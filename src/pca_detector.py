"""One-class PCA detector: fit on benign, score by reconstruction error.

Math (README / ERD E6-E9)::

    x_s = (x - mu_s) / sigma_s            # Preprocessor (benign-train fit)
    z   = W_k^T (x_s - mu_pca)            # project,  z in R^k, k < n
    xh  = W_k z + mu_pca                  # reconstruct
    SPE = sum_i (x_s,i - xh_i)^2          # anomaly score (MSE = SPE / n)
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA

from src import SEED


class PCADetector:
    def __init__(self, n_components: int | None = None,
                 variance_threshold: float = 0.95,
                 random_state: int = SEED):
        self.n_components = n_components
        self.variance_threshold = variance_threshold
        self.random_state = random_state
        self.pca_: PCA | None = None
        self.k_: int = 0

    def fit(self, X: np.ndarray) -> "PCADetector":
        n = X.shape[1]
        if self.n_components is None:
            full = PCA(svd_solver="full", random_state=self.random_state).fit(X)
            cum = np.cumsum(full.explained_variance_ratio_)
            self.k_ = int(np.searchsorted(cum, self.variance_threshold) + 1)
            self.k_ = max(1, min(self.k_, n - 1))          # ERD C4: k < n
        else:
            self.k_ = min(int(self.n_components), n - 1)
        self.pca_ = PCA(n_components=self.k_, svd_solver="full",
                        random_state=self.random_state).fit(X)
        return self

    @property
    def variance_retained_(self) -> float:
        assert self.pca_ is not None
        return float(np.sum(self.pca_.explained_variance_ratio_))

    def reconstruct(self, X: np.ndarray) -> np.ndarray:
        assert self.pca_ is not None, "fit first"
        return self.pca_.inverse_transform(self.pca_.transform(X))

    def score(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Return (SPE, MSE) per row; larger = more anomalous."""
        resid = X - self.reconstruct(X)
        spe = np.einsum("ij,ij->i", resid, resid)
        return spe, spe / X.shape[1]

    def variance_table(self) -> pd.DataFrame:
        assert self.pca_ is not None
        evr = self.pca_.explained_variance_ratio_
        return pd.DataFrame({"component": np.arange(1, self.k_ + 1),
                             "explained_variance_ratio": evr,
                             "cumulative": np.cumsum(evr)})

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        with open(path, "wb") as fh:
            pickle.dump({"pca": self.pca_, "k": self.k_,
                         "variance_threshold": self.variance_threshold,
                         "seed": self.random_state}, fh)
        (path.parent / "pca_meta.json").write_text(json.dumps({
            "n_features": int(self.pca_.n_features_in_),
            "n_components_k": self.k_,
            "variance_retained": self.variance_retained_,
        }, indent=1))
        return path

    @classmethod
    def load(cls, path: str | Path) -> "PCADetector":
        with open(path, "rb") as fh:
            blob = pickle.load(fh)
        det = cls()
        det.pca_, det.k_ = blob["pca"], blob["k"]
        det.variance_threshold = blob["variance_threshold"]
        return det


if __name__ == "__main__":  # README Usage: python -m src.pca_detector
    from src.data_loader import generate_synthetic_dataset, FEATURE_NAMES
    from src.preprocessing import Preprocessor, split_one_class
    from src import CATEGORY_COL, BENIGN_LABEL
    df = generate_synthetic_dataset(n_benign=2000, n_per_attack=300)
    sp = split_one_class(df)
    pp = Preprocessor(FEATURE_NAMES).fit(sp["train_benign"])
    det = PCADetector().fit(pp.transform(sp["train_benign"]))
    spe_b, _ = det.score(pp.transform(sp["test_benign"]))
    spe_a, _ = det.score(pp.transform(sp["test_attack"]))
    print(f"k={det.k_} var={det.variance_retained_:.3f} "
          f"med_benign={np.median(spe_b):.1f} med_attack={np.median(spe_a):.1f}")
