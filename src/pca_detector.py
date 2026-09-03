"""PCA reconstruction-based one-class anomaly detector."""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np
from sklearn.decomposition import PCA


@dataclass
class PCAMetadata:
    n_input_features: int
    n_components_selected: int
    explained_variance_ratio: list[float]
    cumulative_explained_variance: list[float]
    score_method: str

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


class PCAReconstructionDetector:
    """Learn benign low-dimensional structure and score reconstruction error."""

    def __init__(self, n_components: int | float = 0.95, score_method: str = "mse", random_state: int = 42, whiten: bool = False):
        self.n_components = n_components
        self.score_method = score_method
        self.random_state = random_state
        self.whiten = whiten
        self.pca: PCA | None = None
        self.fit_rows_: int = 0

    def fit(self, x_train: np.ndarray) -> "PCAReconstructionDetector":
        if x_train.ndim != 2 or x_train.shape[1] < 2:
            raise ValueError("PCA requires a 2D matrix with at least 2 features.")
        self.pca = PCA(n_components=self.n_components, whiten=self.whiten, random_state=self.random_state)
        self.pca.fit(x_train)
        self.fit_rows_ = int(x_train.shape[0])
        if self.pca.n_components_ >= x_train.shape[1]:
            # Reconstruction with all components hides anomalies; allow but warn in metadata consumers.
            pass
        return self

    def transform(self, x: np.ndarray) -> np.ndarray:
        self._check_fit()
        return self.pca.transform(x)  # type: ignore[union-attr]

    def reconstruct(self, x: np.ndarray) -> np.ndarray:
        z = self.transform(x)
        return self.pca.inverse_transform(z)  # type: ignore[union-attr]

    def score_samples(self, x: np.ndarray) -> np.ndarray:
        reconstructed = self.reconstruct(x)
        squared = (x - reconstructed) ** 2
        if self.score_method == "spe":
            return squared.sum(axis=1)
        if self.score_method == "mse":
            return squared.mean(axis=1)
        raise ValueError("score_method must be 'mse' or 'spe'.")

    def _check_fit(self) -> None:
        if self.pca is None:
            raise RuntimeError("PCA detector must be fitted before use.")

    def metadata(self) -> PCAMetadata:
        self._check_fit()
        ratio = self.pca.explained_variance_ratio_  # type: ignore[union-attr]
        return PCAMetadata(
            n_input_features=int(self.pca.n_features_in_),  # type: ignore[union-attr]
            n_components_selected=int(self.pca.n_components_),  # type: ignore[union-attr]
            explained_variance_ratio=[float(v) for v in ratio],
            cumulative_explained_variance=[float(v) for v in np.cumsum(ratio)],
            score_method=self.score_method,
        )
