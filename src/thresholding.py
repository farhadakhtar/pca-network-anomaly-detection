"""Anomaly threshold selection strategies."""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np


@dataclass
class ThresholdResult:
    method: str
    threshold: float
    params: dict[str, float]
    calibration_count: int

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


def fit_threshold(scores: np.ndarray, method: str = "percentile", **params: float) -> ThresholdResult:
    scores = np.asarray(scores, dtype=float)
    scores = scores[np.isfinite(scores)]
    if scores.size == 0:
        raise ValueError("Cannot fit threshold: no finite calibration scores.")
    method = method.lower()
    if method == "percentile":
        p = float(params.get("percentile", 99.0))
        if not 0 < p < 100:
            raise ValueError("Percentile threshold requires 0 < percentile < 100.")
        value = float(np.percentile(scores, p))
        used = {"percentile": p}
    elif method in {"mean_std", "mean+std"}:
        k = float(params.get("k", 3.0))
        value = float(np.mean(scores) + k * np.std(scores, ddof=1 if scores.size > 1 else 0))
        used = {"k": k}
    elif method == "robust":
        k = float(params.get("k", 3.5))
        median = float(np.median(scores))
        mad = float(np.median(np.abs(scores - median)))
        value = median + k * 1.4826 * mad
        used = {"k": k, "median": median, "mad": mad}
    else:
        raise ValueError(f"Unknown threshold method '{method}'. Use percentile, mean_std, or robust.")
    return ThresholdResult(method=method, threshold=value, params=used, calibration_count=int(scores.size))


def predict_from_scores(scores: np.ndarray, threshold: float) -> np.ndarray:
    """Return 1 for anomaly when score > threshold, else 0."""
    return (np.asarray(scores) > threshold).astype(int)
