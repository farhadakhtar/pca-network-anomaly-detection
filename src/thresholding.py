"""Statistical thresholding on benign-train scores (ERD E10-E11, EDR §5)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np


@dataclass
class Threshold:
    strategy: str
    value: float
    params: dict
    fitted_on: str = "benign_train_scores"


def fit_threshold(scores: np.ndarray, strategy: str = "p99",
                  k: float = 3.0) -> Threshold:
    """Baseline T = P99(benign-train scores); sweeps in EDR §5."""
    s = np.asarray(scores, dtype=float)
    if strategy == "p95":
        v = float(np.percentile(s, 95))
    elif strategy == "p99":
        v = float(np.percentile(s, 99))
    elif strategy == "p99.5":
        v = float(np.percentile(s, 99.5))
    elif strategy == "mean+2std":
        v = float(s.mean() + 2 * s.std())
    elif strategy == "mean+3std":
        v = float(s.mean() + 3 * s.std())
    elif strategy == "mad":
        med = float(np.median(s))
        mad = float(np.median(np.abs(s - med)))
        v = med + k * 1.4826 * mad
    else:
        raise ValueError(f"unknown strategy {strategy!r}")
    return Threshold(strategy=strategy, value=v,
                     params={"k": k, "n_fit": len(s)})


def predict(scores: np.ndarray, thr: Threshold) -> np.ndarray:
    """Score(x) > T -> Anomaly (1) else Normal (0)."""
    return (np.asarray(scores, dtype=float) > thr.value).astype(int)


def save_thresholds(path: str | Path, thr_map: dict[str, Threshold]) -> Path:
    path = Path(path)
    path.write_text(json.dumps({k: asdict(v) for k, v in thr_map.items()}, indent=1))
    return path


def load_thresholds(path: str | Path) -> dict[str, Threshold]:
    blob = json.loads(Path(path).read_text())
    return {k: Threshold(**v) for k, v in blob.items()}
