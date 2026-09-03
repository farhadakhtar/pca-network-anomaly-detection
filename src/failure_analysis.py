"""Failure analysis helpers for PCA anomaly experiments."""
from __future__ import annotations

import numpy as np
import pandas as pd


def threshold_sensitivity(scores: np.ndarray, y_true: np.ndarray, percentiles: list[float]) -> pd.DataFrame:
    from .evaluation import binary_metrics
    rows = []
    benign_scores = scores[y_true == 0]
    for p in percentiles:
        t = float(np.percentile(benign_scores, p))
        pred = (scores > t).astype(int)
        m = binary_metrics(y_true, pred, scores).as_dict()
        rows.append({"percentile": p, "threshold": t, **m})
    return pd.DataFrame(rows)


def top_false_positives(frame: pd.DataFrame, scores: np.ndarray, y_true: np.ndarray, y_pred: np.ndarray, n: int = 20) -> pd.DataFrame:
    fp_idx = np.where((y_true == 0) & (y_pred == 1))[0]
    order = fp_idx[np.argsort(scores[fp_idx])[::-1]][:n]
    out = frame.iloc[order].copy()
    out["anomaly_score"] = scores[order]
    return out


def top_false_negatives(frame: pd.DataFrame, scores: np.ndarray, y_true: np.ndarray, y_pred: np.ndarray, n: int = 20) -> pd.DataFrame:
    fn_idx = np.where((y_true == 1) & (y_pred == 0))[0]
    order = fn_idx[np.argsort(scores[fn_idx])][:n]
    out = frame.iloc[order].copy()
    out["anomaly_score"] = scores[order]
    return out
