"""Reusable evaluation metrics for anomaly detection."""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score


@dataclass
class Metrics:
    samples: int
    tn: int
    fp: int
    fn: int
    tp: int
    precision: float | None
    recall: float | None
    f1: float | None
    fpr: float | None
    detection_rate: float | None
    false_negative_rate: float | None
    auroc: float | None
    auprc: float | None

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None = None) -> Metrics:
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    labels = [0, 1]
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=labels).ravel()
    precision = precision_score(y_true, y_pred, zero_division=0) if y_true.size else None
    recall = recall_score(y_true, y_pred, zero_division=0) if y_true.size else None
    f1 = f1_score(y_true, y_pred, zero_division=0) if y_true.size else None
    fpr = float(fp / (fp + tn)) if (fp + tn) else None
    fnr = float(fn / (fn + tp)) if (fn + tp) else None
    auroc = auprc = None
    if scores is not None and len(np.unique(y_true)) == 2:
        auroc = float(roc_auc_score(y_true, scores))
        auprc = float(average_precision_score(y_true, scores))
    return Metrics(int(y_true.size), int(tn), int(fp), int(fn), int(tp), float(precision), float(recall), float(f1), fpr, float(recall) if recall is not None else None, fnr, auroc, auprc)


def labels_to_binary(labels: pd.Series, benign_label: str) -> np.ndarray:
    return (labels.astype(str).str.lower() != str(benign_label).lower()).astype(int).to_numpy()


def per_attack_summary(labels: pd.Series, y_pred: np.ndarray, scores: np.ndarray, benign_label: str) -> pd.DataFrame:
    rows = []
    label_values = labels.astype(str).to_numpy()
    for label in sorted(set(label_values)):
        mask = label_values == label
        is_benign = label.lower() == str(benign_label).lower()
        rows.append({
            "traffic_type": label,
            "is_benign": is_benign,
            "samples": int(mask.sum()),
            "mean_score": float(np.mean(scores[mask])) if mask.any() else None,
            "median_score": float(np.median(scores[mask])) if mask.any() else None,
            "detection_rate": float(np.mean(y_pred[mask])) if mask.any() else None,
            "false_negative_rate": float(1.0 - np.mean(y_pred[mask])) if (mask.any() and not is_benign) else None,
            "false_positive_rate": float(np.mean(y_pred[mask])) if (mask.any() and is_benign) else None,
        })
    return pd.DataFrame(rows)
