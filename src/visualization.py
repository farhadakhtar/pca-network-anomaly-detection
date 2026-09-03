"""Research visualizations for anomaly detection experiments."""
from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import ConfusionMatrixDisplay, PrecisionRecallDisplay, RocCurveDisplay, confusion_matrix


def _path(path: str | Path) -> Path:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True); return p


def plot_explained_variance(cumulative: list[float], path: str | Path) -> None:
    plt.figure(figsize=(7, 4)); plt.plot(range(1, len(cumulative)+1), cumulative, marker="o")
    plt.xlabel("PCA components"); plt.ylabel("Cumulative explained variance"); plt.ylim(0, 1.02); plt.grid(True, alpha=0.3)
    plt.title("PCA cumulative explained variance"); plt.tight_layout(); plt.savefig(_path(path)); plt.close()


def plot_score_histogram(scores: np.ndarray, y_true: np.ndarray, threshold: float, path: str | Path) -> None:
    plt.figure(figsize=(7, 4))
    plt.hist(scores[y_true == 0], bins=40, alpha=0.65, label="Benign")
    if (y_true == 1).any(): plt.hist(scores[y_true == 1], bins=40, alpha=0.65, label="Attack/anomaly")
    plt.axvline(threshold, color="red", linestyle="--", label="Threshold")
    plt.xlabel("Reconstruction error score"); plt.ylabel("Samples"); plt.legend(); plt.title("Anomaly score distribution")
    plt.tight_layout(); plt.savefig(_path(path)); plt.close()


def plot_confusion(y_true: np.ndarray, y_pred: np.ndarray, path: str | Path) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    disp = ConfusionMatrixDisplay(cm, display_labels=["benign", "anomaly"])
    disp.plot(values_format="d"); plt.title("Confusion matrix"); plt.tight_layout(); plt.savefig(_path(path)); plt.close()


def plot_roc_pr(y_true: np.ndarray, scores: np.ndarray, roc_path: str | Path, pr_path: str | Path) -> None:
    if len(np.unique(y_true)) < 2:
        return
    RocCurveDisplay.from_predictions(y_true, scores); plt.title("ROC curve"); plt.tight_layout(); plt.savefig(_path(roc_path)); plt.close()
    PrecisionRecallDisplay.from_predictions(y_true, scores); plt.title("Precision-recall curve"); plt.tight_layout(); plt.savefig(_path(pr_path)); plt.close()


def plot_per_attack(summary: pd.DataFrame, path: str | Path) -> None:
    attacks = summary[~summary["is_benign"]]
    if attacks.empty: return
    plt.figure(figsize=(8, 4)); plt.bar(attacks["traffic_type"], attacks["detection_rate"])
    plt.ylabel("Detection rate"); plt.ylim(0, 1.0); plt.title("Per-attack detection comparison"); plt.xticks(rotation=30, ha="right")
    plt.tight_layout(); plt.savefig(_path(path)); plt.close()
