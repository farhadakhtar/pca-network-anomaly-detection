"""Matplotlib figures for every experiment (results/figures/)."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                             roc_auc_score, roc_curve)


def _save(fig: plt.Figure, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)
    return path


def plot_score_hist(benign: np.ndarray, attack: np.ndarray, threshold: float,
                    path: str | Path, title: str = "Anomaly-score distribution") -> Path:
    fig, ax = plt.subplots(figsize=(7, 4))
    bins = np.quantile(np.concatenate([benign, attack]), np.linspace(0, 1, 60))
    ax.hist(benign, bins=bins, alpha=0.6, label="benign", color="steelblue")
    ax.hist(attack, bins=bins, alpha=0.6, label="attack", color="firebrick")
    ax.axvline(threshold, color="k", ls="--", label=f"T={threshold:.1f}")
    ax.set_xscale("log")
    ax.set_xlabel("SPE score (log scale)")
    ax.set_ylabel("flows")
    ax.set_title(title)
    ax.legend()
    return _save(fig, path)


def plot_roc_pr(y_true: np.ndarray, scores: np.ndarray,
                prefix: str | Path) -> tuple[Path, Path]:
    prefix = Path(prefix)
    fpr, tpr, _ = roc_curve(y_true, scores)
    prec, rec, _ = precision_recall_curve(y_true, scores)
    auroc = roc_auc_score(y_true, scores)
    auprc = average_precision_score(y_true, scores)
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(fpr, tpr, label=f"AUROC={auroc:.3f}")
    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_xlabel("FPR")
    ax.set_ylabel("TPR")
    ax.set_title("ROC")
    ax.legend()
    p1 = _save(fig, prefix.parent / (prefix.name + "_roc.png"))
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(rec, prec, label=f"AUPRC={auprc:.3f}", color="darkorange")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall")
    ax.legend()
    p2 = _save(fig, prefix.parent / (prefix.name + "_pr.png"))
    return p1, p2


def plot_variance_elbow(var_table: pd.DataFrame, k: int, path: str | Path) -> Path:
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(var_table["component"], var_table["cumulative"], marker="o", ms=3)
    ax.axvline(k, color="k", ls="--", label=f"k={k}")
    ax.set_xlabel("components")
    ax.set_ylabel("cumulative variance")
    ax.set_title("PCA variance elbow")
    ax.legend()
    return _save(fig, path)


def plot_shift_overlay(train_benign: np.ndarray, shift_benign: np.ndarray,
                       attack: np.ndarray, threshold: float,
                       path: str | Path) -> Path:
    fig, ax = plt.subplots(figsize=(7, 4))
    bins = np.quantile(np.concatenate([train_benign, shift_benign, attack]),
                       np.linspace(0, 1, 60))
    ax.hist(train_benign, bins=bins, alpha=0.5, label="train benign", color="steelblue")
    ax.hist(shift_benign, bins=bins, alpha=0.5, label="shift benign", color="goldenrod")
    ax.hist(attack, bins=bins, alpha=0.5, label="attack", color="firebrick")
    ax.axvline(threshold, color="k", ls="--", label=f"T={threshold:.1f}")
    ax.set_xscale("log")
    ax.set_xlabel("SPE score (log scale)")
    ax.set_ylabel("flows")
    ax.set_title("Distribution shift: scores vs frozen threshold")
    ax.legend()
    return _save(fig, path)


def plot_recall_bars(per_attack: pd.DataFrame, path: str | Path,
                     col: str = "detection_rate", title: str = "Recall by attack") -> Path:
    fig, ax = plt.subplots(figsize=(6, 4))
    d = per_attack.sort_values(col, ascending=True)
    ax.barh(d["attack"] if "attack" in d else d["model"], d[col], color="seagreen")
    ax.set_xlabel(col)
    ax.set_title(title)
    for i, v in enumerate(d[col]):
        ax.text(v, i, f" {v:.2f}", va="center")
    return _save(fig, path)


def plot_frontier(sweep: pd.DataFrame, path: str | Path) -> Path:
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.plot(sweep["fpr"], sweep["recall"], marker="o")
    for _, r in sweep.iterrows():
        ax.annotate(r["strategy"], (r["fpr"], r["recall"]), fontsize=8)
    ax.set_xlabel("FPR")
    ax.set_ylabel("Recall")
    ax.set_title("Threshold frontier (fit on benign-train only)")
    return _save(fig, path)


def plot_runtime_bars(comp: pd.DataFrame, path: str | Path) -> Path:
    fig, ax = plt.subplots(figsize=(6, 4))
    x = np.arange(len(comp))
    w = 0.35
    ax.bar(x - w / 2, comp["train_s"], w, label="train (s)")
    ax.bar(x + w / 2, comp["infer_s"], w, label="infer (s)")
    ax.set_xticks(x, comp["model"])
    ax.set_ylabel("seconds")
    ax.set_title("Cost vs quality (Exp5)")
    ax.legend()
    return _save(fig, path)
