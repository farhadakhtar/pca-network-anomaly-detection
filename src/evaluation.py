"""Metrics + per-slice tables + experiment summaries (ERD E12-E13, EDR §2.3/§8)."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score,
                             roc_auc_score)

from src import BENIGN_LABEL, CATEGORY_COL


def evaluate(y_true: np.ndarray, scores: np.ndarray,
             y_pred: np.ndarray) -> dict:
    """All six README metrics; AUROC/AUPRC are NaN when single-class."""
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    try:
        auroc = float(roc_auc_score(y_true, scores))
    except ValueError:
        auroc = float("nan")
    try:
        auprc = float(average_precision_score(y_true, scores))
    except ValueError:
        auprc = float("nan")
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fp / max(fp + tn, 1)),
        "auroc": auroc, "auprc": auprc,
        "support_benign": int((y_true == 0).sum()),
        "support_attack": int((y_true == 1).sum()),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def evaluate_per_attack(scores_df: pd.DataFrame) -> pd.DataFrame:
    """One row per attack category, each scored against the shared benign set.

    Expects columns: y_true, score, y_pred, AttackCategory.
    """
    ben = scores_df[scores_df[CATEGORY_COL] == BENIGN_LABEL]
    rows = []
    for cat, sub in scores_df[scores_df[CATEGORY_COL] != BENIGN_LABEL].groupby(CATEGORY_COL):
        both = pd.concat([ben, sub], ignore_index=True)
        m = evaluate(both["y_true"].to_numpy(), both["score"].to_numpy(),
                     both["y_pred"].to_numpy())
        rows.append({"attack": cat, "mean_spe": float(sub["score"].mean()),
                     "median_spe": float(sub["score"].median()),
                     "detection_rate": m["recall"], "auroc": m["auroc"],
                     "auprc": m["auprc"], "support": len(sub), **m})
    return pd.DataFrame(rows).sort_values("detection_rate", ascending=False)


def save_metrics_csv(path: str | Path, rows: list[dict] | pd.DataFrame) -> Path:
    path = Path(path)
    df = rows if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
    df.to_csv(path, index=False)
    return path


def write_experiment_summary(path: str | Path, *, exp_id: str, title: str,
                             train_desc: str, test_desc: str, model_desc: str,
                             threshold_desc: str, metrics: pd.DataFrame,
                             figures: list[str], worked: list[str],
                             failed: list[str], leakage_note: str,
                             notebook: str) -> Path:
    """Fill the EDR §8 per-experiment report template."""
    path = Path(path)
    lines = [f"# {exp_id} — {title}", f"- Train: {train_desc} | Test: {test_desc}",
             f"- Model: {model_desc} | Threshold: {threshold_desc}",
             "", "## Metrics", "", metrics.to_markdown(index=False), "",
             "## Figures"] + [f"- `{f}`" for f in figures] + [
             "", "## What worked"] + [f"- {w}" for w in worked] + [
             "", "## What failed"] + [f"- f" for f in failed] + [
             "", f"## Leakage check", f"- {leakage_note}",
             "", f"## Reproduction", f"- Notebook: `{notebook}`", ""]
    path.write_text("\n".join(lines))
    return path
