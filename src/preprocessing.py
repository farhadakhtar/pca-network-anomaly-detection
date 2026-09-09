"""Cleaning, one-class splits, benign-only scaler fit (ERD E4/E5/E7, DRD A3/A4).

One-class discipline (ERD C1): the imputation medians AND the StandardScaler
are fit on ``train_benign`` only. Test/shift data is transform-only.
"""
from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from src import BENIGN_LABEL, CATEGORY_COL, SEED


def clean_frame(df: pd.DataFrame, features: list[str],
                max_nan_frac: float = 0.5) -> tuple[pd.DataFrame, dict]:
    """Coerce numeric, map ±Inf -> NaN, drop rows that are mostly NaN."""
    out = df.copy()
    out[features] = out[features].apply(pd.to_numeric, errors="coerce")
    out[features] = out[features].replace([np.inf, -np.inf], np.nan)
    before = len(out)
    bad = out[features].isna().mean(axis=1) > max_nan_frac
    out = out.loc[~bad].reset_index(drop=True)
    info = {"rows_before": before, "rows_dropped": int(bad.sum())}
    return out, info


def split_one_class(df: pd.DataFrame, test_size: float = 0.3,
                    seed: int = SEED) -> dict[str, pd.DataFrame]:
    """Benign pool -> train/test; every attack row -> held-out test (DRD D-14)."""
    benign = df[df[CATEGORY_COL] == BENIGN_LABEL].reset_index(drop=True)
    attack = df[df[CATEGORY_COL] != BENIGN_LABEL].reset_index(drop=True)
    tr, te = train_test_split(benign, test_size=test_size, random_state=seed)
    return {
        "train_benign": tr.reset_index(drop=True),
        "test_benign": te.reset_index(drop=True),
        "test_attack": attack,
    }


class Preprocessor:
    """Median imputation + StandardScaler, fit on benign-train only."""

    def __init__(self, features: list[str]):
        self.features = list(features)
        self.medians_: pd.Series | None = None
        self.scaler_: StandardScaler | None = None

    def fit(self, df_train_benign: pd.DataFrame) -> "Preprocessor":
        assert CATEGORY_COL not in self.features, "label leakage in feature list (ERD C3)"
        sub = df_train_benign[self.features].replace([np.inf, -np.inf], np.nan)
        self.medians_ = sub.median()
        self.scaler_ = StandardScaler().fit(sub.fillna(self.medians_))
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        assert self.medians_ is not None and self.scaler_ is not None, "fit first"
        sub = df[self.features].replace([np.inf, -np.inf], np.nan)
        X = sub.fillna(self.medians_).to_numpy(dtype=float)
        return self.scaler_.transform(X)

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        with open(path, "wb") as fh:
            pickle.dump({"features": self.features, "medians": self.medians_,
                         "scaler": self.scaler_, "seed": SEED}, fh)
        (path.parent / "feature_list.json").write_text(
            json.dumps(self.features, indent=1))
        return path

    @classmethod
    def load(cls, path: str | Path) -> "Preprocessor":
        with open(path, "rb") as fh:
            blob = pickle.load(fh)
        pp = cls(blob["features"])
        pp.medians_, pp.scaler_ = blob["medians"], blob["scaler"]
        return pp


def save_processed(path: str | Path, *, X_train: np.ndarray,
                   X_test_benign: np.ndarray, X_test_attack: np.ndarray,
                   y_test: np.ndarray, test_cats: np.ndarray,
                   meta: dict) -> Path:
    path = Path(path)
    np.savez_compressed(path, X_train=X_train, X_test_benign=X_test_benign,
                        X_test_attack=X_test_attack, y_test=y_test,
                        test_cats=test_cats)
    (path.parent / (path.stem + "_meta.json")).write_text(json.dumps(meta, indent=1))
    return path
