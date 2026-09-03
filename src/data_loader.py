"""Dataset ingestion and split utilities for flow-based intrusion datasets."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import pandas as pd
from sklearn.model_selection import train_test_split

from .config import resolve_path
from .synthetic import generate_synthetic_flows

LABEL_CANDIDATES = ["Label", "label", "Attack", "attack", "attack_cat", "Class", "class"]
DEFAULT_BENIGN_LABELS = {"benign", "normal", "0"}


@dataclass
class LoadedDataset:
    frame: pd.DataFrame
    label_column: str
    benign_label: str
    metadata: dict[str, Any]

    @property
    def labels(self) -> pd.Series:
        return self.frame[self.label_column]

    def is_benign(self) -> pd.Series:
        return self.labels.astype(str).str.lower() == str(self.benign_label).lower()

    def stats(self) -> dict[str, Any]:
        counts = self.labels.astype(str).value_counts().to_dict()
        return {"rows": int(len(self.frame)), "columns": int(len(self.frame.columns)), "label_counts": counts}


def infer_label_column(df: pd.DataFrame, configured: str | None = None) -> str:
    if configured:
        if configured not in df.columns:
            raise ValueError(f"Dataset is missing configured label column '{configured}'. Available columns: {list(df.columns)[:20]}")
        return configured
    for c in LABEL_CANDIDATES:
        if c in df.columns:
            return c
    raise ValueError(f"Could not infer label column. Configure dataset.label_column. Candidate names tried: {LABEL_CANDIDATES}")


def infer_benign_label(labels: pd.Series, configured: str | None = None) -> str:
    if configured is not None:
        return configured
    lowered = labels.astype(str).str.lower()
    for val in labels.astype(str).unique():
        if val.lower() in DEFAULT_BENIGN_LABELS:
            return val
    raise ValueError("Could not infer benign label. Configure dataset.benign_label (for example 'BENIGN' or 'Normal').")


def load_dataset(dataset_config: dict[str, Any], seed: int = 42) -> LoadedDataset:
    """Load a configured CSV dataset or deterministic synthetic smoke dataset."""
    if dataset_config.get("synthetic", False):
        df = generate_synthetic_flows(
            n_benign=int(dataset_config.get("n_benign", 1000)),
            n_attack_per_type=int(dataset_config.get("n_attack_per_type", 150)),
            n_shift=int(dataset_config.get("n_shift", 250)),
            seed=seed,
        )
        label_col = "Label"
        benign = "BENIGN"
        return LoadedDataset(df, label_col, benign, {"source": "synthetic", "warning": "Synthetic smoke data only."})

    path = resolve_path(dataset_config.get("path"))
    if path is None or not path.exists():
        raise FileNotFoundError(f"Dataset path not found: {dataset_config.get('path')}. Place CSVs in data/raw or update config.")
    if path.is_dir():
        frames = [pd.read_csv(p) for p in sorted(path.glob("*.csv"))]
        if not frames:
            raise FileNotFoundError(f"No CSV files found in dataset directory: {path}")
        df = pd.concat(frames, ignore_index=True)
    else:
        df = pd.read_csv(path)
    label_col = infer_label_column(df, dataset_config.get("label_column"))
    benign = infer_benign_label(df[label_col], dataset_config.get("benign_label"))
    return LoadedDataset(df, label_col, benign, {"source": str(path)})


@dataclass
class DataSplits:
    train_benign: pd.DataFrame
    calibration_benign: pd.DataFrame
    test_benign: pd.DataFrame
    test_attack: pd.DataFrame
    shifted_benign: pd.DataFrame
    metadata: dict[str, Any]


def make_splits(dataset: LoadedDataset, split_config: Any, seed: int) -> DataSplits:
    """Create leakage-safe benign train/calibration/test and attack partitions."""
    df = dataset.frame.copy()
    benign_mask = dataset.is_benign()
    shifted_mask = df[dataset.label_column].astype(str).str.lower().str.contains("shift")
    benign = df[benign_mask].copy()
    shifted = df[shifted_mask].copy()
    attacks = df[(~benign_mask) & (~shifted_mask)].copy()
    if benign.empty:
        raise ValueError(f"No benign rows found for benign_label='{dataset.benign_label}'.")
    if len(benign) < 5:
        raise ValueError("Need at least 5 benign rows to create train/calibration/test splits.")

    shuffle = bool(getattr(split_config, "shuffle", True))
    train_size = float(getattr(split_config, "train_size", 0.6))
    cal_size = float(getattr(split_config, "calibration_size", 0.2))
    if shuffle:
        train, rest = train_test_split(benign, train_size=train_size, random_state=seed, shuffle=True)
        rel_cal = cal_size / max(1e-12, (1.0 - train_size))
        cal, test = train_test_split(rest, train_size=rel_cal, random_state=seed, shuffle=True)
    else:
        benign = benign.sort_values(getattr(split_config, "temporal_column", None)) if getattr(split_config, "temporal_column", None) in benign.columns else benign
        n = len(benign); n_train = int(n * train_size); n_cal = int(n * cal_size)
        train, cal, test = benign.iloc[:n_train], benign.iloc[n_train:n_train+n_cal], benign.iloc[n_train+n_cal:]
    meta = {"train_benign": len(train), "calibration_benign": len(cal), "test_benign": len(test), "test_attack": len(attacks), "shifted_benign": len(shifted), "shuffle": shuffle}
    return DataSplits(train.reset_index(drop=True), cal.reset_index(drop=True), test.reset_index(drop=True), attacks.reset_index(drop=True), shifted.reset_index(drop=True), meta)
