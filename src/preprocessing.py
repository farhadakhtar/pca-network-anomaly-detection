"""Leakage-safe preprocessing pipeline for PCA anomaly detection."""
from __future__ import annotations

from dataclasses import dataclass
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from .feature_selection import FeatureSelectionReport, select_numeric_features


@dataclass
class PreprocessingReport:
    feature_report: dict[str, object]
    medians: dict[str, float]
    scaler_mean: dict[str, float]
    scaler_scale: dict[str, float]
    rows_seen_fit: int

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


class FlowPreprocessor:
    """Fit feature selection, imputation, and scaling on training data only."""

    def __init__(self, label_column: str, requested_features: list[str] | None = None, max_missing_fraction: float = 0.5, correlation_threshold: float | None = 0.995):
        self.label_column = label_column
        self.requested_features = requested_features
        self.max_missing_fraction = max_missing_fraction
        self.correlation_threshold = correlation_threshold
        self.feature_report: FeatureSelectionReport | None = None
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = StandardScaler()
        self.features_: list[str] = []
        self.fit_index_: list[int] = []

    def fit(self, df: pd.DataFrame) -> "FlowPreprocessor":
        self.fit_index_ = list(df.index)
        self.feature_report = select_numeric_features(df, self.label_column, self.requested_features, self.max_missing_fraction, self.correlation_threshold)
        self.features_ = self.feature_report.selected_features
        x = self._numeric_frame(df)
        imputed = self.imputer.fit_transform(x)
        self.scaler.fit(imputed)
        return self

    def _numeric_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        missing = [c for c in self.features_ if c not in df.columns]
        if missing:
            raise ValueError(f"Input data is missing features required by fitted preprocessor: {missing}")
        x = df[self.features_].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
        return x

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.features_:
            raise RuntimeError("Preprocessor must be fitted before transform().")
        x = self._numeric_frame(df)
        return self.scaler.transform(self.imputer.transform(x))

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.fit(df).transform(df)

    def report(self) -> PreprocessingReport:
        if self.feature_report is None:
            raise RuntimeError("Preprocessor has not been fitted.")
        medians = dict(zip(self.features_, [float(v) for v in self.imputer.statistics_]))
        means = dict(zip(self.features_, [float(v) for v in self.scaler.mean_]))
        scales = dict(zip(self.features_, [float(v) for v in self.scaler.scale_]))
        return PreprocessingReport(self.feature_report.as_dict(), medians, means, scales, len(self.fit_index_))
