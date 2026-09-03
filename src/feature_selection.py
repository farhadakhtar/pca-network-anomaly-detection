"""Feature validation and unsupervised feature selection."""
from __future__ import annotations

from dataclasses import dataclass, field
import numpy as np
import pandas as pd

LEAKAGE_PATTERNS = ["label", "attack", "class", "target", "id", "source ip", "destination ip", "timestamp", "time"]


@dataclass
class FeatureSelectionReport:
    selected_features: list[str]
    missing_requested: list[str] = field(default_factory=list)
    dropped_constant: list[str] = field(default_factory=list)
    dropped_nan_heavy: list[str] = field(default_factory=list)
    dropped_infinite_heavy: list[str] = field(default_factory=list)
    dropped_potential_leakage: list[str] = field(default_factory=list)
    dropped_correlated: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return self.__dict__.copy()


def select_numeric_features(
    df: pd.DataFrame,
    label_column: str,
    requested_features: list[str] | None = None,
    max_missing_fraction: float = 0.5,
    correlation_threshold: float | None = 0.995,
) -> FeatureSelectionReport:
    """Select usable numeric features without using labels/test outcomes."""
    report = FeatureSelectionReport(selected_features=[])
    candidate = requested_features or [c for c in df.columns if c != label_column]
    report.missing_requested = [c for c in candidate if c not in df.columns]
    candidate = [c for c in candidate if c in df.columns and c != label_column]

    numeric = []
    for c in candidate:
        lower = c.lower()
        if any(p in lower for p in LEAKAGE_PATTERNS):
            report.dropped_potential_leakage.append(c); continue
        s = pd.to_numeric(df[c], errors="coerce")
        if not pd.api.types.is_numeric_dtype(s):
            continue
        nan_frac = float(s.isna().mean())
        inf_frac = float(np.isinf(s.dropna()).mean()) if s.notna().any() else 0.0
        if nan_frac > max_missing_fraction:
            report.dropped_nan_heavy.append(c); continue
        if inf_frac > max_missing_fraction:
            report.dropped_infinite_heavy.append(c); continue
        finite = s.replace([np.inf, -np.inf], np.nan).dropna()
        if finite.nunique() <= 1:
            report.dropped_constant.append(c); continue
        numeric.append(c)

    if correlation_threshold is not None and len(numeric) > 1:
        clean = df[numeric].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
        corr = clean.corr(numeric_only=True).abs()
        to_drop: set[str] = set()
        for i, c in enumerate(corr.columns):
            if c in to_drop:
                continue
            for other in corr.columns[i + 1:]:
                if corr.loc[c, other] >= correlation_threshold:
                    to_drop.add(other)
        report.dropped_correlated = sorted(to_drop)
        numeric = [c for c in numeric if c not in to_drop]

    report.selected_features = numeric
    if len(numeric) < 2:
        raise ValueError(f"Only {len(numeric)} valid numerical features remain after preprocessing selection. Need at least 2. Report: {report.as_dict()}")
    return report
