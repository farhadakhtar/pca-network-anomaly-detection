"""Feature selection + cross-dataset alignment (ERD E3, DRD D-05..D-09)."""
from __future__ import annotations

import pandas as pd

from src import CATEGORY_COL, FLOW_ID_COL, LABEL_COL

LEAKY_HINTS = ("label", "attack", "category", "flow_id", "dataset_id", "ip_", "_ip", "src_", "dst_")


def select_features(df: pd.DataFrame,
                    exclude: tuple[str, ...] = (LABEL_COL, CATEGORY_COL, FLOW_ID_COL, "dataset_id"),
                    missing_thresh: float = 0.20,
                    inf_thresh: float = 0.20) -> tuple[list[str], pd.DataFrame]:
    """Apply keep/drop rules; every column gets a logged reason (DRD D-06).

    Returns (ordered kept feature list, per-column report frame).
    """
    rows = []
    kept: list[str] = []
    for col in df.columns:
        s = df[col]
        rec = {"feature": col, "dtype": str(s.dtype)}
        if col in exclude or any(h in col.lower() for h in LEAKY_HINTS):
            rec.update(action="drop", reason="excluded/leaky identifier")
        elif not pd.api.types.is_numeric_dtype(s):
            rec.update(action="drop", reason="non-numeric (v1)")
        else:
            num = pd.to_numeric(s, errors="coerce")
            miss = float(num.isna().mean())
            inf = float(np.isinf(num.to_numpy(dtype=float, na_value=np.nan)).mean())
            rec.update(missing_rate=round(miss, 4), inf_rate=round(inf, 4),
                       nunique=int(s.nunique(dropna=True)))
            if s.nunique(dropna=True) <= 1:
                rec.update(action="drop", reason="constant/zero-variance")
            elif miss > missing_thresh:
                rec.update(action="drop", reason=f"missing {miss:.1%} > {missing_thresh:.0%}")
            elif inf > inf_thresh:
                rec.update(action="drop", reason=f"inf {inf:.1%} > {inf_thresh:.0%}")
            else:
                rec.update(action="keep", reason="ok")
                kept.append(col)
        rows.append(rec)
    report = pd.DataFrame(rows, columns=["feature", "dtype", "missing_rate",
                                         "inf_rate", "nunique", "action", "reason"])
    return kept, report


def align_features(list_a: list[str], list_b: list[str]) -> tuple[list[str], pd.DataFrame]:
    """Ordered intersection for cross-dataset runs (DRD D-08, ERD C7)."""
    set_b = set(list_b)
    common = [c for c in list_a if c in set_b]
    only_a = [c for c in list_a if c not in set_b]
    only_b = [c for c in list_b if c not in set(list_a)]
    align = pd.DataFrame({
        "feature": common + only_a + only_b,
        "status": (["common"] * len(common) + ["only_A"] * len(only_a)
                   + ["only_B"] * len(only_b)),
    })
    return common, align
