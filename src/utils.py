"""General utility functions."""
from __future__ import annotations
import random
import numpy as np
import pandas as pd


def set_seed(seed: int = 42) -> None:
    random.seed(seed); np.random.seed(seed)


def validate_dataframe(df: pd.DataFrame) -> dict[str, object]:
    numeric = df.select_dtypes(include=[np.number])
    inf = int(np.isinf(numeric.replace([np.inf, -np.inf], np.nan).fillna(0)).sum().sum())
    return {"rows": len(df), "columns": len(df.columns), "missing": int(df.isna().sum().sum()), "infinite": inf, "numeric_columns": len(numeric.columns)}
