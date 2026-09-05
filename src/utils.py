"""Utility layer for PCA-Based Network Anomaly Detection.

Reusable helpers, validation utilities, and basic data checks.
NO business logic — pure utility functions only.

Functions are organized into logical sections:
- validation
- statistics
- reproducibility
- misc
"""

import os
import random
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_dataframe(df: pd.DataFrame,
                       require_numeric: bool = True,
                       check_missing: bool = True,
                       check_infinite: bool = True) -> Dict[str, Any]:
    """Validate a pandas DataFrame and return a validation report.

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame to validate.
    require_numeric : bool
        If True, check that data contains numeric values.
    check_missing : bool
        If True, check for missing (NaN) values.
    check_infinite : bool
        If True, check for infinite values.

    Returns
    -------
    Dict[str, Any]
        Validation report with keys: 'valid', 'issues', 'stats'.
    """
    issues: List[str] = []
    stats: Dict[str, Any] = {
        "row_count": len(df),
        "column_count": len(df.columns),
        "missing_count": 0,
        "infinite_count": 0,
    }

    if df.empty:
        issues.append("DataFrame is empty.")
        return {"valid": False, "issues": issues, "stats": stats}

    if check_missing:
        missing_total = int(df.isnull().sum().sum())
        stats["missing_count"] = missing_total
        if missing_total > 0:
            issues.append(f"Found {missing_total} missing values.")

    if check_infinite:
        infinite_total = int(np.isinf(df.select_dtypes(include=[np.number]).fillna(0)).sum().sum())
        stats["infinite_count"] = infinite_total
        if infinite_total > 0:
            issues.append(f"Found {infinite_total} infinite values.")

    if require_numeric:
        numeric_df = df.select_dtypes(include=[np.number])
        if len(numeric_df.columns) == 0:
            issues.append("DataFrame contains no numeric columns.")
        elif len(numeric_df.columns) < len(df.columns):
            non_numeric = set(df.columns) - set(numeric_df.columns)
            issues.append(f"Non-numeric columns found: {non_numeric}")

    valid = len(issues) == 0
    return {"valid": valid, "issues": issues, "stats": stats}


def check_column_exists(df: pd.DataFrame, column: str) -> bool:
    """Check if a column exists in a DataFrame.

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame to check.
    column : str
        Column name to look for.

    Returns
    -------
    bool
        True if column exists.
    """
    return column in df.columns


def safe_numeric_conversion(series: pd.Series) -> pd.Series:
    """Convert a series to numeric, coercing errors to NaN.

    Parameters
    ----------
    series : pd.Series
        Series to convert.

    Returns
    -------
    pd.Series
        Numeric series with errors coerced to NaN.
    """
    return pd.to_numeric(series, errors="coerce")


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def compute_percentile(data: np.ndarray, percentile: float) -> float:
    """Compute a percentile value from a numpy array.

    Parameters
    ----------
    data : np.ndarray
        Input data array.
    percentile : float
        Percentile to compute (0-100).

    Returns
    -------
    float
        The percentile threshold value.
    """
    return float(np.percentile(data, percentile))


def compute_mean(data: np.ndarray) -> float:
    """Compute the mean of a numpy array.

    Parameters
    ----------
    data : np.ndarray
        Input data array.

    Returns
    -------
    float
        Mean value.
    """
    return float(np.mean(data))


def compute_std(data: np.ndarray) -> float:
    """Compute the standard deviation of a numpy array.

    Parameters
    ----------
    data : np.ndarray
        Input data array.

    Returns
    -------
    float
        Standard deviation.
    """
    return float(np.std(data, ddof=1))


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------

def set_seed(seed: int = None) -> None:
    """Set random seeds for reproducibility.

    Parameters
    ----------
    seed : int, optional
        Seed value. If None, uses default RANDOM_SEED (42).
    """
    seed = seed or 42
    random.seed(seed)
    np.random.seed(seed)


def set_deterministic_mode() -> None:
    """Enable deterministic mode for consistent results."""
    os.environ["PYTHONHASHSEED"] = "0"


# ---------------------------------------------------------------------------
# Miscellaneous Helpers
# ---------------------------------------------------------------------------

def timeout_func(seconds: float):
    """Decorator to enforce a timeout on a function.

    NOTE: This is a basic placeholder. For production use, consider
    multiprocessing-based timeout enforcement.

    Parameters
    ----------
    seconds : float
        Maximum seconds to allow the function to run.

    Returns
    -------
    decorator : callable
        Decorator function.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    return decorator