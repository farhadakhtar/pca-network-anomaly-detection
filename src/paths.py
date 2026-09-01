"""Path management system for PCA-Based Network Anomaly Detection.

Resolves directories dynamically and avoids hardcoded paths.
Provides a single source of truth for all project paths.
"""

import os
from pathlib import Path
from typing import Final

from .config import PROJECT_ROOT, RAW_DIR, PROCESSED_DIR


# ---------------------------------------------------------------------------
# Directory Resolution
# ---------------------------------------------------------------------------

def resolve_raw_data_dir() -> Path:
    """Resolve the raw data directory, respecting environment overrides.

    Returns
    -------
    Path
        Absolute path to the raw data directory.
    """
    override = os.getenv("RAW_DATA_DIR")
    if override:
        return Path(override).resolve()
    return RAW_DIR


def resolve_processed_data_dir() -> Path:
    """Resolve the processed data directory, respecting environment overrides.

    Returns
    -------
    Path
        Absolute path to the processed data directory.
    """
    override = os.getenv("PROCESSED_DATA_DIR")
    if override:
        return Path(override).resolve()
    return PROCESSED_DIR


def resolve_results_dir() -> Path:
    """Resolve the results directory.

    Returns
    -------
    Path
        Absolute path to the results directory.
    """
    override = os.getenv("RESULTS_DIR")
    if override:
        return Path(override).resolve()
    return PROJECT_ROOT / "results"


def resolve_figures_dir() -> Path:
    """Resolve the figures directory within results.

    Returns
    -------
    Path
        Absolute path to the figures directory.
    """
    return resolve_results_dir() / "figures"


def resolve_tables_dir() -> Path:
    """Resolve the tables directory within results.

    Returns
    -------
    Path
        Absolute path to the tables directory.
    """
    return resolve_results_dir() / "tables"


def resolve_reports_dir() -> Path:
    """Resolve the reports directory within results.

    Returns
    -------
    Path
        Absolute path to the reports directory.
    """
    return resolve_results_dir() / "reports"


# ---------------------------------------------------------------------------
# Dataset Filenames
# ---------------------------------------------------------------------------

DEFAULT_RAW_FILENAME: Final[str] = "network_traffic.csv"
DEFAULT_PROCESSED_FILENAME: Final[str] = "network_traffic_processed.csv"


# ---------------------------------------------------------------------------
# Path Constants (lazy-loaded via functions above)
# ---------------------------------------------------------------------------

# Resolved at call time to allow environment overrides
RAW_DATA_DIR: Final[Path] = resolve_raw_data_dir()
PROCESSED_DATA_DIR: Final[Path] = resolve_processed_data_dir()
RESULTS_DIR: Final[Path] = resolve_results_dir()
FIGURES_DIR: Final[Path] = resolve_figures_dir()
TABLES_DIR: Final[Path] = resolve_tables_dir()
REPORTS_DIR: Final[Path] = resolve_reports_dir()


# ---------------------------------------------------------------------------
# Convenience: ensure directories exist
# ---------------------------------------------------------------------------

def ensure_directories() -> None:
    """Create all required directories if they do not exist.

    This is idempotent and safe to call multiple times.
    """
    for _dir in [RAW_DATA_DIR, PROCESSED_DATA_DIR, RESULTS_DIR,
                 FIGURES_DIR, TABLES_DIR, REPORTS_DIR]:
        _dir.mkdir(parents=True, exist_ok=True)