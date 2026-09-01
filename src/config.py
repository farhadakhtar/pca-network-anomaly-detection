"""Configuration system for PCA-Based Network Anomaly Detection.

Centralized configuration with global constants, dataset paths,
random seeds, and experiment settings.
"""

import os
from pathlib import Path
from typing import Final

# ---------------------------------------------------------------------------
# Project Root & Paths (lazy-resolved via paths.py)
# ---------------------------------------------------------------------------

PROJECT_ROOT: Path = Path(__file__).parent.parent.resolve()

# ---------------------------------------------------------------------------
# Dataset Paths
# ---------------------------------------------------------------------------

DATA_DIR: Final[Path] = PROJECT_ROOT / "data"
RAW_DIR: Final[Path] = DATA_DIR / "raw"
PROCESSED_DIR: Final[Path] = DATA_DIR / "processed"

# ---------------------------------------------------------------------------
# Random Seeds & Reproducibility
# ---------------------------------------------------------------------------

RANDOM_SEED: Final[int] = 42
NUMPY_RANDOM_SEED: Final[int] = 42
PYTHONHASHSEED: Final[str] = str(RANDOM_SEED)

# ---------------------------------------------------------------------------
# PCA Experiment Configs
# ---------------------------------------------------------------------------

# Default number of principal components (can be overridden per experiment)
DEFAULT_N_COMPONENTS: Final[int] = 15

# PCA solver options
PCA_SOLVER: Final[str] = "auto"
PCA_WHITEN: Final[bool] = False

# Thresholding configs
DEFAULT_THRESHOLD_PERCENTILE: Final[float] = 99.0
DEFAULT_THRESHOLD_METHOD: Final[str] = "percentile"

# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

# Default feature column names (will be overridden by dataset-specific configs)
DEFAULT_FEATURE_COLUMNS: Final[list[str]] = [
    "flow_duration",
    "total_forward_packets",
    "total_backward_packets",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "avg_packet_size",
    "packet_length_variance",
    "forward_backward_ratio",
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

DEFAULT_LOG_LEVEL: Final[str] = "INFO"
DEFAULT_LOG_FORMAT: Final[str] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# ---------------------------------------------------------------------------
# Experiment Defaults
# ---------------------------------------------------------------------------

TEST_SIZE: Final[float] = 0.25
VALIDATION_SIZE: Final[float] = 0.20

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

def get_env() -> str:
    """Return the current environment (development, testing, production)."""
    return os.getenv("APP_ENV", "development")


def is_development() -> bool:
    """Check if running in development environment."""
    return get_env = get_env()
    return return_env == "development"


def is_testing() -> bool:
    """Check if running in testing environment."""
    return get_env() == "testing"