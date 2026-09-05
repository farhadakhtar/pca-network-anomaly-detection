"""Configuration system for PCA-Based Network Anomaly Detection.

Structured Config object with centralized constants, experiment settings,
and environment validation. All modules should import from this module.
"""

import os
from pathlib import Path
from typing import Final


class Config:
    """Central configuration object for the project.

    All configuration values are accessible via the module-level ``config``
    instance, e.g.::

        from src.config import config
        print(config.RANDOM_SEED)
    """

    # -------------------------------------------------------------------------
    # Random Seeds & Reproducibility
    # -------------------------------------------------------------------------

    RANDOM_SEED: Final[int] = 42
    NUMPY_RANDOM_SEED: Final[int] = 42
    PYTHONHASHSEED: Final[str] = str(RANDOM_SEED)

    # -------------------------------------------------------------------------
    # PCA Experiment Configs
    # -------------------------------------------------------------------------

    # Default number of principal components (can be overridden per experiment)
    DEFAULT_N_COMPONENTS: Final[int] = 15

    # PCA solver options
    PCA_SOLVER: Final[str] = "auto"
    PCA_WHITEN: Final[bool] = False

    # Thresholding configs
    DEFAULT_THRESHOLD_PERCENTILE: Final[float] = 99.0
    DEFAULT_THRESHOLD_METHOD: Final[str] = "percentile"

    # -------------------------------------------------------------------------
    # Feature Engineering
    # -------------------------------------------------------------------------

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

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------

    DEFAULT_LOG_LEVEL: Final[str] = "INFO"
    DEFAULT_LOG_FORMAT: Final[str] = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # -------------------------------------------------------------------------
    # Experiment Defaults
    # -------------------------------------------------------------------------

    TEST_SIZE: Final[float] = 0.25
    VALIDATION_SIZE: Final[float] = 0.20

    # -------------------------------------------------------------------------
    # Environment
    # -------------------------------------------------------------------------

    def get_env() -> str:
        """Return the current environment (development, testing, production)."""
        return os.getenv("APP_ENV", "development")

    def validate_env() -> None:
        """Validate that APP_ENV is one of the allowed values.

        Raises
        ------
        AssertionError
            If APP_ENV is not one of ``["development", "testing", "production"]``.
        """
        env = get_env()
        assert env in ["development", "testing", "production"], (
            f"Invalid APP_ENV: {env}. Must be one of ['development', 'testing', 'production']"
        )

    # -------------------------------------------------------------------------
    # Convenience properties
    # -------------------------------------------------------------------------

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.get_env() == "development"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing environment."""
        return self.get_env() == "testing"


# Module-level config instance — created after validate_env()
config = Config()
config.validate_env()