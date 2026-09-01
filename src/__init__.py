"""PCA-Based Network Anomaly Detection - Package Initialization.

This package provides a foundation layer for unsupervised network anomaly
 detection using Principal Component Analysis (PCA).

Typical usage example:

    from src.config import PROJECT_ROOT, RANDOM_SEED
    from src.paths import RAW_DATA_DIR, RESULTS_DIR
    from src.logging import setup_logger
    from src.utils import validate_dataframe
"""

__version__: str = "0.1.0"
__author__: str = "Research Team"

# Import core configs so they're available on package import
from .config import (  # noqa: F401
    PROJECT_ROOT,
    DATA_DIR,
    RAW_DIR,
    PROCESSED_DIR,
    RANDOM_SEED,
    DEFAULT_N_COMPONENTS,
    DEFAULT_THRESHOLD_PERCENTILE,
    DEFAULT_LOG_LEVEL,
    DEFAULT_LOG_FORMAT,
    get_env,
    is_development,
    is_testing,
)

# Import path resolvers
from .paths import (  # noqa: F401
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    RESULTS_DIR,
    FIGURES_DIR,
    TABLES_DIR,
    REPORTS_DIR,
    ensure_directories,
)

# Import logging
from .logging import (  # noqa: F401
    setup_logger,
    setup_root_logger,
)

# Import utilities
from .utils import (  # noqa: F401
    validate_dataframe,
    check_column_exists,
    safe_numeric_conversion,
    compute_percentile,
    compute_mean,
    compute_std,
    set_seed,
    set_deterministic_mode,
)