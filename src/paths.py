"""Path management system for PCA-Based Network Anomaly Detection.

Object-based path resolution with centralized directory management.
All path resolution goes through the ``paths`` instance.
"""

from pathlib import Path

from .config import config


class Paths:
    """Resolves and manages all project directories.

    Provides a single source of truth for project paths with support for
    environment variable overrides. All directories are created on demand.

    Example
    -------
    >>> from src.paths import paths
    >>> print(paths.raw_data)
    D:\...\data\raw
    >>> paths.ensure_directories()
    """

    def __init__(self):
        self.base_dir: Path = Path(__file__).resolve().parent.parent
        self.raw_data: Path = self.base_dir / "data" / "raw"
        self.processed_data: Path = self.base_dir / "data" / "processed"
        self.results: Path = self.base_dir / "results"
        self.figures: Path = self.results / "figures"
        self.tables: Path = self.results / "tables"
        self.reports: Path = self.results / "reports"

        # Apply environment overrides if set
        self._apply_env_overrides()

    def _apply_env_overrides(self):
        """Apply environment variable overrides for path resolution.

        Override environment variables:
        - RAW_DATA_DIR: override raw data directory
        - PROCESSED_DATA_DIR: override processed data directory
        - RESULTS_DIR: override results directory
        """
        import os

        raw_override = os.getenv("RAW_DATA_DIR")
        if raw_override:
            self.raw_data = Path(raw_override).resolve()

        processed_override = os.getenv("PROCESSED_DATA_DIR")
        if processed_override:
            self.processed_data = Path(processed_override).resolve()

        results_override = os.getenv("RESULTS_DIR")
        if results_override:
            self.results = Path(results_override).resolve()
            # Re-derive child dirs
            self.figures = self.results / "figures"
            self.tables = self.results / "tables"
            self.reports = self.results / "reports"

    def ensure_directories(self):
        """Create all required directories if they do not exist.

        This is idempotent and safe to call multiple times.
        """
        for path in [self.raw_data, self.processed_data, self.results,
                     self.figures, self.tables, self.reports]:
            path.mkdir(parents=True, exist_ok=True)


# Module-level paths instance — the central point of access
paths = Paths()