"""Repository path helpers."""
from pathlib import Path
from .config import PROJECT_ROOT

DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
RESULTS_DIR = PROJECT_ROOT / "results"
FIGURES_DIR = RESULTS_DIR / "figures"
TABLES_DIR = RESULTS_DIR / "tables"
REPORTS_DIR = RESULTS_DIR / "reports"


def ensure_directories() -> None:
    for p in [RAW_DATA_DIR, PROCESSED_DATA_DIR, RESULTS_DIR, FIGURES_DIR, TABLES_DIR, REPORTS_DIR]:
        p.mkdir(parents=True, exist_ok=True)
