"""Structured logging system for PCA-Based Network Anomaly Detection.

Provides log levels (INFO, DEBUG, ERROR), file + console output,
and structured log format configuration.
"""

import logging
import sys
from typing import Optional

from .config import DEFAULT_LOG_LEVEL, DEFAULT_LOG_FORMAT


# ---------------------------------------------------------------------------
# Logger Setup
# ---------------------------------------------------------------------------

def setup_logger(
    name: str,
    log_level: Optional[str] = None,
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
) -> logging.Logger:
    """Set up a logger with console and optional file output.

    Parameters
    ----------
    name : str
        Logger name (typically __name__).
    log_level : str, optional
        Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR').
        Defaults to config DEFAULT_LOG_LEVEL.
    log_file : str, optional
        Path to log file. If None, no file output.
    format_string : str, optional
        Custom log format. Defaults to config DEFAULT_LOG_FORMAT.

    Returns
    -------
    logging.Logger
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level or DEFAULT_LOG_LEVEL, logging.INFO))

    # Avoid adding handlers if already configured
    if logger.handlers:
        return logger

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level or DEFAULT_LOG_LEVEL, logging.INFO))

    fmt = format_string or DEFAULT_LOG_FORMAT
    formatter = logging.Formatter(fmt)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(getattr(logging, log_level or DEFAULT_LOG_LEVEL, logging.INFO))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# ---------------------------------------------------------------------------
# Pre-configured root logger
# ---------------------------------------------------------------------------

def setup_root_logger(log_file: Optional[str] = None) -> None:
    """Set up the root project logger.

    Parameters
    ----------
    log_file : str, optional
        Path to log file. If None, only console output.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, DEFAULT_LOG_LEVEL, logging.INFO))

    # Clear existing handlers to avoid duplicates
    if root.handlers:
        root.handlers.clear()

    fmt = DEFAULT_LOG_FORMAT
    formatter = logging.Formatter(fmt)

    # Console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # File (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)