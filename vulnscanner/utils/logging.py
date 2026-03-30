"""
Centralised logging configuration using Rich for pretty console output.
"""

import logging
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)


def get_logger(name: str = "vulnscanner") -> logging.Logger:
    """Return a logger wired to Rich's handler."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
            markup=True,
        )
        handler.setFormatter(logging.Formatter("%(message)s", datefmt="[%X]"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


def setup_file_logging(log_path: Path) -> None:
    """Optionally mirror logs to a file."""
    logger = logging.getLogger("vulnscanner")
    fh = logging.FileHandler(log_path)
    fh.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s")
    )
    logger.addHandler(fh)
