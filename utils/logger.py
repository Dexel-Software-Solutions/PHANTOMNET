"""
PHANTOMNET Logger
Centralized structured logging with color output and file rotation.
"""

import logging
import logging.handlers
from pathlib import Path


COLORS = {
    "DEBUG": "\033[36m",
    "INFO": "\033[32m",
    "WARNING": "\033[33m",
    "ERROR": "\033[31m",
    "CRITICAL": "\033[35m",
    "RESET": "\033[0m",
}


class ColorFormatter(logging.Formatter):
    FMT = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        color = COLORS.get(record.levelname, COLORS["RESET"])
        reset = COLORS["RESET"]
        formatter = logging.Formatter(
            f"{color}{self.FMT}{reset}",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        return formatter.format(record)


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Create and configure a named logger with console and file handlers."""
    logger = logging.getLogger(name)

    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level, logging.INFO))

    # Console handler with color
    ch = logging.StreamHandler()
    ch.setFormatter(ColorFormatter())
    logger.addHandler(ch)

    # Rotating file handler
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    fh = logging.handlers.RotatingFileHandler(
        log_dir / "phantomnet.log",
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8"
    )
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    )
    logger.addHandler(fh)

    return logger
