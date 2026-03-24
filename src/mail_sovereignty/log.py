"""Centralized loguru logging configuration."""

import logging
import sys

from loguru import logger


class _InterceptHandler(logging.Handler):
    """Route stdlib logging records into loguru."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: str | int = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        frame, depth = logging.currentframe(), 2
        while frame and frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        logger.opt(depth=depth, exception=record.exc_info).log(
            level, record.getMessage()
        )


def setup(verbose: bool = False) -> None:
    """Configure loguru as the sole logging backend."""
    logger.remove()

    level = "DEBUG" if verbose else "INFO"
    if verbose:
        fmt = (
            "<green>{time:HH:mm:ss}</green> | <level>{level:<7}</level> | "
            "<cyan>{name}</cyan> | <level>{message}</level>"
        )
    else:
        fmt = (
            "<green>{time:HH:mm:ss}</green> | <level>{level:<7}</level> | "
            "<level>{message}</level>"
        )
    logger.add(sys.stderr, format=fmt, level=level, colorize=True)

    # Log everything to a rotating file (always DEBUG regardless of verbosity)
    file_fmt = (
        "{time:YYYY-MM-DD HH:mm:ss} | {level:<7} | {name}:{function}:{line} | {message}"
    )
    logger.add(
        "mxmap.log",
        format=file_fmt,
        level="DEBUG",
        rotation="5 MB",
        retention=3,
        encoding="utf-8",
    )

    # Intercept all stdlib logging → loguru
    logging.basicConfig(handlers=[_InterceptHandler()], level=0, force=True)

    # Suppress noisy third-party loggers
    for name in ("httpx", "httpcore", "dns", "stamina"):
        logging.getLogger(name).setLevel(logging.WARNING)
