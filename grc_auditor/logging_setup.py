"""Logging setup.

The run log is itself an audit artifact: it records every action the tool takes
(every host touched, every command class run). It is written both to the console
and to an immutable per-run log file under the run's output directory.
"""

from __future__ import annotations

import logging
import os
import sys

LOGGER_NAME = "grc_auditor"


def setup_logging(run_dir: str, verbose: bool = False) -> logging.Logger:
    """Configure the package logger with console + per-run file handlers."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    os.makedirs(run_dir, exist_ok=True)
    audit_path = os.path.join(run_dir, "audit.log")
    file_handler = logging.FileHandler(audit_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    logger.debug("audit log: %s", audit_path)
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)
