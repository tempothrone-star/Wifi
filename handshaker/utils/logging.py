"""Logging setup with a configurable level.

Logs go to stderr so tool output on stdout (e.g. captured handshakes list,
verification reports) stays clean and machine-parseable.
"""

from __future__ import annotations

import logging
import sys

_FMT = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
_DATEFMT = "%H:%M:%S"


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def configure_logging(level: str = "INFO") -> None:
    """Configure the root logger once."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FMT, datefmt=_DATEFMT))
    root = logging.getLogger("handshaker")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not root.handlers:
        root.addHandler(handler)
    else:
        root.handlers[0].setFormatter(handler.formatter)
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
