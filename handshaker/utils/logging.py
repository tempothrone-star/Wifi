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


class _RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        from .secrets import redact
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact(v) for k, v in record.args.items()}
            else:
                record.args = tuple(redact(a) for a in record.args)
        return True


def configure_logging(level: str = "INFO") -> None:
    """Configure the root logger once. Logs go to stderr; secrets are redacted."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FMT, datefmt=_DATEFMT))
    handler.addFilter(_RedactFilter())
    root = logging.getLogger("handshaker")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not root.handlers:
        root.addHandler(handler)
    else:
        root.handlers[0].setFormatter(handler.formatter)
        root.handlers[0].addFilter(_RedactFilter())
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
