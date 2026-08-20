"""Typed exceptions for the handshaker.

Using explicit exception types (instead of swallowing errors or guessing)
is part of the tool's anti-hallucination design: failures are surfaced
truthfully and never papered over.
"""

from __future__ import annotations


class HandshakerError(Exception):
    """Base class for all handshaker errors."""


class NotRootError(HandshakerError):
    """The operation requires root privileges."""


class AuthorizationDeniedError(HandshakerError):
    """The operator did not accept the authorization / consent gate."""


class NoAdapterError(HandshakerError):
    """No usable wireless adapter was found."""


class AdapterError(HandshakerError):
    """Failed to manipulate the adapter (monitor mode, injection, reset)."""


class ToolNotFoundError(HandshakerError):
    """A required external Kali tool is missing from the PATH."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(
            f"Required tool '{tool}' not found on PATH. "
            "Install it (e.g. `sudo apt install aircrack-ng hcxtools tshark mdk4 bettercap`) "
            "or disable the feature that needs it."
        )


class ToolExecutionError(HandshakerError):
    """An external tool returned a non-zero exit code."""


class CaptureError(HandshakerError):
    """A capture could not be produced."""


class VerificationError(HandshakerError):
    """A capture failed verification and was rejected."""


class LearningStateError(HandshakerError):
    """The adaptive learning state could not be read/written."""


class ConfigError(HandshakerError):
    """Configuration is invalid."""
