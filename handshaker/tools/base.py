"""Base class shared by all tool wrappers."""

from __future__ import annotations

from ..utils.proc import find_tool


class Tool:
    """A wrapped Kali tool.

    Subclasses set ``name`` and implement specific actions. A ``Tool`` is
    constructed with an optional path override; the binary is resolved lazily
    so wrappers can be imported even when a tool is not installed.
    """

    name: str = ""

    def __init__(self, override: str | None = None) -> None:
        self.override = override
        self._path: str | None = None

    @property
    def path(self) -> str:
        if self._path is None:
            self._path = find_tool(self.name, self.override)
        return self._path
