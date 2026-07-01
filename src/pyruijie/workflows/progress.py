"""Progress-sink primitives for :mod:`pyruijie.workflows`.

Designed with a stable, self-contained API so a single GUI or CLI
component can render workflow events without branching on internals.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ProgressEvent:
    """A single progress notification emitted by a workflow.

    Attributes:
        level: One of ``"info"``, ``"success"``, ``"warning"``, ``"error"``.
        code: Short stable identifier (e.g. ``"peer.added"``) suitable
            for i18n lookup or UI icon mapping.
        message: Human-readable English summary. Must never contain
            secrets (private keys, preshared keys, passwords, API
            tokens) — those are stripped at the source.
        context: Arbitrary structured metadata. Same no-secrets rule
            applies.
    """

    level: str
    code: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)


class ProgressSink(Protocol):
    """Interface the caller implements to observe progress."""

    def emit(self, event: ProgressEvent) -> None:
        """Handle a progress event. Must not raise."""
        ...


class NullProgressSink:
    """Discards all events. Default when the caller doesn't supply one."""

    def emit(self, event: ProgressEvent) -> None:  # noqa: D401
        return None


class ConsoleProgressSink:
    """Prints to stderr. Intended for CLI use only."""

    _LEVEL_PREFIX = {
        "info": "  ",
        "success": "  ✓ ",
        "warning": "  ⚠ ",
        "error": "  ✗ ",
    }

    def __init__(self, stream: Any = None, verbose: bool = True) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._verbose = verbose

    def emit(self, event: ProgressEvent) -> None:
        if not self._verbose and event.level == "info":
            return
        prefix = self._LEVEL_PREFIX.get(event.level, "  ")
        self._stream.write(f"{prefix}{event.message}\n")
        self._stream.flush()
