"""Errors shared by every reconstruction pipeline.

Defines: `BackupError` (expected parsing/reconstruction failures),
`MissingCryptoError`, `ReconstructionFailedError` (a fail-closed run, with the
path of its failure report).
Used by: every core module, launcher.cli, gui.interface (through messages).
Depends on: nothing.
"""

from __future__ import annotations

from pathlib import Path


class BackupError(Exception):
    """Raised for expected backup parsing and reconstruction failures."""


class MissingCryptoError(BackupError):
    """Raised when encrypted backup handling needs the optional dependency."""


class ReconstructionFailedError(BackupError):
    """Raised when reconstruction processed rows but at least one row failed."""

    def __init__(self, message: str, report_path: Path | None = None) -> None:
        super().__init__(message)
        self.report_path = report_path
