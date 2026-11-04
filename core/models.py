"""Data containers shared across the reconstruction pipeline.

Defines: `FileRecord` (one `Manifest.db` row resolved to source and output
paths) and `ReconstructionResult` (the outcome reported by a run).
Used by: core.reconstructor, core.android_reconstructor, gui.interface, launcher.cli.
Depends on: config.settings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from config.settings import (
    ROOT_TRACEABILITY_TEXT_NAME,
    TRACEABILITY_DIR_NAME,
    TRACEABILITY_FILE_MANIFEST_NAME,
    TRACEABILITY_PROVENANCE_NAME,
    ZIP_HASH_SIDECAR_SUFFIX,
)


@dataclass
class FileRecord:
    """One `Manifest.db` row, resolved to its backup blob and output path."""

    file_id: str
    domain: str
    relative_path: str
    flags: int
    metadata: dict[str, Any]
    source_path: Path
    output_path: PurePosixPath


@dataclass
class ReconstructionResult:
    """Aggregate outcome of a reconstruction run, as reported to the caller."""

    output: Path
    output_format: str
    output_layout: str
    encrypted: bool
    stats: dict[str, int]
    dry_run: bool = False
    cancelled: bool = False
    # SHA-256 of the finished zip, also written to `<output>.sha256`; None for a folder.
    archive_sha256: str | None = None
    platform: str = "ios"

    def as_dict(self) -> dict[str, Any]:
        traceability = (
            f"{TRACEABILITY_DIR_NAME}/{TRACEABILITY_PROVENANCE_NAME} and "
            f"{TRACEABILITY_DIR_NAME}/{TRACEABILITY_FILE_MANIFEST_NAME}"
        )
        if self.output_format == "zip":
            traceability = f"{ROOT_TRACEABILITY_TEXT_NAME}, {traceability}"
        sidecar = self.output.with_name(f"{self.output.name}{ZIP_HASH_SIDECAR_SUFFIX}")
        return {
            "output": str(self.output),
            "platform": self.platform,
            "format": self.output_format,
            "layout": self.output_layout,
            "encrypted": self.encrypted,
            "dry_run": self.dry_run,
            "cancelled": self.cancelled,
            "stats": self.stats,
            "traceability": traceability,
            "sha256": self.archive_sha256,
            "sha256_file": str(sidecar) if self.archive_sha256 else None,
        }
