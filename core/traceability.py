"""Traceability artefacts shared by every pipeline.

Defines: `sha256_file`, the file-manifest CSV writer (`write_csv`, iOS columns
by default), the `_traceability/` pair for a folder or a zip, and the
fail-closed `write_failure_report`.
Used by: core.ios_reconstructor, core.ios_traceability,
core.android_reconstructor, core.decryptor, tests.
Depends on: core.ffs_archive, core.output_paths, config.settings.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config.settings import (
    CHUNK_SIZE,
    FAILURE_REPORT_DIR_NAME,
    TRACEABILITY_DIR_NAME,
    TRACEABILITY_FILE_MANIFEST_NAME,
    TRACEABILITY_PROVENANCE_NAME,
)
from core.ffs_archive import (
    FfsZipWriter,
)
from core.output_paths import (
    long_path,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Columns of the iOS file manifest. Consumed by: write_csv (default), core.decryptor.
IOS_MANIFEST_FIELDNAMES = (
    "file_id",
    "domain",
    "relative_path",
    "flags",
    "source_path",
    "output_path",
    "source_sha256",
    "output_sha256",
    "source_size",
    "output_size",
    "declared_size",
    "status",
    "error",
    # Written only by --mode decrypt: an encrypted backup records Digest as
    # SHA-1 of the ciphertext, so decrypting forces it to be recomputed over
    # the plaintext. Both values are kept so the rewrite is auditable.
    "manifest_digest_original",
    "manifest_digest_rewritten",
)


def write_csv(
    rows: list[dict[str, Any]], fh: io.TextIOBase, fieldnames: Iterable[str] = IOS_MANIFEST_FIELDNAMES
) -> None:
    writer = csv.DictWriter(fh, fieldnames=list(fieldnames))
    writer.writeheader()
    writer.writerows(rows)


def write_trace_folder(output_dir: Path, provenance: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    trace_dir = long_path(output_dir) / TRACEABILITY_DIR_NAME
    trace_dir.mkdir(parents=True, exist_ok=True)
    (trace_dir / TRACEABILITY_PROVENANCE_NAME).write_text(
        json.dumps(provenance, indent=2, sort_keys=True), encoding="utf-8"
    )
    with (trace_dir / TRACEABILITY_FILE_MANIFEST_NAME).open("w", newline="", encoding="utf-8") as fh:
        write_csv(rows, fh)


def write_trace_zip(
    writer: FfsZipWriter,
    provenance: dict[str, Any],
    rows: list[dict[str, Any]],
    fieldnames: Iterable[str] = IOS_MANIFEST_FIELDNAMES,
) -> dict[str, str]:
    """Write the `_traceability/` pair into the archive; return member -> SHA-256."""
    csv_buffer = io.StringIO()
    write_csv(rows, csv_buffer, fieldnames)
    members = {
        f"{TRACEABILITY_DIR_NAME}/{TRACEABILITY_PROVENANCE_NAME}": json.dumps(provenance, indent=2, sort_keys=True),
        f"{TRACEABILITY_DIR_NAME}/{TRACEABILITY_FILE_MANIFEST_NAME}": csv_buffer.getvalue(),
    }
    return {name: writer.add_root_bytes(name, text.encode("utf-8")) for name, text in members.items()}


def write_failure_report(
    output: Path,
    provenance: dict[str, Any],
    rows: list[dict[str, Any]],
    fieldnames: Iterable[str] = IOS_MANIFEST_FIELDNAMES,
) -> Path:
    report_root = output.parent / FAILURE_REPORT_DIR_NAME
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    report_dir = long_path(report_root / f"{output.stem}-{timestamp}")
    report_dir.mkdir(parents=True, exist_ok=False)
    (report_dir / TRACEABILITY_PROVENANCE_NAME).write_text(
        json.dumps(provenance, indent=2, sort_keys=True), encoding="utf-8"
    )
    with (report_dir / TRACEABILITY_FILE_MANIFEST_NAME).open("w", newline="", encoding="utf-8") as fh:
        write_csv(rows, fh, fieldnames)
    return report_dir
