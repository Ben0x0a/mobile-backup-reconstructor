"""iOS-specific provenance and zip-root artefacts.

Defines: `build_provenance` (the iOS provenance JSON), the enriched manifest
(`build_enriched_manifest`: Manifest.db + Files.zipPath), the root summary
sections, and `write_ios_root_artefacts`.
Used by: core.ios_reconstructor.
Depends on: core.traceability, core.ffs_archive, core.ios_backup,
core.ios_domain_map, config.settings.
"""

from __future__ import annotations

import platform
import shutil
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config.settings import (
    ENRICHED_MANIFEST_NAME,
    ENRICHED_ZIP_PATH_COLNAME,
    ROOT_MANIFEST_DB_NAME,
    TOOL_NAME,
    TOOL_VERSION,
    TRACEABILITY_DIR_NAME,
    TRACEABILITY_FILE_MANIFEST_NAME,
)
from core.ffs_archive import (
    FfsZipWriter,
    TraceSection,
    sidecar_path,
    write_root_traceability_text,
)
from core.ios_backup import first_present, missing_optional_files
from core.ios_domain_map import DomainMap
from core.traceability import sha256_file, write_trace_zip


def optional_file_sha256(path: Path) -> str | None:
    """The file's digest, or None when the backup does not carry it."""
    return sha256_file(path) if path.is_file() else None


def build_provenance(
    backup_dir: Path,
    output: Path,
    output_format: str,
    manifest: dict[str, Any],
    info: dict[str, Any],
    status: dict[str, Any],
    encrypted: bool,
    stats: dict[str, int],
    command: list[str],
    output_layout: str,
    domain_map: DomainMap | None,
    dry_run: bool,
    continue_on_error: bool,
    try_default_passwords: bool,
    manifest_db_plaintext_sha256: str | None = None,
) -> dict[str, Any]:
    # `stats["cancelled"]` is surfaced at the top of the output block as well as
    # inside stats: a reader must not have to notice a counter to learn that the
    # reconstruction was stopped early and the tree is incomplete.
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "platform": "ios",
        "created_utc": datetime.now(UTC).isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
        "command": command,
        "backup": {
            "path": str(backup_dir),
            "manifest_plist_sha256": sha256_file(backup_dir / "Manifest.plist"),
            "manifest_db_sha256": sha256_file(backup_dir / "Manifest.db"),
            # The Manifest.db actually walked: the decrypted copy for an encrypted
            # backup, the same file (same digest) otherwise. It is the one written
            # to the archive root, so this digest verifies that copy.
            "manifest_db_plaintext_sha256": manifest_db_plaintext_sha256,
            # None when the backup does not carry the file at all. `absent_files`
            # below says which, so a null is never ambiguous between "missing from
            # the backup" and "the tool failed to read it".
            "info_plist_sha256": optional_file_sha256(backup_dir / "Info.plist"),
            "status_plist_sha256": optional_file_sha256(backup_dir / "Status.plist"),
            "absent_files": missing_optional_files(backup_dir),
            "encrypted": encrypted,
            "manifest_version": manifest.get("Version"),
            "system_domains_version": manifest.get("SystemDomainsVersion"),
            "manifest_date": str(manifest.get("Date")),
            "status": {
                "is_full_backup": status.get("IsFullBackup"),
                "snapshot_state": status.get("SnapshotState"),
                "date": str(status.get("Date")),
            },
            "device": {
                "name": first_present(info, ("Device Name", "Display Name")),
                "product_name": info.get("Product Name"),
                "product_type": first_present(info, ("Product Type", "ProductType")),
                "product_version": first_present(info, ("Product Version", "ProductVersion")),
                "serial_number": info.get("Serial Number"),
                "unique_identifier": first_present(info, ("Unique Identifier", "Target Identifier")),
            },
        },
        "output": {
            "path": str(output),
            "format": output_format,
            "layout": output_layout,
            "domain_map": domain_map.get("path") if domain_map else None,
            "domain_map_name": domain_map.get("name") if domain_map else None,
            "domain_map_ios_versions": domain_map.get("ios_versions") if domain_map else None,
            "dry_run": dry_run,
            "continue_on_error": continue_on_error,
            "try_default_passwords": try_default_passwords,
            "cancelled": bool(stats.get("cancelled")),
        },
        "stats": stats,
    }


# Row statuses whose `output_path` names a member actually in the archive (or,
# for a dry run, the member a real run would write). Consumed by: build_enriched_manifest.
ARCHIVED_STATUSES = frozenset({"written", "directory_record", "planned"})


def build_enriched_manifest(db_path: Path, rows: list[dict[str, Any]], destination: Path) -> Path:
    """Copy `Manifest.db` to `destination`, adding each row's archive member name.

    HOW: copies the database file, adds one TEXT column
    (`ENRICHED_ZIP_PATH_COLNAME`) to `Files`, and sets it by `fileID` for every
    row present in the archive. Rows that were not written (missing blob,
    failure, cancelled before reaching them) keep NULL, so a NULL is never
    mistaken for a path.
    WHY a copy with one added column rather than a separate table or CSV: any
    tool or query written for Manifest.db keeps working unchanged, and the
    member name sits on the same row as the domain and relativePath it was
    derived from. The original Manifest.db is written beside it, untouched.
    """
    shutil.copyfile(db_path, destination)
    conn = sqlite3.connect(destination)
    try:
        conn.execute(f'ALTER TABLE Files ADD COLUMN "{ENRICHED_ZIP_PATH_COLNAME}" TEXT')
        conn.executemany(
            f'UPDATE Files SET "{ENRICHED_ZIP_PATH_COLNAME}" = ? WHERE fileID = ?',
            ((row["output_path"], row["file_id"]) for row in rows if row["status"] in ARCHIVED_STATUSES),
        )
        conn.commit()
    finally:
        conn.close()
    return destination


def ios_traceability_sections(provenance: dict[str, Any], digests: dict[str, str], zip_name: str) -> list[TraceSection]:
    """The root summary for an iOS archive, from the provenance and root digests."""
    backup = provenance["backup"]
    device = backup["device"]
    output = provenance["output"]
    encrypted = backup["encrypted"]
    return [
        (
            "Run",
            [
                ("Tool", f"{provenance['tool']} {provenance['tool_version']}"),
                ("Created (UTC)", provenance["created_utc"]),
                ("Host", f"{provenance['host']['system']} {provenance['host']['release']}"),
                ("Python", provenance["host"]["python"]),
                ("Command", " ".join(provenance["command"])),
            ],
        ),
        (
            "Source",
            [
                ("Platform", "iOS backup (iTunes / Finder)"),
                ("Path", backup["path"]),
                ("Encrypted", "yes" if encrypted else "no"),
                ("Backup date", backup["manifest_date"]),
                ("Device name", device["name"]),
                ("Product", f"{device['product_name'] or ''} {device['product_type'] or ''}".strip()),
                ("iOS version", device["product_version"]),
                ("Serial number", device["serial_number"]),
                ("Unique identifier", device["unique_identifier"]),
                ("Absent optional files", ", ".join(backup["absent_files"])),
            ],
        ),
        (
            "Source digests (SHA-256, as read)",
            [
                ("Manifest.plist", backup["manifest_plist_sha256"]),
                ("Manifest.db" + (" (encrypted)" if encrypted else ""), backup["manifest_db_sha256"]),
                ("Info.plist", backup["info_plist_sha256"]),
                ("Status.plist", backup["status_plist_sha256"]),
            ],
        ),
        (
            "Archive root artefacts (SHA-256)",
            [
                (
                    ROOT_MANIFEST_DB_NAME + (" (decrypted)" if encrypted else " (copy of the source)"),
                    digests.get(ROOT_MANIFEST_DB_NAME),
                ),
                (ENRICHED_MANIFEST_NAME, digests.get(ENRICHED_MANIFEST_NAME)),
                *((name, digest) for name, digest in digests.items() if name.startswith(TRACEABILITY_DIR_NAME)),
            ],
        ),
        (
            "Output",
            [
                ("Archive", zip_name),
                ("Layout", output["layout"]),
                ("Domain map", output["domain_map_name"]),
                ("Dry run", output["dry_run"]),
                ("Continue on error", output["continue_on_error"]),
                ("Cancelled (incomplete)", output["cancelled"]),
            ],
        ),
        ("Statistics", list(provenance["stats"].items())),
        (
            "Verification",
            [
                ("Archive SHA-256", f"in {sidecar_path(Path(zip_name)).name}, beside the archive"),
                (
                    "Per-file digests",
                    f"{TRACEABILITY_DIR_NAME}/{TRACEABILITY_FILE_MANIFEST_NAME} (source and output SHA-256)",
                ),
                (f"{ENRICHED_MANIFEST_NAME}", f"Manifest.db + Files.{ENRICHED_ZIP_PATH_COLNAME} (member name per row)"),
            ],
        ),
    ]


def write_ios_root_artefacts(
    writer: FfsZipWriter,
    db_path: Path,
    provenance: dict[str, Any],
    rows: list[dict[str, Any]],
    zip_name: str,
) -> None:
    """Write `_traceability/`, Manifest.db, the enriched manifest and the summary.

    The summary is written last because it lists the digests of the others.
    """
    digests = {ROOT_MANIFEST_DB_NAME: writer.add_root_file(ROOT_MANIFEST_DB_NAME, db_path)}
    with tempfile.TemporaryDirectory(prefix="mobile_backup_enriched_") as tmp:
        enriched = build_enriched_manifest(db_path, rows, Path(tmp) / ENRICHED_MANIFEST_NAME)
        digests[ENRICHED_MANIFEST_NAME] = writer.add_root_file(ENRICHED_MANIFEST_NAME, enriched)
    digests.update(write_trace_zip(writer, provenance, rows))
    write_root_traceability_text(writer, ios_traceability_sections(provenance, digests, zip_name))
