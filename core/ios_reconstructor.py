"""The iOS reconstruction pipeline.

Defines: the folder and Full File System-like zip writers
(`reconstruct_to_folder`, `reconstruct_to_zip`), dry-run planning, output
validation, and `reconstruct_ios_backup`, which runs them end to end.
Used by: core.reconstructor.
Depends on: core.ios_backup, core.ios_crypto, core.ios_domain_map,
core.ios_traceability, core.traceability, core.run_control, core.ffs_archive,
core.output_paths, core.errors, core.models, config.settings.

The input backup is never modified. For encrypted backups, decrypted content is
written only to the requested output folder or zip archive.
"""

from __future__ import annotations

import hashlib
import platform
from pathlib import Path
from typing import Any, BinaryIO

from config.settings import (
    CHUNK_SIZE,
    DEFAULT_OUTPUT_LAYOUT,
    ENRICHED_MANIFEST_NAME,
    FFS_LAYOUT,
    OUTPUT_LAYOUTS,
    ROOT_MANIFEST_DB_NAME,
    ROOT_TRACEABILITY_TEXT_NAME,
    TOOL_NAME,
    TRACEABILITY_DIR_NAME,
)
from core.errors import BackupError, ReconstructionFailedError
from core.ffs_archive import (
    FfsZipWriter,
    write_zip_sha256_sidecar,
)
from core.ios_backup import (
    backup_product_version,
    count_manifest_rows,
    is_directory_record,
    iter_file_records,
    iter_manifest_rows,
    metadata_mtime,
    metadata_size,
    read_optional_plist,
    read_plist,
    resolve_backup_dir,
)
from core.ios_crypto import Keybag, decrypt_copy, file_key_for_record, prepare_manifest_db
from core.ios_domain_map import DomainMap, load_domain_mounts, mapped_output_path
from core.ios_traceability import build_provenance, write_ios_root_artefacts
from core.models import FileRecord, ReconstructionResult
from core.output_paths import (
    claim_unique_path,
    exceeds_windows_max_path,
    long_path,
)
from core.run_control import (
    CancelEvent,
    ProgressCallback,
    is_cancelled,
    make_staging_dir,
    promote_folder_output,
    promote_zip_output,
    remove_staging_dir,
    report_progress,
)
from core.traceability import sha256_file, write_failure_report, write_trace_folder


def copy_plain(src: Path, dst: BinaryIO) -> tuple[int, str, str]:
    """Copy an unencrypted backup blob verbatim, hashing input and output.

    WHY no size limit: in an unencrypted backup the stored blob IS the file, so
    there is no AES padding to trim. Truncating to the metadata `Size` here
    destroyed intact evidence whenever that field was stale or zero, and still
    reported the row as `written`. The declared size is recorded in the file
    manifest for comparison instead of being enforced.
    """
    src_digest = hashlib.sha256()
    out_digest = hashlib.sha256()
    written = 0
    with src.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            src_digest.update(chunk)
            dst.write(chunk)
            out_digest.update(chunk)
            written += len(chunk)
    return written, src_digest.hexdigest(), out_digest.hexdigest()


def row_for_record(record: FileRecord, output_ref: str, status: str, error: str = "") -> dict[str, Any]:
    return {
        "file_id": record.file_id,
        "domain": record.domain,
        "relative_path": record.relative_path,
        "flags": record.flags,
        "source_path": str(record.source_path),
        "output_path": output_ref,
        "source_sha256": "",
        "output_sha256": "",
        "source_size": record.source_path.stat().st_size if record.source_path.is_file() else "",
        "output_size": "",
        "declared_size": metadata_size(record.metadata) if metadata_size(record.metadata) is not None else "",
        "status": status,
        "error": error,
    }


def dry_run_records(
    backup_dir: Path,
    db_path: Path,
    output_layout: str,
    domain_map: DomainMap | None = None,
    claimed: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Plan every row without writing content.

    `claimed` is the archive writer's claim table for zip output, so planned
    names match what a real run would write (root artefact names are reserved).
    """
    rows: list[dict[str, Any]] = []
    stats = {
        "records": 0,
        "written": 0,
        "missing": 0,
        "failed": 0,
        "directories": 0,
        "cancelled": 0,
        # Destinations over Windows' 260-character limit. Written correctly via the
        # extended-length path, but unreachable to a tool that does not handle them.
        "long_paths": 0,
    }
    claimed = {} if claimed is None else claimed
    for record in iter_file_records(backup_dir, db_path, output_layout, domain_map):
        stats["records"] += 1
        rel = claim_unique_path(record.output_path, claimed, is_directory_record(record))
        output_ref = rel.as_posix()
        if is_directory_record(record):
            rows.append(row_for_record(record, output_ref, "directory_record"))
            stats["directories"] += 1
        elif record.source_path.is_file():
            rows.append(row_for_record(record, output_ref, "planned"))
        else:
            rows.append(row_for_record(record, output_ref, "missing_source"))
            stats["missing"] += 1
    return rows, stats


def reconstruct_to_folder(
    backup_dir: Path,
    db_path: Path,
    output_dir: Path,
    encrypted: bool,
    keybag: Keybag | None,
    output_layout: str = "backup",
    domain_map: DomainMap | None = None,
    report_root: Path | None = None,
    progress: ProgressCallback | None = None,
    cancel: CancelEvent | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Reconstruct every manifest row into `output_dir`.

    `report_root` is the path recorded in the file manifest, which differs from
    `output_dir` because reconstruction runs inside a staging directory that is
    promoted on success. WHY: recording the staging path left every row of a
    forensic manifest pointing at a temporary directory that no longer exists.
    """
    report_root = report_root if report_root is not None else output_dir
    # All I/O below goes through the extended-length form; `report_root` stays
    # plain so traceability records the path an examiner would type.
    output_dir = long_path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    stats = {
        "records": 0,
        "written": 0,
        "missing": 0,
        "failed": 0,
        "directories": 0,
        "cancelled": 0,
        # Destinations over Windows' 260-character limit. Written correctly via the
        # extended-length path, but unreachable to a tool that does not handle them.
        "long_paths": 0,
    }
    claimed: dict[str, str] = {}
    total = count_manifest_rows(db_path)
    for record in iter_file_records(backup_dir, db_path, output_layout, domain_map):
        if is_cancelled(cancel):
            stats["cancelled"] = 1
            break
        stats["records"] += 1
        rel = claim_unique_path(record.output_path, claimed, is_directory_record(record), output_dir)
        target = output_dir / Path(*rel.parts)
        reported = str(report_root / Path(*rel.parts))
        if is_directory_record(record):
            target.mkdir(parents=True, exist_ok=True)
            row = row_for_record(record, reported, "directory_record")
            rows.append(row)
            stats["directories"] += 1
            continue
        if not record.source_path.is_file():
            row = row_for_record(record, reported, "missing_source")
            rows.append(row)
            stats["missing"] += 1
            continue
        row = row_for_record(record, reported, "pending")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            key = file_key_for_record(record, keybag) if encrypted and keybag else None
            if encrypted and key is None:
                raise BackupError("Encrypted backup record has no usable file encryption key")
            with target.open("wb") as out_fh:
                if key is None:
                    output_size, source_hash, output_hash = copy_plain(record.source_path, out_fh)
                else:
                    output_size, source_hash, output_hash = decrypt_copy(
                        record.source_path, out_fh, key, metadata_size(record.metadata)
                    )
            row.update(
                {
                    "status": "written",
                    "source_sha256": source_hash,
                    "output_sha256": output_hash,
                    "output_size": output_size,
                }
            )
            stats["written"] += 1
        except Exception as exc:
            row.update({"status": "failed", "error": str(exc)})
            stats["failed"] += 1
            if target.exists():
                target.unlink()
        if exceeds_windows_max_path(Path(reported)):
            stats["long_paths"] += 1
        rows.append(row)
        report_progress(progress, stats["records"], total, record.relative_path)
    return rows, stats


def reconstruct_to_zip(
    backup_dir: Path,
    db_path: Path,
    writer: FfsZipWriter,
    encrypted: bool,
    keybag: Keybag | None,
    output_layout: str = "backup",
    domain_map: DomainMap | None = None,
    progress: ProgressCallback | None = None,
    cancel: CancelEvent | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Stream every manifest row into the open archive `writer`.

    No device path ever touches the disk as a path: content goes through a
    spool into a member name, which is what keeps the Windows path limit out
    of the picture (see core.ffs_archive).
    """
    rows: list[dict[str, Any]] = []
    stats = {
        "records": 0,
        "written": 0,
        "missing": 0,
        "failed": 0,
        "directories": 0,
        "cancelled": 0,
        # Always 0 for a zip: member names carry no path limit. Kept so every
        # run reports the same statistics keys.
        "long_paths": 0,
    }
    total = count_manifest_rows(db_path)
    for record in iter_file_records(backup_dir, db_path, output_layout, domain_map):
        if is_cancelled(cancel):
            stats["cancelled"] = 1
            break
        stats["records"] += 1
        arcname = writer.claim(record.output_path, is_directory_record(record))
        if is_directory_record(record):
            dir_name = writer.add_directory(arcname, metadata_mtime(record.metadata))
            rows.append(row_for_record(record, dir_name, "directory_record"))
            stats["directories"] += 1
            continue
        if not record.source_path.is_file():
            rows.append(row_for_record(record, arcname, "missing_source"))
            stats["missing"] += 1
            continue
        row = row_for_record(record, arcname, "pending")
        try:
            key = file_key_for_record(record, keybag) if encrypted and keybag else None
            if encrypted and key is None:
                raise BackupError("Encrypted backup record has no usable file encryption key")

            def produce(spool: BinaryIO, key: bytes | None = key, record: FileRecord = record) -> tuple[int, str, str]:
                if key is None:
                    return copy_plain(record.source_path, spool)
                return decrypt_copy(record.source_path, spool, key, metadata_size(record.metadata))

            output_size, source_hash, output_hash = writer.add_member(arcname, metadata_mtime(record.metadata), produce)
            row.update(
                {
                    "status": "written",
                    "source_sha256": source_hash,
                    "output_sha256": output_hash,
                    "output_size": output_size,
                }
            )
            stats["written"] += 1
        except Exception as exc:
            row.update({"status": "failed", "error": str(exc)})
            stats["failed"] += 1
        rows.append(row)
        report_progress(progress, stats["records"], total, record.relative_path)
    return rows, stats


def validate_output_target(path: Path, backup_dir: Path, force: bool, output_format: str) -> None:
    resolved_parent = path.parent.expanduser().resolve()
    backup_resolved = backup_dir.resolve()
    if backup_resolved == path.expanduser().resolve() or backup_resolved in path.expanduser().resolve().parents:
        raise BackupError("Output must not be inside the source backup directory")
    if output_format == "folder":
        if not resolved_parent.exists():
            raise BackupError(f"Output parent directory does not exist: {resolved_parent}")
        if path.exists() and not path.is_dir():
            raise BackupError(f"Output folder path exists but is not a directory: {path}")
    else:
        if path.exists() and not force:
            raise BackupError(f"Output zip already exists: {path}. Use --force to overwrite.")
        if not resolved_parent.exists():
            raise BackupError(f"Output parent directory does not exist: {resolved_parent}")


def output_has_tool_collision(
    output_dir: Path,
    db_path: Path | None = None,
    output_layout: str = "backup",
    domain_map: DomainMap | None = None,
) -> bool:
    if not output_dir.exists():
        return False
    if (output_dir / TRACEABILITY_DIR_NAME).exists():
        return True
    if db_path is None:
        return False
    seen: set[str] = set()
    for _, domain, relative_path, _, _ in iter_manifest_rows(db_path):
        top_level = mapped_output_path(domain, relative_path, output_layout, domain_map).parts[0]
        if top_level.lower() in seen:
            continue
        seen.add(top_level.lower())  # each top-level folder need only be checked once
        if (output_dir / top_level).exists():
            return True
    return False


def normalise_output_format(output_format: str, output_layout: str = "backup") -> str:
    """Resolve `auto` and enforce that the Full File System-like layout is a zip.

    WHY the FFS layout refuses a folder rather than quietly switching: its device
    paths exceed Windows' 260-character limit as a folder tree, which broke the
    output for tools that do not handle long paths. An operator who explicitly
    asked for a folder must learn why they get a zip, not find one unannounced.
    """
    if output_format not in ("auto", "folder", "zip"):
        raise BackupError(f"Unsupported output format: {output_format}")
    if output_layout == FFS_LAYOUT:
        if output_format == "folder":
            raise BackupError(
                "The Full File System-like layout is always written as a zip: its device paths "
                "exceed Windows' path-length limit as a folder tree. Use --format zip (or auto), "
                "or --layout backup for a folder."
            )
        return "zip"
    if output_format == "auto":
        return "zip" if platform.system() == "Windows" else "folder"
    return output_format


def normalise_output_layout(output_layout: str) -> str:
    if output_layout not in OUTPUT_LAYOUTS:
        raise BackupError(f"Unsupported output layout: {output_layout}")
    return output_layout


def reconstruct_ios_backup(
    backup: Path,
    output: Path,
    output_format: str = "auto",
    password: str | None = None,
    force: bool = False,
    command: list[str] | None = None,
    allow_password_prompt: bool = True,
    output_layout: str = DEFAULT_OUTPUT_LAYOUT,
    domain_map_path: Path | None = None,
    dry_run: bool = False,
    continue_on_error: bool = False,
    try_default_passwords: bool = False,
    progress: ProgressCallback | None = None,
    cancel: CancelEvent | None = None,
) -> ReconstructionResult:
    """Reconstruct an iOS backup directory; see core.reconstructor.reconstruct_backup."""
    backup_dir = resolve_backup_dir(backup)
    manifest = read_plist(backup_dir / "Manifest.plist")
    info = read_optional_plist(backup_dir / "Info.plist")
    status = read_optional_plist(backup_dir / "Status.plist")
    encrypted = bool(manifest.get("IsEncrypted", False))
    output_layout = normalise_output_layout(output_layout)
    output_format = normalise_output_format(output_format, output_layout)
    product_version = backup_product_version(info, manifest)
    domain_map = load_domain_mounts(domain_map_path, product_version) if output_layout == FFS_LAYOUT else None

    output = output.expanduser()
    if output_format == "zip" and output.suffix.lower() != ".zip":
        output = output.with_suffix(".zip")
    validate_output_target(output, backup_dir, force, output_format)

    db_path, tmp_dir, keybag = prepare_manifest_db(
        backup_dir, encrypted, manifest, password, allow_password_prompt, try_default_passwords
    )
    command = command or [TOOL_NAME]
    stage_root = make_staging_dir(output.parent.expanduser().resolve())
    archive_sha256: str | None = None

    def provenance_for(stats: dict[str, int]) -> dict[str, Any]:
        return build_provenance(
            backup_dir,
            output,
            output_format,
            manifest,
            info,
            status,
            encrypted,
            stats,
            command,
            output_layout,
            domain_map,
            dry_run,
            continue_on_error,
            try_default_passwords,
            manifest_db_plaintext_sha256=sha256_file(db_path),
        )

    def fail_closed(provenance: dict[str, Any], rows: list[dict[str, Any]]) -> None:
        report_path = write_failure_report(output, provenance, rows)
        raise ReconstructionFailedError(
            f"Reconstruction failed; no output was produced. Failure report: {report_path}", report_path
        )

    try:
        if (
            output_format == "folder"
            and output_has_tool_collision(output, db_path, output_layout, domain_map)
            and not force
        ):
            raise BackupError(
                f"Output folder already contains reconstructed backup data: {output}. Use --force to append."
            )
        staged_output = stage_root / output.name
        if output_format == "folder":
            if dry_run:
                long_path(staged_output).mkdir(parents=True, exist_ok=True)
                rows, stats = dry_run_records(backup_dir, db_path, output_layout, domain_map)
            else:
                rows, stats = reconstruct_to_folder(
                    backup_dir,
                    db_path,
                    staged_output,
                    encrypted,
                    keybag,
                    output_layout,
                    domain_map,
                    report_root=output,
                    progress=progress,
                    cancel=cancel,
                )
            provenance = provenance_for(stats)
            if stats["failed"] and not continue_on_error and not stats["cancelled"]:
                fail_closed(provenance, rows)
            write_trace_folder(staged_output, provenance, rows)
            promote_folder_output(staged_output, output)
        else:
            reserved = (ROOT_MANIFEST_DB_NAME, ENRICHED_MANIFEST_NAME, ROOT_TRACEABILITY_TEXT_NAME)
            with FfsZipWriter(staged_output, reserved) as writer:
                if dry_run:
                    rows, stats = dry_run_records(backup_dir, db_path, output_layout, domain_map, writer.claimed)
                else:
                    rows, stats = reconstruct_to_zip(
                        backup_dir,
                        db_path,
                        writer,
                        encrypted,
                        keybag,
                        output_layout,
                        domain_map,
                        progress=progress,
                        cancel=cancel,
                    )
                provenance = provenance_for(stats)
                if stats["failed"] and not continue_on_error and not stats["cancelled"]:
                    fail_closed(provenance, rows)
                write_ios_root_artefacts(writer, db_path, provenance, rows, output.name)
            promote_zip_output(staged_output, output, force)
            archive_sha256, _ = write_zip_sha256_sidecar(output)
    finally:
        remove_staging_dir(stage_root)
        if tmp_dir:
            tmp_dir.cleanup()
    return ReconstructionResult(
        output=output,
        output_format=output_format,
        output_layout=output_layout,
        encrypted=encrypted,
        stats=stats,
        dry_run=dry_run,
        cancelled=bool(stats["cancelled"]),
        archive_sha256=archive_sha256,
    )
