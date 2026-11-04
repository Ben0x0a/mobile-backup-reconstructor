"""Reading an iOS backup directory and its `Manifest.db`.

Defines: backup-directory validation, plist reading, `Files.file` metadata
decoding (NSKeyedArchiver), the streaming `Manifest.db` walk and its
`FileRecord`s, and the product-version lookup.
Used by: core.ios_crypto, core.ios_reconstructor, core.ios_traceability,
core.reconstructor, core.decryptor.
Depends on: core.errors, core.ios_domain_map, core.models, config.settings.

The backup is only ever read.
"""

from __future__ import annotations

import os
import plistlib
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from config.settings import (
    OPTIONAL_BACKUP_FILES,
    REQUIRED_BACKUP_FILES,
)
from core.errors import BackupError
from core.ios_domain_map import DomainMap, mapped_output_path
from core.models import FileRecord

DIRECTORY_FLAG = 2


def read_plist(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        value = plistlib.load(fh)
    if not isinstance(value, dict):
        raise BackupError(f"{path.name} is not a plist dictionary")
    return value


def read_optional_plist(path: Path) -> dict[str, Any]:
    """Read a plist that a backup may legitimately not have, or `{}` if absent.

    A present-but-malformed file still raises: a missing file is an older backup,
    a corrupt one is a problem the operator needs to know about.
    """
    if not path.is_file():
        return {}
    return read_plist(path)


def missing_optional_files(backup_dir: Path) -> list[str]:
    """Which provenance-only files this backup does not carry."""
    return [name for name in OPTIONAL_BACKUP_FILES if not (backup_dir / name).is_file()]


def resolve_backup_dir(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path.is_file() and path.name == "Manifest.plist":
        path = path.parent
    if not path.is_dir():
        raise BackupError(f"Backup path is not a directory: {path}")
    # Only Manifest.plist and Manifest.db are required. Info.plist and Status.plist
    # carry provenance that older backups may simply not have, and nothing in
    # reconstruction or decryption reads them — so demanding them rejected backups
    # this tool can handle. Their absence is reported in the provenance artefact.
    for name in REQUIRED_BACKUP_FILES:
        if not (path / name).is_file():
            raise BackupError(f"Missing required backup file: {name}")
    ensure_readable(path)
    return path


def ensure_readable(backup_dir: Path) -> None:
    """Fail early, and legibly, when the backup's files cannot be read.

    WHY here rather than letting the open fail: an acquisition tool that strips
    permissions leaves every file mode 000, and the resulting `PermissionError`
    surfaced as a traceback from deep inside the pipeline. Checking up front turns
    that into one sentence naming the cause and the fix.
    """
    unreadable = [
        name
        for name in (*REQUIRED_BACKUP_FILES, *OPTIONAL_BACKUP_FILES)
        if (backup_dir / name).is_file() and not os.access(backup_dir / name, os.R_OK)
    ]
    if not unreadable:
        return
    raise BackupError(
        f"Cannot read {', '.join(unreadable)} in {backup_dir}: permission denied. "
        "Some acquisition tools write the backup with no read permission at all "
        "(mode 000). Grant yourself read access on a WORKING COPY rather than the "
        "original evidence, for example: "
        f"cp -R '{backup_dir}' /path/to/copy && chmod -R u+rX /path/to/copy"
    )


def first_present(mapping: dict[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def decode_nskeyed(value: Any) -> Any:
    if not isinstance(value, dict) or "$objects" not in value or "$top" not in value:
        return value
    objects = value["$objects"]

    def decode(obj: Any) -> Any:
        if isinstance(obj, plistlib.UID):
            if obj.data >= len(objects):
                return None
            return decode(objects[obj.data])
        if isinstance(obj, dict):
            return {key: decode(val) for key, val in obj.items() if key != "$class"}
        if isinstance(obj, list):
            return [decode(item) for item in obj]
        return obj

    top = value["$top"]
    if isinstance(top, dict) and "root" in top:
        return decode(top["root"])
    return decode(top)


def parse_file_metadata(blob: bytes | None) -> dict[str, Any]:
    if not blob:
        return {}
    try:
        parsed = plistlib.loads(blob)
    except Exception:
        return {}
    decoded = decode_nskeyed(parsed)
    return decoded if isinstance(decoded, dict) else {}


def metadata_size(metadata: dict[str, Any]) -> int | None:
    value = first_present(metadata, ("Size", "size"))
    if isinstance(value, int) and value >= 0:
        return value
    return None


def metadata_mtime(metadata: dict[str, Any]) -> datetime | None:
    value = first_present(metadata, ("LastModified", "LastModifiedDate", "Modified", "mtime"))
    if isinstance(value, datetime):
        return value
    return None


def plist_data_value(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        nested = value.get("NS.data")
        return nested if isinstance(nested, bytes) else None
    return None


def source_path_for_file_id(backup_dir: Path, file_id: str) -> Path:
    nested = backup_dir / file_id[:2] / file_id
    if nested.exists():
        return nested
    return backup_dir / file_id


def count_manifest_rows(db_path: Path) -> int:
    """Total rows in the `Files` table, for progress reporting.

    WHY a separate cheap COUNT rather than materialising the rows: the walk is a
    streaming cursor over a manifest that can hold hundreds of thousands of rows,
    and a progress bar needs its denominator before the first file is written.
    """
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM Files").fetchone()[0])
    finally:
        conn.close()


def iter_manifest_rows(db_path: Path) -> Iterator[tuple[str, str, str, int, bytes | None]]:
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    try:
        # ORDER BY the logical name, not the table's own row order.
        #
        # WHY: the order decides which of two colliding output paths keeps the
        # unsuffixed name (see claim_unique_path). Table order depends on SQLite
        # internals, so a manifest rewritten by another tool could reorder the
        # same content and move the `~1`. Sorting makes the output reproducible,
        # and matches mf-scan's rule so the two tools produce the same tree.
        # SQLite does the sort, so the walk stays streaming.
        query = "SELECT fileID, domain, relativePath, flags, file FROM Files ORDER BY domain || '/' || relativePath"
        for file_id, domain, rel_path, flags, file_blob in conn.execute(query):
            if not file_id or not domain:
                continue
            yield str(file_id), str(domain), str(rel_path or ""), int(flags or 0), file_blob
    finally:
        conn.close()


def iter_file_records(
    backup_dir: Path,
    db_path: Path,
    output_layout: str = "backup",
    domain_map: DomainMap | None = None,
) -> Iterator[FileRecord]:
    for file_id, domain, relative_path, flags, file_blob in iter_manifest_rows(db_path):
        metadata = parse_file_metadata(file_blob)
        yield FileRecord(
            file_id=file_id,
            domain=domain,
            relative_path=relative_path,
            flags=flags,
            metadata=metadata,
            source_path=source_path_for_file_id(backup_dir, file_id),
            output_path=mapped_output_path(domain, relative_path, output_layout, domain_map),
        )


def is_directory_record(record: FileRecord) -> bool:
    return bool(record.flags & DIRECTORY_FLAG)


def backup_product_version(info: dict[str, Any], manifest: dict[str, Any]) -> str | None:
    value = first_present(info, ("Product Version", "ProductVersion"))
    if isinstance(value, str):
        return value
    lockdown = manifest.get("Lockdown")
    if isinstance(lockdown, dict):
        value = first_present(lockdown, ("ProductVersion", "Product Version"))
        if isinstance(value, str):
            return value
    return None
