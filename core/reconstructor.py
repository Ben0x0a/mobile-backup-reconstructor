#!/usr/bin/env python3
"""Reconstruct files from an iOS local backup, and dispatch Android backups.

Defines: keybag parsing and decryption, `Manifest.db` traversal, domain-to-path
mapping, the iOS reconstruction pipeline (folder and Full File System-like zip),
traceability output, and the CLI argument parser. An Android `.ab` input is
recognised by its header and handed to core.android_reconstructor.
Used by: launcher.cli, gui.interface, core.decryptor, core.android_reconstructor, tests.
Depends on: config.settings, config/domain_maps (package data), core.models,
core.output_paths, core.ffs_archive, core.android_backup (lazily).

The input backup is never modified. For encrypted backups, decrypted content is
written only to the requested output folder or zip archive.
"""

from __future__ import annotations

import argparse
import atexit
import csv
import getpass
import hashlib
import io
import json
import logging
import os
import platform
import plistlib
import shutil
import sqlite3
import struct
import sys
import tempfile
from collections.abc import Callable, Iterable, Iterator
from contextlib import ExitStack
from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import as_file, files
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Protocol

from config.settings import (
    CHUNK_SIZE,
    DEFAULT_BACKUP_PASSWORDS,
    DEFAULT_OUTPUT_LAYOUT,
    ENRICHED_MANIFEST_NAME,
    ENRICHED_ZIP_PATH_COLNAME,
    FAILURE_REPORT_DIR_NAME,
    FFS_LAYOUT,
    OPTIONAL_BACKUP_FILES,
    OUTPUT_LAYOUTS,
    REQUIRED_BACKUP_FILES,
    ROOT_MANIFEST_DB_NAME,
    ROOT_TRACEABILITY_TEXT_NAME,
    TOOL_NAME,
    TOOL_VERSION,
    TRACEABILITY_DIR_NAME,
    TRACEABILITY_FILE_MANIFEST_NAME,
    TRACEABILITY_PROVENANCE_NAME,
)
from core.ffs_archive import (
    FfsZipWriter,
    TraceSection,
    sidecar_path,
    write_root_traceability_text,
    write_zip_sha256_sidecar,
)
from core.models import FileRecord, ReconstructionResult
from core.output_paths import (
    WINDOWS_MAX_PATH,
    claim_unique_path,
    exceeds_windows_max_path,
    long_path,
    safe_join_path,
    safe_output_path,
    sanitise_segment,  # noqa: F401 - re-exported: part of this module's public surface
)

_LOG = logging.getLogger(__name__)

DIRECTORY_FLAG = 2
ZERO_IV = b"\x00" * 16
KEYBAG_CLASSKEY_TAGS = {b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"}
WRAP_PASSCODE = 2
DomainMap = dict[str, Any]

# (files_done, files_total, current_output_path) -> None. Cosmetic only; see
# report_progress. A bare callable so core imports no UI toolkit.
ProgressCallback = Callable[[int, int, str], None]


class CancelEvent(Protocol):
    """The subset of `threading.Event` the pipeline needs to support cancellation."""

    def is_set(self) -> bool: ...


# Keeps resources materialised by `as_file` alive for the life of the process.
# WHY: `as_file` deletes what it extracted when its context exits, so a path
# returned from inside a `with` block is already gone by the time it is used.
_RESOURCE_STACK = ExitStack()
atexit.register(_RESOURCE_STACK.close)


@lru_cache(maxsize=1)
def default_domain_map_path() -> Path:
    """Locate the shipped domain-map directory.

    HOW: resolves ``config/domain_maps`` through importlib.resources, keeping
    any extracted copy open on a process-lifetime ExitStack.
    WHY: ``Path(__file__).parents[1]`` breaks when the package is installed
    into a zip, frozen by PyInstaller, or used as a namespace package.
    """
    resource = files("config").joinpath("domain_maps")
    return Path(_RESOURCE_STACK.enter_context(as_file(resource)))


class BackupError(Exception):
    """Raised for expected backup parsing and reconstruction failures."""


class MissingCryptoError(BackupError):
    """Raised when encrypted backup handling needs the optional dependency."""


class ReconstructionFailedError(BackupError):
    """Raised when reconstruction processed rows but at least one row failed."""

    def __init__(self, message: str, report_path: Path | None = None) -> None:
        super().__init__(message)
        self.report_path = report_path


def require_crypto() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    except ImportError as exc:
        raise MissingCryptoError(
            "Encrypted backups require the 'cryptography' package. "
            f"It is not available to the current Python interpreter: {sys.executable}. "
            "Install and run with: uv sync; uv run python main.py, or "
            "activate the virtual environment before launching."
        ) from exc
    return Cipher, algorithms, modes, aes_key_unwrap


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tlv_blocks(blob: bytes) -> Iterator[tuple[bytes, bytes]]:
    offset = 0
    while offset + 8 <= len(blob):
        tag = blob[offset : offset + 4]
        length = struct.unpack(">L", blob[offset + 4 : offset + 8])[0]
        start = offset + 8
        end = start + length
        if end > len(blob):
            raise BackupError(f"Malformed keybag TLV block {tag!r}: length exceeds blob")
        yield tag, blob[start:end]
        offset = end
    if offset != len(blob):
        raise BackupError("Malformed keybag TLV data: trailing bytes")


class Keybag:
    def __init__(self, data: bytes) -> None:
        self.attrs: dict[bytes, Any] = {}
        self.class_keys: dict[int, dict[bytes, Any]] = {}
        self._parse(data)

    def _parse(self, data: bytes) -> None:
        """Split the TLV stream into header attributes and per-class key records.

        HOW: walks the records in order. Everything before the first `CLAS` is a
        header attribute; each `CLAS` starts a new protection-class record, and the
        class tags that follow belong to it until the next `CLAS`.

        WHY `CLAS` delimits rather than `UUID`: a real keybag carries a per-class
        `UUID` before each `CLAS`, and delimiting on that appears to work — but a
        keybag written without those per-class UUIDs then yields NO class keys at
        all, and the failure surfaces as "check the backup password" when the
        password was right. `CLAS` is the tag that actually defines a class, so it
        is the one that delimits. Per-class `UUID`/`KTYP`/`PBKY` are not needed for
        an offline unwrap.
        """
        current: dict[bytes, Any] | None = None
        for tag, value in tlv_blocks(data):
            parsed: Any = struct.unpack(">L", value)[0] if len(value) == 4 else value
            if tag == b"CLAS":
                if current:
                    self._store_class_key(current)
                current = {tag: parsed}
                continue
            if current is not None and tag in KEYBAG_CLASSKEY_TAGS:
                current[tag] = parsed
                continue
            # A `UUID` seen inside the class section belongs to that class and is
            # not needed; keeping the header's own UUID means not overwriting it.
            if tag == b"UUID" and (current is not None or tag in self.attrs):
                continue
            self.attrs[tag] = parsed
        if current:
            self._store_class_key(current)

    def _store_class_key(self, class_key: dict[bytes, Any]) -> None:
        protection_class = class_key.get(b"CLAS")
        if not isinstance(protection_class, int):
            raise BackupError("Malformed keybag: class key missing CLAS")
        self.class_keys[protection_class] = class_key

    def unlock(self, password: str) -> None:
        _, _, _, aes_key_unwrap = require_crypto()
        try:
            dpsl = self.attrs[b"DPSL"]
            dpic = self.attrs[b"DPIC"]
            salt = self.attrs[b"SALT"]
            iterations = self.attrs[b"ITER"]
        except KeyError as exc:
            raise BackupError("Backup keybag is missing password derivation parameters") from exc

        password_bytes = password.encode("utf-8")
        passcode1 = hashlib.pbkdf2_hmac("sha256", password_bytes, dpsl, dpic, 32)
        passcode_key = hashlib.pbkdf2_hmac("sha1", passcode1, salt, iterations, 32)

        # No class keys means the walk found nothing to unwrap. Reporting that as
        # a bad password would send an examiner hunting for the wrong problem.
        if not self.class_keys:
            raise BackupError("Backup keybag contains no protection-class keys (malformed keybag)")

        failures = []
        for protection_class, class_key in self.class_keys.items():
            wrapped_key = class_key.get(b"WPKY")
            wrap_flags = class_key.get(b"WRAP", 0)
            if not isinstance(wrapped_key, bytes):
                failures.append(protection_class)
                continue
            if wrap_flags & WRAP_PASSCODE:
                try:
                    class_key[b"KEY"] = aes_key_unwrap(passcode_key, wrapped_key)
                except Exception:
                    failures.append(protection_class)
            else:
                class_key[b"KEY"] = wrapped_key
        if failures:
            raise BackupError("Could not unlock backup keybag. Check the backup password.")

    def unwrap_key(self, protection_class: int, persistent_key: bytes) -> bytes:
        _, _, _, aes_key_unwrap = require_crypto()
        class_key = self.class_keys.get(protection_class)
        if not class_key or b"KEY" not in class_key:
            raise BackupError(f"No unlocked key for protection class {protection_class}")
        try:
            return aes_key_unwrap(class_key[b"KEY"], persistent_key)
        except Exception as exc:
            raise BackupError(f"Could not unwrap key for class {protection_class}") from exc


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    Cipher, algorithms, modes, _ = require_crypto()
    if len(data) % 16:
        raise BackupError("Encrypted data length is not a multiple of AES block size")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def strip_pkcs7_if_present(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or pad_len > len(data):
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def decrypt_manifest_db(backup_dir: Path, manifest: dict[str, Any], keybag: Keybag) -> bytes:
    manifest_key_blob = manifest.get("ManifestKey")
    if not isinstance(manifest_key_blob, bytes) or len(manifest_key_blob) < 8:
        raise BackupError("Manifest.plist does not contain a valid ManifestKey")
    protection_class = struct.unpack("<L", manifest_key_blob[:4])[0]
    manifest_key = keybag.unwrap_key(protection_class, manifest_key_blob[4:])
    encrypted = (backup_dir / "Manifest.db").read_bytes()
    decrypted = strip_pkcs7_if_present(aes_cbc_decrypt(encrypted, manifest_key))
    if not decrypted.startswith(b"SQLite format 3\x00"):
        raise BackupError("Decrypted Manifest.db does not look like SQLite")
    return decrypted


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


def parse_simple_domain_yaml(path: Path) -> DomainMap:
    sections = {"exact_domains": {}, "prefix_domains": {}}
    parsed: DomainMap = {**sections, "unknown_domain_template": "unknown_backup_domains/{domain}"}
    current_section: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw_line.startswith((" ", "\t")) and line.endswith(":"):
            current_section = line[:-1].strip()
            if current_section not in parsed:
                parsed[current_section] = {}
            continue
        if not raw_line.startswith((" ", "\t")) and ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip()] = value.strip().strip("'\"")
            current_section = None
            continue
        if current_section is not None and ":" in line:
            key, value = line.split(":", 1)
            parsed[current_section][key.strip().strip("'\"")] = value.strip().strip("'\"")
            continue
        raise BackupError(f"Unsupported domain mapping YAML line in {path}: {raw_line}")
    return parsed


def parse_version_tuple(version: str | None) -> tuple[int, ...] | None:
    if not version:
        return None
    parts: list[int] = []
    for part in str(version).split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else None


def compare_versions(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def ios_version_matches_range(version: str | None, ios_range: Any) -> bool:
    parsed_version = parse_version_tuple(version)
    if parsed_version is None:
        return True
    if not isinstance(ios_range, dict):
        return True
    min_version = parse_version_tuple(ios_range.get("min"))
    max_version = parse_version_tuple(ios_range.get("max"))
    if min_version is not None and compare_versions(parsed_version, min_version) < 0:
        return False
    if max_version is not None and compare_versions(parsed_version, max_version) > 0:
        return False
    return True


def load_domain_map_yaml(map_path: Path) -> DomainMap:
    try:
        import yaml  # type: ignore
    except ImportError:
        data = parse_simple_domain_yaml(map_path)
    else:
        with map_path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            raise BackupError(f"Domain mapping file must contain a YAML mapping: {map_path}")
        data = loaded
    exact = data.get("exact_domains", {})
    prefixes = data.get("prefix_domains", {})
    unknown = data.get("unknown_domain_template", "unknown_backup_domains/{domain}")
    ios_versions = data.get("ios_versions", {})
    name = data.get("name", map_path.stem)
    if not isinstance(exact, dict) or not isinstance(prefixes, dict) or not isinstance(unknown, str):
        raise BackupError(f"Invalid domain mapping file structure: {map_path}")
    if ios_versions is None:
        ios_versions = {}
    if not isinstance(ios_versions, dict):
        raise BackupError(f"Invalid ios_versions header in domain mapping file: {map_path}")
    return {
        "name": str(name),
        "ios_versions": {str(k): str(v) for k, v in ios_versions.items()},
        "exact_domains": {str(k): str(v) for k, v in exact.items()},
        "prefix_domains": {str(k): str(v) for k, v in prefixes.items()},
        "unknown_domain_template": unknown,
        "path": str(map_path),
    }


def load_domain_mounts(path: Path | None = None, ios_version: str | None = None) -> DomainMap:
    map_path = (path or default_domain_map_path()).expanduser()
    if map_path.is_dir():
        candidates = sorted(p for p in map_path.iterdir() if p.suffix.lower() in (".yaml", ".yml"))
        if not candidates:
            raise BackupError(f"Domain mapping directory contains no YAML files: {map_path}")
        first_valid: DomainMap | None = None
        for candidate in candidates:
            domain_map = load_domain_map_yaml(candidate)
            if first_valid is None:
                first_valid = domain_map
            if ios_version_matches_range(ios_version, domain_map.get("ios_versions")):
                return domain_map
        if first_valid is not None:
            return first_valid
    if not map_path.is_file():
        raise BackupError(f"Domain mapping file or directory not found: {map_path}")
    return load_domain_map_yaml(map_path)


def filesystem_domain_root(domain: str, domain_map: DomainMap | None = None) -> str:
    domain_map = domain_map or load_domain_mounts()
    exact = domain_map["exact_domains"]
    if domain in exact:
        return exact[domain]
    for prefix, template in domain_map["prefix_domains"].items():
        if domain.startswith(prefix):
            suffix = domain[len(prefix) :]
            return str(template).format(domain=domain, suffix=suffix)
    return str(domain_map["unknown_domain_template"]).format(domain=domain)


def mapped_output_path(
    domain: str,
    relative_path: str,
    output_layout: str,
    domain_map: DomainMap | None = None,
) -> PurePosixPath:
    if output_layout == "backup":
        return safe_output_path(domain, relative_path)
    if output_layout == "filesystem":
        return safe_join_path(filesystem_domain_root(domain, domain_map), relative_path)
    raise BackupError(f"Unsupported output layout: {output_layout}")


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


def report_progress(progress: ProgressCallback | None, done: int, total: int, path: str) -> None:
    """Invoke `progress`, swallowing anything it raises.

    WHY guarded: progress reporting is cosmetic, and a caller's broken callback
    (a closed stream, a disposed Qt widget) must not abort a reconstruction that
    is otherwise succeeding and holding a partially written output.
    """
    if progress is None:
        return
    try:
        progress(done, total, path)
    except Exception:  # noqa: BLE001 - cosmetic reporting must never fail a run
        _LOG.debug("progress callback raised; continuing", exc_info=True)


def is_cancelled(cancel: CancelEvent | None) -> bool:
    """Whether the caller has asked to stop.

    WHY a returned flag rather than an exception: cancellation is an expected
    outcome, not a failure. The walk breaks out, the rows gathered so far are
    kept, and the run is recorded as `cancelled` — so a stopped reconstruction
    is still attributable evidence rather than a crash with no manifest.
    """
    return cancel is not None and cancel.is_set()


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


def file_key_for_record(record: FileRecord, keybag: Keybag) -> bytes | None:
    key_blob = plist_data_value(first_present(record.metadata, ("EncryptionKey", "encryptionKey")))
    if key_blob is None:
        return None
    protection_class = first_present(record.metadata, ("ProtectionClass", "protectionClass"))
    if not isinstance(protection_class, int):
        raise BackupError("Encrypted backup record has no protection class")
    if len(key_blob) <= 4:
        raise BackupError("Invalid file encryption key blob")
    return keybag.unwrap_key(protection_class, key_blob[4:])


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


def decrypt_copy(src: Path, dst: BinaryIO, key: bytes, limit: int | None) -> tuple[int, str, str]:
    Cipher, algorithms, modes, _ = require_crypto()
    src_digest = hashlib.sha256()
    out_digest = hashlib.sha256()
    written = 0
    decryptor = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV)).decryptor()
    trailing = b""
    with src.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            src_digest.update(chunk)
            data = trailing + chunk
            block_len = (len(data) // 16) * 16
            trailing = data[block_len:]
            if block_len:
                plain = decryptor.update(data[:block_len])
                plain = trim_to_limit(plain, written, limit)
                if plain:
                    dst.write(plain)
                    out_digest.update(plain)
                    written += len(plain)
    if trailing:
        raise BackupError("Encrypted file length is not a multiple of AES block size")
    final = decryptor.finalize()
    if final:
        final = trim_to_limit(final, written, limit)
        if final:
            dst.write(final)
            out_digest.update(final)
            written += len(final)
    return written, src_digest.hexdigest(), out_digest.hexdigest()


def trim_to_limit(data: bytes, written: int, limit: int | None) -> bytes:
    if limit is None:
        return data
    if written >= limit:
        return b""
    return data[: max(0, limit - written)]


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


def is_directory_record(record: FileRecord) -> bool:
    return bool(record.flags & DIRECTORY_FLAG)


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


def redact_password_args(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        if arg in ("--password", "-p"):
            redacted.append(arg)
            skip_next = True
            continue
        if arg.startswith("--password="):
            redacted.append("--password=<redacted>")
            continue
        redacted.append(arg)
    return redacted


def try_unlock_keybag(keybag_blob: bytes, password: str) -> Keybag:
    keybag = Keybag(keybag_blob)
    keybag.unlock(password)
    return keybag


def prepare_manifest_db(
    backup_dir: Path,
    encrypted: bool,
    manifest: dict[str, Any],
    password: str | None,
    allow_prompt: bool = True,
    try_default_passwords: bool = False,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None, Keybag | None]:
    """Return a readable `Manifest.db`, decrypting it first when necessary.

    `try_default_passwords` opts in to trying `DEFAULT_BACKUP_PASSWORDS` before
    prompting. WHY it is opt-in: guessing passwords, even from a four-entry list
    of acquisition-tool defaults, is an action an examiner should choose and be
    able to account for, not a silent default. Whether it was enabled is
    recorded in the provenance artefact.
    """
    if not encrypted:
        return backup_dir / "Manifest.db", None, None
    require_crypto()
    keybag_blob = manifest.get("BackupKeyBag")
    if not isinstance(keybag_blob, bytes):
        raise BackupError("Encrypted backup is missing BackupKeyBag")

    candidate_passwords: list[str] = []
    tried_defaults = False
    prompted = False
    if password:
        candidate_passwords.append(password)
    else:
        if try_default_passwords:
            candidate_passwords.extend(DEFAULT_BACKUP_PASSWORDS)
            tried_defaults = True
        # Prompt only on a real terminal. WHY: getpass raises EOFError when
        # stdin is a pipe or closed, which would escape as a traceback on a
        # perfectly legitimate non-interactive run (CI, cron, a shell pipeline).
        if allow_prompt and sys.stdin is not None and sys.stdin.isatty():
            try:
                candidate_passwords.append(getpass.getpass("Backup password: "))
                prompted = True
            except (EOFError, KeyboardInterrupt) as exc:
                raise BackupError("No backup password was entered.") from exc

    # With no password, no usable prompt and no opt-in there is nothing to try,
    # and an empty loop would otherwise report a misleading "could not unlock".
    if not candidate_passwords:
        raise BackupError(
            "This backup is encrypted and no password was supplied. Provide one, "
            "or pass --try-default-passwords to try common acquisition-tool defaults first."
        )

    last_error: Exception | None = None
    for candidate in candidate_passwords:
        try:
            keybag = try_unlock_keybag(keybag_blob, candidate)
            decrypted_db = decrypt_manifest_db(backup_dir, manifest, keybag)
            tmp = tempfile.TemporaryDirectory(prefix="mobile_backup_manifest_")
            tmp_db = Path(tmp.name) / "Manifest.db"
            tmp_db.write_bytes(decrypted_db)
            if tried_defaults and candidate in DEFAULT_BACKUP_PASSWORDS:
                _LOG.warning(f"Backup unlocked with the default password {candidate!r}")
            return tmp_db, tmp, keybag
        except BackupError as exc:
            last_error = exc

    if password:
        raise BackupError("Could not unlock backup keybag. Check the backup password.") from last_error
    sources = ["the default passwords"] if tried_defaults else []
    if prompted:
        sources.append("the entered password")
    raise BackupError(f"Could not unlock backup keybag with {' or '.join(sources)}.") from last_error


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
            dir_name = writer.add_directory(arcname)
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reconstruct an iOS backup (Manifest.db) or an Android adb backup (.ab) into a "
            "structure like a Full File System acquisition, decrypting encrypted backups."
        )
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("backup", type=Path, help="An iOS backup directory, its Manifest.plist, or an Android .ab file")
    parser.add_argument("output", type=Path, help="Output folder or zip path")
    parser.add_argument(
        "--format",
        choices=("auto", "folder", "zip"),
        default="auto",
        help=(
            "Output format. The filesystem layout is always a zip; for the backup layout, "
            "auto uses zip on Windows and folder elsewhere."
        ),
    )
    parser.add_argument(
        "--mode",
        choices=("rebuild", "decrypt"),
        default="rebuild",
        help=(
            "rebuild reconstructs the backup into a directory tree (decrypting first "
            "when needed); decrypt produces the same backup with its content in the "
            "clear, keeping the hash-addressed layout."
        ),
    )
    parser.add_argument(
        "--layout",
        choices=OUTPUT_LAYOUTS,
        default=DEFAULT_OUTPUT_LAYOUT,
        help=(
            "Output layout: filesystem rebuilds a structure like a Full File System acquisition "
            "(always a zip); backup keeps iOS backup domains."
        ),
    )
    parser.add_argument(
        "--domain-map",
        type=Path,
        default=None,
        help=(
            "YAML file or directory of domain-to-filesystem mappings (iOS), or an Android "
            "path-map YAML file (.ab). Defaults to the shipped maps."
        ),
    )
    parser.add_argument("--force", action="store_true", help="Allow appending to an output folder or replacing a zip.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Write only traceability/planned output paths; do not reconstruct file contents.",
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Produce output for successful files even if some rows fail. Failed rows remain in traceability.",
    )
    parser.add_argument(
        "--try-default-passwords",
        action="store_true",
        help="Before prompting, try the backup passwords commonly set by acquisition tools.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress the progress counter.")
    parser.add_argument("--verbose", action="store_true", help="Log debug-level diagnostics to stderr.")
    parser.add_argument(
        "--info-only",
        action="store_true",
        help="Inspect manifests and print backup metadata without reconstructing files.",
    )
    return parser.parse_args(argv)


def inspect_backup(backup: Path) -> dict[str, Any]:
    from core.android_backup import inspect_android_backup, is_android_backup

    if is_android_backup(backup.expanduser()):
        return inspect_android_backup(backup.expanduser())
    backup_dir = resolve_backup_dir(backup)
    manifest = read_plist(backup_dir / "Manifest.plist")
    info = read_optional_plist(backup_dir / "Info.plist")
    return {
        "backup": str(backup_dir),
        "platform": "ios",
        "encrypted": bool(manifest.get("IsEncrypted", False)),
        "absent_files": missing_optional_files(backup_dir),
        "device": first_present(info, ("Device Name", "Display Name")),
        "product": info.get("Product Name"),
        "ios": first_present(info, ("Product Version", "ProductVersion")),
        "date": str(manifest.get("Date")),
    }


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


def promote_folder_output(staged_output: Path, final_output: Path) -> None:
    # Both ends go through the extended-length form: the staged tree can already
    # hold paths over Windows' limit, and so can the destination.
    staged_output = long_path(staged_output)
    if final_output.exists():
        shutil.copytree(staged_output, long_path(final_output), dirs_exist_ok=True)
    else:
        final_output.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(staged_output), str(long_path(final_output)))


def promote_zip_output(staged_output: Path, final_output: Path, force: bool) -> None:
    if final_output.exists():
        if not force:
            raise BackupError(f"Output zip already exists: {final_output}")
        final_output.unlink()
    final_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(long_path(staged_output)), str(long_path(final_output)))


def make_staging_dir(output_parent: Path) -> Path:
    """A private staging directory beside the destination, so promotion is a rename."""
    return Path(tempfile.mkdtemp(prefix="mobile_backup_output_", dir=output_parent))


def remove_staging_dir(stage_root: Path) -> None:
    """Delete the staging directory through the extended-length path.

    WHY not `TemporaryDirectory.cleanup()`: it removes the tree through the
    plain path, so on Windows a staged tree holding paths over 260 characters
    (a folder run appended with --force, or one that failed) could not be
    deleted and the cleanup itself raised over an otherwise finished run.
    """
    try:
        shutil.rmtree(long_path(stage_root))
    except FileNotFoundError:
        pass
    except OSError as exc:
        _LOG.warning(f"Could not remove the staging directory {stage_root}: {exc}")


def reconstruct_backup(
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
    """Reconstruct an iOS backup directory or an Android `.ab` file.

    The platform is decided from the input's content (the `.ab` header), not
    its name; an Android backup is handed over to core.android_reconstructor
    with the same arguments.
    """
    from core.android_backup import is_android_backup

    if is_android_backup(backup.expanduser()):
        from core.android_reconstructor import reconstruct_android_backup

        return reconstruct_android_backup(
            backup.expanduser(),
            output,
            output_format,
            password,
            force,
            command,
            allow_password_prompt,
            output_layout,
            domain_map_path,
            dry_run,
            continue_on_error,
            try_default_passwords,
            progress=progress,
            cancel=cancel,
        )

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


def tty_progress_reporter() -> ProgressCallback | None:
    """A one-line stderr counter, or None when stderr is not a terminal.

    WHY TTY-only and on stderr: the carriage-return rewrite is noise in a log file
    or a pipe, and stdout is reserved for the JSON result so `... | jq` keeps
    working.
    """
    if not sys.stderr.isatty():
        return None

    def report(done: int, total: int, path: str) -> None:
        shown = path if len(path) <= 60 else f"...{path[-57:]}"
        # total is 0 when it cannot be known up front (an .ab is a tar stream).
        counter = f"{done}/{total}" if total > 0 else f"{done}"
        print(f"\r  {counter}  {shown:<60}", end="", file=sys.stderr, flush=True)

    return report


def reject_conflicting_mode_flags(args: argparse.Namespace, raw_args: list[str]) -> None:
    """Refuse flags that have no meaning in the chosen mode.

    WHY an error rather than a silent no-op: an operator who passes
    `--mode decrypt --layout filesystem` believes they asked for a filesystem
    layout. Ignoring it would hand them an output they did not ask for and had no
    way to notice.
    """
    if args.mode != "decrypt":
        return
    from core.android_backup import is_android_backup

    if is_android_backup(args.backup.expanduser()):
        raise BackupError(
            "--mode decrypt applies to iOS backups only. An encrypted Android backup is "
            "decrypted as part of the reconstruction: use the default --mode rebuild."
        )
    passed = {arg.split("=", 1)[0] for arg in raw_args}
    for flag, reason in (
        ("--layout", "the output keeps the backup's own hash-addressed layout"),
        ("--domain-map", "no domain mapping is applied"),
        ("--format", "the output is always a folder"),
    ):
        if flag in passed:
            raise BackupError(f"{flag} has no effect with --mode decrypt: {reason}.")


def main(argv: list[str] | None = None) -> int:
    raw_args = sys.argv[1:] if argv is None else argv
    command = redact_password_args([sys.argv[0], *raw_args])
    args = parse_args(raw_args)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        if args.info_only:
            print(json.dumps(inspect_backup(args.backup), indent=2, sort_keys=True))
            return 0

        reject_conflicting_mode_flags(args, raw_args)
        progress = None if args.dry_run or args.quiet else tty_progress_reporter()

        if args.mode == "decrypt":
            from core.decryptor import decrypt_backup

            decrypted = decrypt_backup(
                args.backup,
                args.output,
                None,
                args.force,
                command,
                True,
                args.try_default_passwords,
                progress=progress,
            )
            if progress is not None:
                print(file=sys.stderr)
            print(json.dumps(decrypted.as_dict(), indent=2, sort_keys=True))
            if decrypted.cancelled:
                _LOG.warning("Cancelled; the output is incomplete and is not a usable backup")
                return 3
            if decrypted.stats["failed"]:
                _LOG.warning(f"{decrypted.stats['failed']} file(s) failed; see the file manifest")
                return 2
            return 0

        result = reconstruct_backup(
            args.backup,
            args.output,
            args.format,
            None,
            args.force,
            command,
            True,
            args.layout,
            args.domain_map,
            args.dry_run,
            args.continue_on_error,
            args.try_default_passwords,
            progress=progress,
        )
        if progress is not None:
            print(file=sys.stderr)  # close the counter line before the result
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
        if result.stats.get("long_paths"):
            _LOG.warning(
                f"{result.stats['long_paths']} output path(s) exceed Windows' "
                f"{WINDOWS_MAX_PATH}-character limit. They were written correctly, but a tool "
                "that does not handle long paths will not be able to open them."
            )
        if result.cancelled:
            _LOG.warning("Cancelled; the output is incomplete and is recorded as cancelled")
            return 3
        if result.stats["failed"]:
            _LOG.warning(f"{result.stats['failed']} row(s) failed; see the file manifest")
            return 2
        return 0
    except BackupError as exc:
        _LOG.error(f"{exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
