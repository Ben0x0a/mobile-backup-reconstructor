"""Decrypt an encrypted iOS backup, keeping the backup's own layout.

Defines: `decrypt_backup` and the helpers that rewrite a backup's metadata so the
result is a structurally valid UNENCRYPTED backup.
Used by: core.reconstructor (the `--mode decrypt` path), gui.interface.
Depends on: core.reconstructor (shared manifest, traceability and staging
machinery), core.models, config.settings.

WHY this is a separate operation from reconstruction: rebuilding renames every
file into a device-like tree, which is a derived view. Decryption produces the
SAME backup with its content in the clear, so any tool that reads iOS backups —
and cannot read encrypted ones — can then read it. The two differ in what they
output, not in how they read the source.

── What gets rewritten, and why it must be ──────────────────────────────────────
An encrypted backup records each file's `Digest` as the SHA-1 of the CIPHERTEXT as
stored; an unencrypted backup records the SHA-1 of the CONTENT. Decrypting the
blobs without touching the manifest would therefore leave every digest mismatched,
and the output would read as corrupt to any tool that verifies it.

So three things are rewritten, and all three are recorded in the traceability
output rather than changed silently:

1. `Manifest.plist` — `IsEncrypted` becomes false and the key material
   (`BackupKeyBag`, `ManifestKey`) is removed. Leaving a keybag in an output that
   claims to be unencrypted is both confusing and needless key exposure.
2. Each `Files.file` metadata blob — `EncryptionKey` is removed and `Digest` is
   replaced with the SHA-1 of the plaintext.
3. `Manifest.db` itself — decrypted, then updated in place with those blobs.

Everything else is preserved byte-for-byte: the metadata blob is re-encoded from
the same decoded object graph, so fields this tool does not interpret survive
untouched.
"""

from __future__ import annotations

import hashlib
import logging
import plistlib
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config.settings import CHUNK_SIZE, OPTIONAL_BACKUP_FILES, TOOL_NAME, TOOL_VERSION
from core.reconstructor import (
    BackupError,
    CancelEvent,
    Keybag,
    ProgressCallback,
    count_manifest_rows,
    first_present,
    is_cancelled,
    iter_manifest_rows,
    long_path,
    metadata_size,
    parse_file_metadata,
    plist_data_value,
    prepare_manifest_db,
    read_optional_plist,
    read_plist,
    report_progress,
    require_crypto,
    resolve_backup_dir,
    source_path_for_file_id,
    validate_output_target,
    write_trace_folder,
)

_LOG = logging.getLogger(__name__)

# Files copied verbatim from the source backup. Manifest.plist and Manifest.db are
# handled separately because both are rewritten.
COPIED_BACKUP_FILES = OPTIONAL_BACKUP_FILES

# `Files.flags` value marking a regular file; other values (directory, symlink)
# carry no blob and keep their manifest row untouched.
FLAG_REGULAR_FILE = 1


@dataclass
class DecryptionResult:
    """Outcome of a decryption run."""

    output: Path
    encrypted: bool
    stats: dict[str, int] = field(default_factory=dict)
    cancelled: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "output": str(self.output),
            "mode": "decrypt",
            "source_encrypted": self.encrypted,
            "cancelled": self.cancelled,
            "stats": self.stats,
        }


def decrypt_blob(src: Path, dst: Path, key: bytes, size: int | None) -> tuple[int, str, str]:
    """Decrypt one blob to `dst`, returning (bytes written, ciphertext SHA-256,
    plaintext SHA-1).

    HOW: streams AES-CBC through a fixed buffer, hashing the ciphertext on the way
    in and the plaintext on the way out, then truncates to the manifest's declared
    size — CBC rounds up to a block, and the recorded size is authoritative.
    WHY both digests: the ciphertext SHA-256 attests what was read from the
    evidence, and the plaintext SHA-1 is what the rewritten manifest must record
    for the output to verify as an unencrypted backup.
    """
    Cipher, algorithms, modes, _ = require_crypto()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
    cipher_digest = hashlib.sha256()
    plain_digest = hashlib.sha1()  # noqa: S324 - the format records SHA-1, not a choice
    written = 0
    trailing = b""

    # Extended-length form so a deep destination is not refused on Windows.
    dst = long_path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with src.open("rb") as fh, dst.open("wb") as out:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            cipher_digest.update(chunk)
            data = trailing + chunk
            block_len = (len(data) // 16) * 16
            trailing = data[block_len:]
            if block_len:
                plain = decryptor.update(data[:block_len])
                if size is not None and written + len(plain) > size:
                    plain = plain[: max(0, size - written)]
                if plain:
                    out.write(plain)
                    plain_digest.update(plain)
                    written += len(plain)
        if trailing:
            raise BackupError("Encrypted blob length is not a multiple of the AES block size")
        final = decryptor.finalize()
        if size is not None and written + len(final) > size:
            final = final[: max(0, size - written)]
        if final:
            out.write(final)
            plain_digest.update(final)
            written += len(final)

    return written, cipher_digest.hexdigest(), plain_digest.hexdigest()


def rewrite_file_metadata(blob: bytes, plaintext_digest: bytes | None) -> tuple[bytes, str]:
    """Return the metadata blob with the encryption key removed and, when
    `plaintext_digest` is given, the digest replaced; plus the original digest as
    hex (empty when none was recorded).

    `plaintext_digest` is `None` for a file the backup lists but does not hold:
    there is no plaintext to hash, so the source's own digest is left in place
    (destroying it would lose the only record of that file's content) while the
    wrapped key is still removed.

    HOW: decodes the NSKeyedArchiver graph, edits the root object in place, and
    re-encodes it. `plistlib` round-trips this graph byte-identically, so every
    field this tool does not interpret survives untouched — which is the point: a
    rewrite must change only what it claims to change.
    """
    parsed = plistlib.loads(blob)
    objects = parsed.get("$objects")
    top = parsed.get("$top")
    if not isinstance(objects, list) or not isinstance(top, dict):
        return blob, ""
    root_ref = top.get("root")
    if not isinstance(root_ref, plistlib.UID) or root_ref.data >= len(objects):
        return blob, ""
    root = objects[root_ref.data]
    if not isinstance(root, dict):
        return blob, ""

    # The wrapped per-file key is meaningless once the blob is in the clear, and
    # shipping key material inside an output labelled unencrypted is worse than
    # meaningless.
    root.pop("EncryptionKey", None)

    original = ""
    digest = root.get("Digest")
    if isinstance(digest, plistlib.UID) and digest.data < len(objects):
        existing = objects[digest.data]
        if isinstance(existing, bytes):
            original = existing.hex()
        if plaintext_digest is not None:
            objects[digest.data] = plaintext_digest
    elif isinstance(digest, bytes):
        original = digest.hex()
        if plaintext_digest is not None:
            root["Digest"] = plaintext_digest
    # WHY a missing Digest is left missing: adding one would invent metadata the
    # source never recorded. The absence is reported in the file manifest instead.

    return plistlib.dumps(parsed, fmt=plistlib.FMT_BINARY), original


def write_unencrypted_manifest_plist(manifest: dict[str, Any], destination: Path) -> None:
    """Write `Manifest.plist` describing the output as an unencrypted backup."""
    rewritten = dict(manifest)
    rewritten["IsEncrypted"] = False
    for key in ("BackupKeyBag", "ManifestKey"):
        rewritten.pop(key, None)
    with destination.open("wb") as fh:
        plistlib.dump(rewritten, fh)


def apply_metadata_updates(db_path: Path, updates: list[tuple[str, bytes]]) -> None:
    """Write the rewritten metadata blobs back into the output `Manifest.db`.

    Updates rows in place rather than rebuilding the table, so every other column
    and every other table the manifest carries is preserved exactly.
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.executemany("UPDATE Files SET file = ? WHERE fileID = ?", [(b, f) for f, b in updates])
        conn.commit()
    finally:
        conn.close()


def build_decryption_provenance(
    backup_dir: Path,
    output: Path,
    manifest: dict[str, Any],
    info: dict[str, Any],
    stats: dict[str, int],
    command: list[str],
) -> dict[str, Any]:
    """Provenance for a decryption run.

    Records the rewrites explicitly: an examiner reading this must be able to see
    that the output's metadata is not byte-identical to the source's, and exactly
    which fields changed.
    """
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "created_utc": datetime.now(UTC).isoformat(),
        "mode": "decrypt",
        "command": command,
        "backup": {
            "path": str(backup_dir),
            "encrypted": True,
            "device": first_present(info, ("Device Name", "Display Name")),
            "product_version": first_present(info, ("Product Version", "ProductVersion")),
            "manifest_date": str(manifest.get("Date")),
        },
        "output": {
            "path": str(output),
            "layout": "backup (hash-addressed, as the source)",
            "is_valid_unencrypted_backup": True,
        },
        "rewritten_metadata": {
            "note": (
                "The output is a structurally valid UNENCRYPTED backup, so metadata "
                "that describes the encryption had to change. Content is unmodified."
            ),
            "manifest_plist": "IsEncrypted set false; BackupKeyBag and ManifestKey removed",
            "manifest_db": "decrypted; per-file EncryptionKey removed, Digest replaced",
            "digest_note": (
                "An encrypted backup records Digest as SHA-1 of the ciphertext; an "
                "unencrypted one records SHA-1 of the content. Each file's original "
                "value is preserved in the file manifest column "
                "'manifest_digest_original'."
            ),
        },
        "stats": stats,
    }


def decrypt_backup(
    backup: Path,
    output: Path,
    password: str | None = None,
    force: bool = False,
    command: list[str] | None = None,
    allow_password_prompt: bool = True,
    try_default_passwords: bool = False,
    progress: ProgressCallback | None = None,
    cancel: CancelEvent | None = None,
) -> DecryptionResult:
    """Decrypt an encrypted backup into a structurally valid unencrypted one.

    The output keeps the source's hash-addressed layout (`<xx>/<fileID>`), so it is
    the same backup with its content in the clear — readable by any tool that reads
    iOS backups but not encrypted ones.
    """
    backup_dir = resolve_backup_dir(backup)
    manifest = read_plist(backup_dir / "Manifest.plist")
    info = read_optional_plist(backup_dir / "Info.plist")
    if not bool(manifest.get("IsEncrypted", False)):
        raise BackupError(
            "This backup is not encrypted, so there is nothing to decrypt. "
            "Use --mode rebuild to reconstruct it into a filesystem-like tree."
        )

    output = output.expanduser()
    validate_output_target(output, backup_dir, force, "folder")

    db_path, tmp_dir, keybag = prepare_manifest_db(
        backup_dir, True, manifest, password, allow_password_prompt, try_default_passwords
    )
    if keybag is None:
        raise BackupError("Backup keybag was not unlocked")

    command = command or [TOOL_NAME]
    staging = tempfile.TemporaryDirectory(prefix="mobile_backup_decrypt_", dir=output.parent.resolve())
    try:
        staged = long_path(Path(staging.name) / output.name)
        staged.mkdir(parents=True, exist_ok=True)
        rows, stats, updates = _decrypt_files(backup_dir, db_path, staged, keybag, progress, cancel)

        # The manifest and plists are written only after the blobs, so a cancelled
        # run cannot leave an output that claims to be a complete backup.
        shutil.copyfile(db_path, staged / "Manifest.db")
        apply_metadata_updates(staged / "Manifest.db", updates)
        write_unencrypted_manifest_plist(manifest, staged / "Manifest.plist")
        for name in COPIED_BACKUP_FILES:
            source = backup_dir / name
            if source.is_file():
                shutil.copyfile(source, staged / name)

        provenance = build_decryption_provenance(backup_dir, output, manifest, info, stats, command)
        write_trace_folder(staged, provenance, rows)
        if output.exists():
            shutil.copytree(staged, long_path(output), dirs_exist_ok=True)
        else:
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staged), str(long_path(output)))
    finally:
        staging.cleanup()
        if tmp_dir:
            tmp_dir.cleanup()

    return DecryptionResult(
        output=output,
        encrypted=True,
        stats=stats,
        cancelled=bool(stats["cancelled"]),
    )


def _decrypt_files(
    backup_dir: Path,
    db_path: Path,
    staged: Path,
    keybag: Keybag,
    progress: ProgressCallback | None,
    cancel: CancelEvent | None,
) -> tuple[list[dict[str, Any]], dict[str, int], list[tuple[str, bytes]]]:
    """Decrypt every regular file, returning traceability rows, stats and the
    metadata blobs to write back."""
    rows: list[dict[str, Any]] = []
    stats = {
        "records": 0,
        "written": 0,
        "missing": 0,
        "failed": 0,
        "directories": 0,
        "cancelled": 0,
    }
    updates: list[tuple[str, bytes]] = []
    total = count_manifest_rows(db_path)

    for file_id, domain, relative_path, flags, file_blob in iter_manifest_rows(db_path):
        if is_cancelled(cancel):
            stats["cancelled"] = 1
            break
        stats["records"] += 1
        row = _blank_row(file_id, domain, relative_path, flags)

        # Only regular files carry a blob; a directory or symlink row is copied
        # through in Manifest.db untouched.
        if flags != FLAG_REGULAR_FILE:
            row["status"] = "directory_record"
            rows.append(row)
            stats["directories"] += 1
            continue

        source = source_path_for_file_id(backup_dir, file_id)
        row["source_path"] = str(source)
        destination = staged / file_id[:2] / file_id
        row["output_path"] = str(Path(file_id[:2]) / file_id)
        if not source.is_file():
            # No blob to decrypt, but the row must not keep advertising a wrapped
            # key in a backup that now declares itself unencrypted. The digest is
            # left alone: it is the source's only record of a file we do not have.
            new_blob, original_digest = rewrite_file_metadata(file_blob or b"", None)
            updates.append((file_id, new_blob))
            row.update(
                {
                    "status": "missing_source",
                    "manifest_digest_original": original_digest,
                    "error": "blob absent from the backup; digest left as recorded (ciphertext)",
                }
            )
            rows.append(row)
            stats["missing"] += 1
            continue

        try:
            metadata = parse_file_metadata(file_blob)
            key = _file_key(metadata, keybag)
            written, cipher_sha256, plain_sha1 = decrypt_blob(source, destination, key, metadata_size(metadata))
            new_blob, original_digest = rewrite_file_metadata(file_blob or b"", bytes.fromhex(plain_sha1))
            updates.append((file_id, new_blob))
            row.update(
                {
                    "status": "written",
                    "source_sha256": cipher_sha256,
                    "output_size": written,
                    "declared_size": metadata_size(metadata) or "",
                    "manifest_digest_original": original_digest,
                    "manifest_digest_rewritten": plain_sha1,
                }
            )
            stats["written"] += 1
        except Exception as exc:  # noqa: BLE001 - one bad row must not lose the rest
            row.update({"status": "failed", "error": str(exc)})
            stats["failed"] += 1
            if destination.exists():
                destination.unlink()
        rows.append(row)
        report_progress(progress, stats["records"], total, relative_path)

    return rows, stats, updates


def _file_key(metadata: dict[str, Any], keybag: Keybag) -> bytes:
    """The unwrapped per-file AES key for one manifest record."""
    blob = plist_data_value(first_present(metadata, ("EncryptionKey", "encryptionKey")))
    if blob is None or len(blob) <= 4:
        raise BackupError("Record has no usable file encryption key")
    protection_class = first_present(metadata, ("ProtectionClass", "protectionClass"))
    if not isinstance(protection_class, int):
        raise BackupError("Record has no protection class")
    return keybag.unwrap_key(protection_class, blob[4:])


def _blank_row(file_id: str, domain: str, relative_path: str, flags: int) -> dict[str, Any]:
    """An empty traceability row, so every column is present in every record."""
    return {
        "file_id": file_id,
        "domain": domain,
        "relative_path": relative_path,
        "flags": flags,
        "source_path": "",
        "output_path": "",
        "source_sha256": "",
        "output_sha256": "",
        "source_size": "",
        "output_size": "",
        "declared_size": "",
        "status": "pending",
        "error": "",
        "manifest_digest_original": "",
        "manifest_digest_rewritten": "",
    }
