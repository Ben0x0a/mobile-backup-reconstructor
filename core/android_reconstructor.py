"""Reconstruct an Android `adb backup` into a Full File System-like zip.

Defines: the archive-path -> device-path mapping (`load_android_map`,
`android_output_path`), the streamed reconstruction into the archive, the
Android provenance and root summary, and `reconstruct_android_backup`.
Used by: core.reconstructor (`reconstruct_backup` dispatches here on an `.ab` input).
Depends on: core.android_backup, core.ffs_archive, core.output_paths,
core.reconstructor (shared errors, password prompt policy, traceability
helpers), core.models, config.settings, config/android_maps (package data).

An `.ab` carries no file table like iOS's Manifest.db: the tar member names ARE
the index (`apps/<package>/<token>/<path>`, `shared/<volume>/<path>`). Each
token names one app directory on the device (see config/android_maps), so a
member maps to exactly one device path. Content is copied unchanged — `.ab`
stores files verbatim once the payload is decrypted and inflated — so the
source and output digests of a written row are equal.
"""

from __future__ import annotations

import getpass
import hashlib
import logging
import platform
import sys
import tarfile
from datetime import UTC, datetime
from functools import lru_cache
from importlib.resources import as_file, files
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from config.settings import (
    ANDROID_MAP_DIR_NAME,
    ANDROID_MAP_FILE_NAME,
    CHUNK_SIZE,
    FFS_LAYOUT,
    ROOT_TRACEABILITY_TEXT_NAME,
    TOOL_NAME,
    TOOL_VERSION,
    TRACEABILITY_DIR_NAME,
    TRACEABILITY_FILE_MANIFEST_NAME,
)
from core.android_backup import PAYLOAD_ERRORS, AbHeader, open_ab_tar, read_ab_header_from
from core.ffs_archive import (
    FfsZipWriter,
    TraceSection,
    sidecar_path,
    write_root_traceability_text,
    write_zip_sha256_sidecar,
)
from core.models import ReconstructionResult
from core.output_paths import safe_join_path
from core.reconstructor import (
    _RESOURCE_STACK,
    BackupError,
    CancelEvent,
    ProgressCallback,
    ReconstructionFailedError,
    is_cancelled,
    make_staging_dir,
    parse_simple_domain_yaml,
    promote_zip_output,
    remove_staging_dir,
    report_progress,
    sha256_file,
    write_failure_report,
    write_trace_zip,
)

_LOG = logging.getLogger(__name__)

AndroidMap = dict[str, Any]

# Columns of the Android file manifest. Consumed by: write_trace_zip, write_failure_report.
ANDROID_MANIFEST_FIELDNAMES = (
    "archive_path",
    "member_type",
    "package",
    "token",
    "output_path",
    "size",
    "mtime_utc",
    "mode",
    "source_sha256",
    "output_sha256",
    "status",
    "error",
)

# Archive member names this pipeline places at the zip root.
ANDROID_RESERVED_ROOT_NAMES = (ROOT_TRACEABILITY_TEXT_NAME,)


@lru_cache(maxsize=1)
def default_android_map_path() -> Path:
    """Locate the shipped map; see reconstructor.default_domain_map_path for why importlib."""
    resource = files("config").joinpath(ANDROID_MAP_DIR_NAME, ANDROID_MAP_FILE_NAME)
    return Path(_RESOURCE_STACK.enter_context(as_file(resource)))


def load_android_map(path: Path | None = None) -> AndroidMap:
    """Load and validate an Android path map (YAML; PyYAML used when installed)."""
    map_path = (path or default_android_map_path()).expanduser()
    if not map_path.is_file():
        raise BackupError(f"Android path map not found: {map_path}")
    try:
        import yaml  # type: ignore
    except ImportError:
        data = parse_simple_domain_yaml(map_path)
    else:
        with map_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    required = (
        "app_metadata_template",
        "unknown_app_token_template",
        "unknown_shared_template",
        "unknown_template",
    )
    app_tokens = data.get("app_tokens")
    shared_volumes = data.get("shared_volumes")
    if not isinstance(app_tokens, dict) or not isinstance(shared_volumes, dict):
        raise BackupError(f"Android path map needs app_tokens and shared_volumes sections: {map_path}")
    missing = [key for key in required if not isinstance(data.get(key), str)]
    if missing:
        raise BackupError(f"Android path map is missing {', '.join(missing)}: {map_path}")
    # WHY str() on keys: PyYAML reads `0:` as the integer 0, the fallback parser as "0".
    return {
        "name": str(data.get("name", map_path.stem)),
        "path": str(map_path),
        "app_tokens": {str(k): str(v) for k, v in app_tokens.items()},
        "shared_volumes": {str(k): str(v) for k, v in shared_volumes.items()},
        **{key: data[key] for key in required},
    }


def android_output_path(archive_path: str, amap: AndroidMap) -> tuple[PurePosixPath, str, str]:
    """Map one tar member name to (device path, package, token).

    `package` and `token` are empty for members outside `apps/`; for `shared/`
    the token is `shared/<volume>`.
    """
    parts = [part for part in PurePosixPath(archive_path).parts if part not in ("/", ".", "")]
    if len(parts) >= 2 and parts[0] == "apps":
        package = parts[1]
        if len(parts) == 2:
            return safe_join_path(amap["app_metadata_template"].format(package=package), ""), package, ""
        token, rest = parts[2], "/".join(parts[3:])
        if token in amap["app_tokens"]:
            root = amap["app_tokens"][token].format(package=package)
        elif len(parts) == 3:
            # A file directly under apps/<package>/ — `_manifest`, `_meta` — is
            # backup metadata, not a token directory.
            root, rest = amap["app_metadata_template"].format(package=package), token
        else:
            root = amap["unknown_app_token_template"].format(package=package, token=token)
        return safe_join_path(root, rest), package, token
    if len(parts) >= 2 and parts[0] == "shared":
        volume = parts[1]
        root = amap["shared_volumes"].get(volume) or amap["unknown_shared_template"].format(volume=volume)
        return safe_join_path(root, "/".join(parts[2:])), "", f"shared/{volume}"
    return safe_join_path(amap["unknown_template"].format(path=""), "/".join(parts)), "", ""


def _member_mtime(member: tarfile.TarInfo) -> datetime | None:
    try:
        return datetime.fromtimestamp(member.mtime, UTC) if member.mtime else None
    except (OverflowError, OSError, ValueError):
        return None


def _copy_member(src: BinaryIO, dst: BinaryIO) -> tuple[int, str]:
    digest = hashlib.sha256()
    written = 0
    for chunk in iter(lambda: src.read(CHUNK_SIZE), b""):
        digest.update(chunk)
        dst.write(chunk)
        written += len(chunk)
    return written, digest.hexdigest()


def _row(member: tarfile.TarInfo, output_path: str, package: str, token: str, status: str) -> dict[str, Any]:
    mtime = _member_mtime(member)
    return {
        "archive_path": member.name,
        "member_type": "directory" if member.isdir() else "file" if member.isfile() else "other",
        "package": package,
        "token": token,
        "output_path": output_path,
        "size": member.size if member.isfile() else "",
        "mtime_utc": mtime.isoformat() if mtime else "",
        "mode": oct(member.mode),
        "source_sha256": "",
        "output_sha256": "",
        "status": status,
        "error": "",
    }


def new_android_stats() -> dict[str, int]:
    return {"records": 0, "written": 0, "directories": 0, "skipped": 0, "failed": 0, "cancelled": 0}


def describe_payload_error(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def reconstruct_ab_to_zip(
    tar: tarfile.TarFile,
    writer: FfsZipWriter,
    amap: AndroidMap,
    dry_run: bool,
    progress: ProgressCallback | None,
    cancel: CancelEvent | None,
) -> tuple[list[dict[str, Any]], dict[str, int], list[str], str | None]:
    """Stream every tar member into `writer`.

    Returns (rows, stats, packages, stream_error). A stream error (truncated or
    corrupt payload) ends the walk: a tar stream cannot be resumed past a bad
    block, so it is recorded once rather than per member.
    """
    rows: list[dict[str, Any]] = []
    stats = new_android_stats()
    packages: set[str] = set()
    stream_error: str | None = None
    try:
        for member in tar:
            if is_cancelled(cancel):
                stats["cancelled"] = 1
                break
            stats["records"] += 1
            device_path, package, token = android_output_path(member.name, amap)
            if package:
                packages.add(package)
            arcname = writer.claim(device_path, member.isdir())
            if member.isdir():
                dir_name = arcname if dry_run else writer.add_directory(arcname)
                rows.append(_row(member, dir_name, package, token, "directory_record"))
                stats["directories"] += 1
                continue
            if not member.isfile():
                # Links and devices have no content to copy; they stay recorded.
                row = _row(member, "", package, token, "unsupported_member")
                row["error"] = f"tar member type {member.type!r}" + (
                    f" -> {member.linkname}" if member.linkname else ""
                )
                rows.append(row)
                stats["skipped"] += 1
                continue
            if dry_run:
                rows.append(_row(member, arcname, package, token, "planned"))
                continue
            row = _row(member, arcname, package, token, "pending")
            source = tar.extractfile(member)
            assert source is not None, "Invariant violated: a regular tar member always has a file object"
            size, digest = writer.add_member(
                arcname, _member_mtime(member), lambda dst, src=source: _copy_member(src, dst)
            )
            if size != member.size:
                row.update({"status": "failed", "error": f"read {size} bytes, tar header declares {member.size}"})
                stats["failed"] += 1
            else:
                row.update({"status": "written", "source_sha256": digest, "output_sha256": digest})
                stats["written"] += 1
            rows.append(row)
            report_progress(progress, stats["records"], 0, member.name)
    except PAYLOAD_ERRORS as exc:
        stream_error = describe_payload_error(exc)
        stats["failed"] += 1
    return rows, stats, sorted(packages), stream_error


def build_android_provenance(
    backup: Path,
    header: AbHeader,
    regime: str | None,
    output: Path,
    amap: AndroidMap,
    stats: dict[str, int],
    packages: list[str],
    stream_error: str | None,
    command: list[str],
    dry_run: bool,
    continue_on_error: bool,
) -> dict[str, Any]:
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "platform": "android",
        "created_utc": datetime.now(UTC).isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
        },
        "command": command,
        "backup": {
            "path": str(backup),
            "format": "adb backup (.ab)",
            "sha256": sha256_file(backup),
            "size": backup.stat().st_size,
            "format_version": header.version,
            "compressed": header.compressed,
            "encryption": header.encryption,
            "pbkdf2_rounds": header.rounds if header.encrypted else None,
            "key_derivation": regime,
            "packages": packages,
            "stream_error": stream_error,
        },
        "output": {
            "path": str(output),
            "format": "zip",
            "layout": FFS_LAYOUT,
            "path_map": amap["path"],
            "path_map_name": amap["name"],
            "dry_run": dry_run,
            "continue_on_error": continue_on_error,
            "cancelled": bool(stats.get("cancelled")),
        },
        "stats": stats,
    }


def android_traceability_sections(
    provenance: dict[str, Any], digests: dict[str, str], zip_name: str
) -> list[TraceSection]:
    backup = provenance["backup"]
    output = provenance["output"]
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
                ("Platform", "Android backup (adb backup, .ab)"),
                ("Path", backup["path"]),
                ("Size (bytes)", backup["size"]),
                ("Format version", backup["format_version"]),
                ("Compressed", "yes" if backup["compressed"] else "no"),
                ("Encryption", backup["encryption"]),
                ("Key derivation", backup["key_derivation"]),
                ("Packages", len(backup["packages"])),
                ("Stream error", backup["stream_error"]),
            ],
        ),
        ("Source digest (SHA-256, as read)", [(Path(backup["path"]).name, backup["sha256"])]),
        ("Archive root artefacts (SHA-256)", list(digests.items())),
        (
            "Output",
            [
                ("Archive", zip_name),
                ("Layout", output["layout"]),
                ("Path map", output["path_map_name"]),
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
                ("Per-file digests", f"{TRACEABILITY_DIR_NAME}/{TRACEABILITY_FILE_MANIFEST_NAME}"),
            ],
        ),
        ("Packages", [(str(index + 1), name) for index, name in enumerate(backup["packages"])]),
    ]


def reject_android_options(output_format: str, output_layout: str, try_default_passwords: bool) -> None:
    """Refuse options with no meaning for an `.ab`, saying why.

    WHY an error rather than ignoring them: the operator believes they asked
    for that output (see reconstructor.reject_conflicting_mode_flags).
    """
    if output_layout != FFS_LAYOUT:
        raise BackupError(
            "An Android backup is always reconstructed in the Full File System-like layout; "
            "the 'backup' layout applies to iOS backup domains only."
        )
    if output_format == "folder":
        raise BackupError("An Android backup is always reconstructed into a zip (see the Windows path limit).")
    if try_default_passwords:
        raise BackupError(
            "--try-default-passwords lists iOS acquisition-tool defaults; it does not apply to .ab files."
        )


def resolve_android_password(header: AbHeader, password: str | None, allow_prompt: bool) -> str | None:
    """The password to unlock with: given, prompted on a real terminal, or refused."""
    if not header.encrypted or password:
        return password
    # Same TTY rule as the iOS path (reconstructor.prepare_manifest_db): getpass
    # raises on a pipe, which must not escape as a traceback.
    if allow_prompt and sys.stdin is not None and sys.stdin.isatty():
        try:
            return getpass.getpass("Android backup password: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise BackupError("No backup password was entered.") from exc
    raise BackupError("This Android backup is encrypted and no password was supplied.")


def reconstruct_android_backup(
    backup: Path,
    output: Path,
    output_format: str = "auto",
    password: str | None = None,
    force: bool = False,
    command: list[str] | None = None,
    allow_password_prompt: bool = True,
    output_layout: str = FFS_LAYOUT,
    path_map: Path | None = None,
    dry_run: bool = False,
    continue_on_error: bool = False,
    try_default_passwords: bool = False,
    progress: ProgressCallback | None = None,
    cancel: CancelEvent | None = None,
) -> ReconstructionResult:
    """Same contract as reconstructor.reconstruct_backup, for an `.ab` input."""
    reject_android_options(output_format, output_layout, try_default_passwords)
    backup = backup.resolve()
    header = read_ab_header_from(backup)
    amap = load_android_map(path_map)
    output = output.expanduser()
    if output.suffix.lower() != ".zip":
        output = output.with_suffix(".zip")
    if output.resolve() == backup:
        raise BackupError("Output must not overwrite the source backup")
    if output.exists() and not force:
        raise BackupError(f"Output zip already exists: {output}. Use --force to overwrite.")
    if not output.parent.expanduser().resolve().exists():
        raise BackupError(f"Output parent directory does not exist: {output.parent}")
    password = resolve_android_password(header, password, allow_password_prompt)
    command = command or [TOOL_NAME]

    stage_root = make_staging_dir(output.parent.expanduser().resolve())
    archive_sha256: str | None = None
    try:
        staged_output = stage_root / output.name
        with FfsZipWriter(staged_output, ANDROID_RESERVED_ROOT_NAMES) as writer:
            regime: str | None = None
            try:
                with open_ab_tar(backup, password) as (header, regime, tar):
                    rows, stats, packages, stream_error = reconstruct_ab_to_zip(
                        tar, writer, amap, dry_run, progress, cancel
                    )
            except PAYLOAD_ERRORS as exc:
                # Raised before the first member: `tarfile.open` reads ahead, so a
                # small damaged payload fails here rather than inside the walk.
                rows, stats, packages, stream_error = [], new_android_stats(), [], describe_payload_error(exc)
                stats["failed"] = 1
            provenance = build_android_provenance(
                backup, header, regime, output, amap, stats, packages, stream_error, command, dry_run, continue_on_error
            )
            if stats["failed"] and not continue_on_error and not stats["cancelled"]:
                report_path = write_failure_report(output, provenance, rows, ANDROID_MANIFEST_FIELDNAMES)
                raise ReconstructionFailedError(
                    f"Reconstruction failed; no output was produced. Failure report: {report_path}", report_path
                )
            digests = write_trace_zip(writer, provenance, rows, ANDROID_MANIFEST_FIELDNAMES)
            write_root_traceability_text(writer, android_traceability_sections(provenance, digests, output.name))
        promote_zip_output(staged_output, output, force)
        archive_sha256, _ = write_zip_sha256_sidecar(output)
    finally:
        remove_staging_dir(stage_root)
    if stream_error:
        _LOG.warning(f"The backup payload ended early ({stream_error}); later files could not be read")
    return ReconstructionResult(
        output=output,
        output_format="zip",
        output_layout=FFS_LAYOUT,
        encrypted=header.encrypted,
        stats=stats,
        dry_run=dry_run,
        cancelled=bool(stats["cancelled"]),
        archive_sha256=archive_sha256,
        platform="android",
    )
