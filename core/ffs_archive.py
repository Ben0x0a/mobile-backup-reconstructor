"""The Full File System-like zip archive written by every reconstruction.

Defines: `FfsZipWriter` (member claiming, fail-safe streamed member writes,
root artefacts), the human-readable root traceability summary, and the
`<archive>.zip.sha256` sidecar.
Used by: core.ios_reconstructor, core.ios_traceability, core.traceability,
core.android_reconstructor.
Depends on: core.output_paths, config.settings.

WHY a zip, streamed: a rebuilt device path is long before the operator's own
destination is added (`private/var/mobile/Containers/Data/Application/<uuid>/
Library/...`, `data/data/<package>/databases/...`). Written to disk as a tree it
crosses Windows' 260-character limit and breaks tools that do not handle long
paths. Inside a zip a path is only a member name, so no limit applies, and the
archive is also the shape a Full File System acquisition is delivered in.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import zipfile
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, TypeVar

from config.settings import (
    CHUNK_SIZE,
    ROOT_TRACEABILITY_TEXT_NAME,
    TOOL_NAME,
    TOOL_VERSION,
    TRACEABILITY_DIR_NAME,
    ZIP_HASH_SIDECAR_SUFFIX,
    ZIP_SPOOL_MAX_SIZE,
)
from core.output_paths import claim_unique_path, long_path

T = TypeVar("T")

# The earliest timestamp a zip header can store. Consumed by: zip_info.
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

# One summary section: a heading and its (label, value) lines, in display order.
TraceSection = tuple[str, list[tuple[str, Any]]]


def zip_info(arcname: str, mtime: datetime | None) -> zipfile.ZipInfo:
    """A deflated member header carrying the device timestamp, in UTC.

    WHY clamp to 1980: the zip format cannot store an earlier date, and a
    zero or bogus device timestamp would otherwise raise and fail the file.
    """
    info = zipfile.ZipInfo(arcname)
    if mtime is not None:
        if mtime.tzinfo is not None:
            mtime = mtime.astimezone(UTC).replace(tzinfo=None)
        info.date_time = max(mtime.timetuple()[:6], ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


class FfsZipWriter:
    """Write device files, then root artefacts, into one zip archive.

    The root names (`reserved_root_names`) are claimed before any device path,
    so a device file can never take the name of a tool artefact: it is given a
    `~1` suffix instead, exactly as for any other collision.
    """

    def __init__(self, zip_path: Path, reserved_root_names: Iterable[str]) -> None:
        self.zip_path = zip_path
        self.claimed: dict[str, str] = {}
        for name in (*reserved_root_names, TRACEABILITY_DIR_NAME):
            claim_unique_path(PurePosixPath(name), self.claimed, is_directory=False)
        long_path(zip_path).parent.mkdir(parents=True, exist_ok=True)
        self._zf = zipfile.ZipFile(long_path(zip_path), "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True)

    def __enter__(self) -> FfsZipWriter:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._zf.close()

    def claim(self, rel: PurePosixPath, is_directory: bool) -> str:
        """Reserve a member name for one device path; see claim_unique_path."""
        return claim_unique_path(rel, self.claimed, is_directory).as_posix()

    def add_directory(self, arcname: str) -> str:
        dir_name = arcname if arcname.endswith("/") else f"{arcname}/"
        # Through zip_info so the entry is stamped in UTC like every other
        # member; a bare name would take the host's local time.
        self._zf.writestr(zip_info(dir_name, datetime.now(UTC)), b"")
        return dir_name

    def add_member(self, arcname: str, mtime: datetime | None, produce: Callable[[BinaryIO], T]) -> T:
        """Write one member from `produce`, which streams the content into a file.

        HOW: `produce` writes into a spooled temporary file (memory up to
        ZIP_SPOOL_MAX_SIZE, then disk); only when it returns is the content
        copied into the archive.
        WHY spool first: a zip member cannot be removed once started, so a
        decryption that fails halfway would leave a truncated file in the
        archive that looks like evidence. Spooling makes a failed member absent.
        """
        with tempfile.SpooledTemporaryFile(max_size=ZIP_SPOOL_MAX_SIZE) as spool:
            result = produce(spool)
            spool.seek(0)
            with self._zf.open(zip_info(arcname, mtime), "w") as out_fh:
                shutil.copyfileobj(spool, out_fh, CHUNK_SIZE)
        return result

    def add_root_file(self, name: str, source: Path) -> str:
        """Copy a file to the archive root and return its SHA-256."""
        digest = hashlib.sha256()
        with source.open("rb") as src, self._zf.open(zip_info(name, datetime.now(UTC)), "w") as out_fh:
            for chunk in iter(lambda: src.read(CHUNK_SIZE), b""):
                digest.update(chunk)
                out_fh.write(chunk)
        return digest.hexdigest()

    def add_root_bytes(self, name: str, data: bytes) -> str:
        """Write bytes as an archive member and return their SHA-256."""
        self._zf.writestr(zip_info(name, datetime.now(UTC)), data)
        return hashlib.sha256(data).hexdigest()


def format_traceability_text(sections: list[TraceSection]) -> str:
    """Render the root summary: a title, then aligned `label : value` sections.

    WHY plain text beside the JSON: the JSON is for tools; this is what an
    examiner opens first, in any viewer, to see what the archive is, where it
    came from and which hashes prove it.
    """
    lines = [f"{TOOL_NAME} {TOOL_VERSION} — traceability summary", "=" * 60, ""]
    for heading, entries in sections:
        lines.append(f"[{heading}]")
        width = max((len(label) for label, _ in entries), default=0)
        for label, value in entries:
            shown = "(none)" if value is None or value == "" else value
            lines.append(f"  {label.ljust(width)} : {shown}")
        lines.append("")
    return "\n".join(lines)


def write_root_traceability_text(writer: FfsZipWriter, sections: list[TraceSection]) -> str:
    """Write the summary to the archive root and return its SHA-256.

    Encoded UTF-8 with BOM so Windows viewers decode accented device names
    correctly (house rule for text output).
    """
    return writer.add_root_bytes(ROOT_TRACEABILITY_TEXT_NAME, format_traceability_text(sections).encode("utf-8-sig"))


def sidecar_path(zip_path: Path) -> Path:
    return zip_path.with_name(f"{zip_path.name}{ZIP_HASH_SIDECAR_SUFFIX}")


def write_zip_sha256_sidecar(zip_path: Path) -> tuple[str, Path]:
    """Hash the finished archive and write `<name>.zip.sha256` beside it.

    WHY a sidecar: an archive cannot contain its own digest, so the hash that
    seals the whole output has to live outside it. The line is in
    `sha256sum` format (`<hex>  <name>`), verifiable with `sha256sum -c` or
    `shasum -a 256 -c`; it is written WITHOUT a BOM because those tools would
    read the BOM as part of the digest.
    """
    digest = hashlib.sha256()
    with long_path(zip_path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    hex_digest = digest.hexdigest()
    sidecar = sidecar_path(zip_path)
    long_path(sidecar).write_text(f"{hex_digest}  {zip_path.name}\n", encoding="utf-8")
    return hex_digest, sidecar
