"""Output-path safety shared by every reconstruction pipeline.

Defines: path-segment sanitising (Windows-illegal characters and reserved
names), safe joining of device paths, collision-free path claiming, and the
Windows long-path helpers.
Used by: core.reconstructor (iOS), core.android_reconstructor, core.ffs_archive,
core.decryptor (through core.reconstructor).
Depends on: nothing outside the standard library.

WHY a module of its own: both the iOS and the Android pipelines turn device
paths into archive member names and must agree on exactly the same rules, so a
path is sanitised and disambiguated identically whatever the source platform.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath

INVALID_PATH_CHARS = re.compile(r'[<>:"\\|?*\x00-\x1f]')
RESERVED_WINDOWS_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


# Windows refuses a path longer than this unless it carries the extended-length
# prefix. Consumed by: long_path, and the long-path count in the run statistics.
WINDOWS_MAX_PATH = 260
# The prefix that lifts that limit to ~32,767 characters.
WINDOWS_LONG_PATH_PREFIX = "\\\\?\\"


def long_path(path: Path) -> Path:
    r"""Return `path` in a form Windows' `MAX_PATH` limit does not apply to.

    HOW: resolves the path and prepends the `\\?\` extended-length prefix (or
    `\\?\UNC\` for a network share), which raises the limit from 260 characters
    to roughly 32,767. A no-op on every other platform, where no such limit exists.

    WHY prefix rather than skip the file: a rebuilt iOS path is long before the
    operator's own destination is added — `private/var/mobile/Containers/Data/
    Application/<bundle id>/Library/...` — so on Windows a reconstruction failed
    with "path too long" partway through. The alternative, refusing to write those
    files, loses evidence; this writes them.

    The prefix is applied ONLY to paths used for I/O. Traceability records the
    plain path, because `\\?\C:\...` is an implementation detail and an examiner
    should not have to read it.
    """
    if os.name != "nt":
        return path
    resolved = path.resolve()
    text = str(resolved)
    if text.startswith(WINDOWS_LONG_PATH_PREFIX):
        return resolved
    if text.startswith("\\\\"):
        # A UNC share: \\server\share -> \\?\UNC\server\share
        return Path(f"{WINDOWS_LONG_PATH_PREFIX}UNC{text[1:]}")
    return Path(f"{WINDOWS_LONG_PATH_PREFIX}{text}")


def exceeds_windows_max_path(path: Path) -> bool:
    """Whether this destination would be unreachable to a tool that does not
    handle Windows long paths.

    Reported so an operator learns the output needs long-path-aware tools, rather
    than discovering it when something else fails to open the file.
    """
    return len(str(path)) > WINDOWS_MAX_PATH


def sanitise_segment(segment: str) -> str:
    # rstrip, NOT strip: a TRAILING dot or space is illegal on Windows, but a
    # LEADING dot is a legitimate and meaningful part of a Unix filename. Stripping
    # it renamed the evidence — `.GlobalPreferences.plist` was written out as
    # `GlobalPreferences.plist`, a different file from the one the backup recorded.
    cleaned = INVALID_PATH_CHARS.sub("_", segment).rstrip(" .")
    if not cleaned:
        cleaned = "_"
    if cleaned.upper() in RESERVED_WINDOWS_NAMES:
        cleaned = f"_{cleaned}"
    return cleaned


def safe_output_path(domain: str, relative_path: str) -> PurePosixPath:
    parts = [sanitise_segment(domain)]
    for part in PurePosixPath(relative_path).parts:
        if part in ("", ".", "..") or part.startswith("/"):
            continue
        parts.append(sanitise_segment(part))
    return PurePosixPath(*parts)


def safe_join_path(root: str, relative_path: str) -> PurePosixPath:
    parts: list[str] = []
    for part in PurePosixPath(root).parts:
        if part in ("", ".", "..", "/"):
            continue
        parts.append(sanitise_segment(part))
    for part in PurePosixPath(relative_path).parts:
        if part in ("", ".", "..") or part.startswith("/"):
            continue
        parts.append(sanitise_segment(part))
    return PurePosixPath(*parts)


def claim_unique_path(
    rel: PurePosixPath,
    claimed: dict[str, str],
    is_directory: bool,
    base: Path | None = None,
) -> PurePosixPath:
    """Reserve an output path for one record, disambiguating real collisions.

    HOW: walks candidate paths, appending ``~1``, ``~2``, ... until one is free,
    then records which kind of record claimed it. A path is free for a directory
    record when nothing else claimed it as a FILE and the on-disk entry (if any)
    is itself a directory; it is free for a file record when nothing claimed it
    and nothing exists there.
    WHY: ``Manifest.db`` lists rows in arbitrary order, so a directory row often
    arrives after the files inside it, by which point the directory already
    exists because it was created as their parent. Treating mere existence as a
    collision renamed that legitimate row to ``SMS~1`` and left an empty decoy
    folder beside the real one. `base` is None for zip output, which has no
    filesystem to consult.
    """
    candidate = rel
    suffix = 1
    while True:
        key = candidate.as_posix().lower()
        existing = base / Path(*candidate.parts) if base is not None else None
        if is_directory:
            free = claimed.get(key, "directory") == "directory" and (
                existing is None or not existing.exists() or existing.is_dir()
            )
        else:
            free = key not in claimed and (existing is None or not existing.exists())
        if free:
            claimed[key] = "directory" if is_directory else "file"
            return candidate
        candidate = candidate.parent / f"{candidate.name}~{suffix}"
        suffix += 1
