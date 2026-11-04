"""How a reconstruction run is driven and its output promoted.

Defines: the progress callback and cancellation contracts (`ProgressCallback`,
`CancelEvent`, `report_progress`, `is_cancelled`), and the staging directory
lifecycle (`make_staging_dir`, `remove_staging_dir`, `promote_folder_output`,
`promote_zip_output`).
Used by: core.ios_reconstructor, core.android_reconstructor, core.decryptor,
launcher.cli, gui.interface (through the callbacks).
Depends on: core.output_paths, core.errors.

Every run writes into a staging directory beside the destination and promotes
it only on success, which is what makes "fail closed" real.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from core.errors import BackupError
from core.output_paths import (
    long_path,
)

_LOG = logging.getLogger(__name__)


# (files_done, files_total, current_output_path) -> None. Cosmetic only; see
# report_progress. A bare callable so core imports no UI toolkit.
ProgressCallback = Callable[[int, int, str], None]


class CancelEvent(Protocol):
    """The subset of `threading.Event` the pipeline needs to support cancellation."""

    def is_set(self) -> bool: ...


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
