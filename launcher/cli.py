"""Command-line interface for the mobile backup reconstructor.

Defines: the argument parser, password-argument redaction, the TTY progress
counter, mode/flag validation, and `main` (dispatch, JSON result on stdout,
exit codes).
Used by: main, the `mobile-backup-reconstruct` console script, tests.
Depends on: core.reconstructor, core.decryptor (lazily), core.android_backup,
core.run_control, core.errors, core.output_paths, config.settings.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from config.settings import (
    DEFAULT_OUTPUT_LAYOUT,
    OUTPUT_LAYOUTS,
    TOOL_NAME,
    TOOL_VERSION,
)
from core.errors import BackupError
from core.output_paths import (
    WINDOWS_MAX_PATH,
)
from core.reconstructor import inspect_backup, reconstruct_backup
from core.run_control import ProgressCallback

_LOG = logging.getLogger(__name__)


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
