"""Entry points that work on any supported backup.

Defines: `reconstruct_backup` and `inspect_backup`, which recognise an Android
`.ab` by its header (never its name) and otherwise treat the input as an iOS
backup directory.
Used by: launcher.cli, gui.interface, tests.
Depends on: core.android_backup, core.android_reconstructor,
core.ios_reconstructor, core.ios_backup, core.run_control, core.models,
config.settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from config.settings import (
    DEFAULT_OUTPUT_LAYOUT,
)
from core.ios_backup import first_present, missing_optional_files, read_optional_plist, read_plist, resolve_backup_dir
from core.ios_reconstructor import reconstruct_ios_backup
from core.models import ReconstructionResult
from core.run_control import CancelEvent, ProgressCallback


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

    return reconstruct_ios_backup(
        backup,
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
