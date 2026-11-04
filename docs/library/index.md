# Library use

The engine is importable; the CLI and GUI are thin shells over it.

## Reconstruct

```python
from pathlib import Path

from core import reconstruct_backup

result = reconstruct_backup(
    backup=Path("/path/to/ios-backup"),
    output=Path("/path/to/out"),
    output_format="folder",  # "auto" | "folder" | "zip"
    password=None,  # required for encrypted backups
    force=False,
    command=["my-harness"],  # recorded in provenance
    allow_password_prompt=False,  # never block on getpass in a service
    output_layout="filesystem",  # or "backup"
    domain_map_path=None,  # None uses the shipped maps
    dry_run=False,
    continue_on_error=False,
    try_default_passwords=False,  # opt in to trying acquisition-tool defaults
)

print(result.stats)  # {"records": .., "written": .., "failed": .., ..}
print(result.as_dict())  # the same JSON the CLI prints
```

`allow_password_prompt=False` is important in any non-interactive context:
left `True`, an encrypted backup will block on a terminal prompt.

## Inspect

```python
from pathlib import Path

from core import inspect_backup

info = inspect_backup(Path("/path/to/ios-backup"))
if info["encrypted"]:
    ...
```

`inspect_backup` reads only the plists, so it needs neither the password nor
the `cryptography` package.

## Iterate records without writing

```python
from pathlib import Path

from core.ios_backup import iter_file_records, resolve_backup_dir

backup_dir = resolve_backup_dir(Path("/path/to/ios-backup"))
for record in iter_file_records(backup_dir, backup_dir / "Manifest.db"):
    print(record.domain, record.relative_path, record.output_path)
```

This works directly only on an unencrypted backup; for an encrypted one, obtain
the decrypted manifest from `core.ios_crypto.prepare_manifest_db` first.

## Errors

All expected failures raise `BackupError` or a subclass:

| Exception | Raised when |
| --- | --- |
| `BackupError` | Any expected parsing, validation or reconstruction failure |
| `MissingCryptoError` | An encrypted backup needs the `cryptography` package, which is absent |
| `ReconstructionFailedError` | Rows failed and `continue_on_error` was false. Carries `.report_path` |

```python
from core import BackupError
from core.errors import ReconstructionFailedError

try:
    result = reconstruct_backup(...)
except ReconstructionFailedError as exc:
    print("failure report written to", exc.report_path)
except BackupError as exc:
    print("could not reconstruct:", exc)
```

## Logging

The engine logs diagnostics through the standard `logging` module, one logger
per module under the `core` package (configure `core` to catch them all), and
never calls `print` for diagnostics. Configure
handlers as you would for any library.
