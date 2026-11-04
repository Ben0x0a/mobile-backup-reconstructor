# Getting started

## Requirements

- Python 3.12 or newer
- [`uv`](https://docs.astral.sh/uv/) (recommended) or `pip`

## Install

### With uv

```bash
uv sync
```

`uv sync` installs from `pyproject.toml` and the committed `uv.lock`, so you get
exactly the dependency versions the project was tested against.

### With pip

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
python3 -m pip install -e .
```

## Locate a backup

A local iOS backup is a directory containing `Manifest.plist`, `Manifest.db`,
`Info.plist` and `Status.plist`, alongside two-character subdirectories of
hashed file blobs. Default locations:

| Platform | Path |
| --- | --- |
| macOS | `~/Library/Application Support/MobileSync/Backup/<UDID>` |
| Windows | `%APPDATA%\Apple Computer\MobileSync\Backup\<UDID>` |

You may pass either the directory or its `Manifest.plist`.

## Inspect before reconstructing

```bash
uv run python main.py /path/to/ios-backup /path/to/output --info-only
```

```json
{
  "backup": "/path/to/ios-backup",
  "date": "2026-04-13 11:29:13",
  "device": "iPhone SE",
  "encrypted": true,
  "ios": "14.0.1",
  "product": "iPhone SE (2nd generation)"
}
```

`encrypted: true` means you will need the backup password.

## Plan the output

A dry run writes only the traceability artefacts, listing where every file
*would* go, without reconstructing any content:

```bash
uv run python main.py /path/to/ios-backup /path/to/output --dry-run
```

## Reconstruct

```bash
uv run python main.py /path/to/ios-backup /path/to/output
```

An Android `adb backup` file is reconstructed the same way — the input is
recognised by its header:

```bash
uv run python main.py /path/to/backup.ab /path/to/output
```

### Why the FFS-like output is a zip

A rebuilt device path is long before your destination is added
(`private/var/mobile/Containers/Data/Application/<uuid>/Library/...`,
`data/data/<package>/databases/...`), so written as a folder tree many exceed
Windows' 260-character limit and break tools that do not handle long paths.
Inside a zip a path is only a member name, so the Full File System-like layout is
always written as a zip — the same shape a Full File System acquisition is
delivered in. `--format folder` is refused for it; the iOS `backup` layout can
still be written as a folder.

## Read the output

```text
output.zip
├── private/var/mobile/Library/SMS/sms.db
├── Manifest.db                                   # decrypted Manifest.db (iOS)
├── Manifest.mobile-backup-reconstruct.enriched.db # + Files.zipPath (iOS)
├── mobile-backup-reconstruct.traceability.txt     # summary with every hash
└── _traceability/
    ├── mobile-backup-reconstruct.provenance.traceability.json
    └── mobile-backup-reconstruct.file-manifest.traceability.csv
output.zip.sha256                                  # the archive's own SHA-256
```

Open the `.traceability.txt` first: it says what the archive is, where it came
from, and which hashes prove it. The provenance JSON records the run for tools;
the file manifest records one row per file. See
[formats/traceability.md](formats/traceability.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, every row handled |
| `1` | The run failed; no output was produced |
| `2` | Completed with failed rows, under `--continue-on-error` |
