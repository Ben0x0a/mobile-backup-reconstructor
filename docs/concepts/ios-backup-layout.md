# iOS backup layout

## What a backup contains

A local backup is deliberately *not* a filesystem image. It is a flat store of
content-addressed blobs plus a database describing them.

```text
<UDID>/
├── Manifest.plist   # REQUIRED. Backup-level metadata, encryption flag, keybag
├── Manifest.db      # REQUIRED. SQLite index: one row per backed-up file
├── Info.plist       # optional. Device identity: name, product type, iOS version
├── Status.plist     # optional. Snapshot state, whether the backup is full
├── 00/ 01/ .. ff/   # File blobs, named by SHA-1, bucketed by first two hex chars
```

Only `Manifest.plist` and `Manifest.db` are load-bearing: the first carries the
encryption state and key material, the second the file table. `Info.plist` and
`Status.plist` carry provenance, and **older backups may not have them** — so the
tool reads them when present and records their absence when not, rather than
refusing to work. A file that is present but malformed is still an error.

## The Files table

`Manifest.db` holds a single table that matters:

| Column | Meaning |
| --- | --- |
| `fileID` | SHA-1 of `<domain>-<relativePath>`; also the blob's filename |
| `domain` | The logical container the file belonged to |
| `relativePath` | Path within that domain |
| `flags` | `1` = file, `2` = directory record |
| `file` | Binary plist of metadata (size, timestamps, protection class, key) |

A blob lives at `<UDID>/<fileID[:2]>/<fileID>`. Reconstruction is therefore a
join: read each row, find its blob, and write it back to
`<domain>/<relativePath>`.

## Where this lives in the code

| Step | Implementation |
| --- | --- |
| Validate a backup directory | `core/ios_backup.py` `resolve_backup_dir` |
| Walk the `Files` table | `core/ios_backup.py` `iter_manifest_rows`, `iter_file_records` |
| Decode the per-file metadata plist | `core/ios_backup.py` `parse_file_metadata`, `decode_nskeyed` |
| Locate a blob from its `fileID` | `core/ios_backup.py` `source_path_for_file_id` |
| Map a domain to a path | `core/ios_domain_map.py` `filesystem_domain_root` (table: `config/domain_maps/`) |
| Make a path host-safe | `core/output_paths.py` `sanitise_segment`, `safe_join_path` |
| Resolve output-path collisions | `core/output_paths.py` `claim_unique_path` |

## Domains

iOS groups files into *domains* rather than absolute paths. `HomeDomain` holds
the user's home directory; `AppDomain-com.example.app` holds one app's
container; `CameraRollDomain` holds photos. The backup records the domain, not
the path it was mounted at on the device.

The tool offers two layouts:

- `--layout backup` keeps domains as top-level folders, exactly as the backup
  models them. Nothing is inferred.
- `--layout filesystem` (default) maps each domain to the path it occupied on
  the device, so `HomeDomain` becomes `private/var/mobile`. This is a
  *reconstruction*, driven by the editable maps in
  [`config/domain_maps/`](../formats/domain-maps.md).

Paths are always written relative to the output root, never as absolute
`/private/...` paths, so output cannot escape the folder you chose.

## Directory records

Rows with `flags = 2` describe directories, not files. They have no blob. The
tool creates the directory and records the row as `directory_record` — these
are not missing files, and should not be read as gaps in the evidence.

## What is not in a backup

A local backup is not a full filesystem acquisition. It excludes system files,
caches, and anything the app marked as excluded from backup. Keychain items are
present but encrypted under a separate class key. Absence from a backup is not
evidence of absence from the device.
