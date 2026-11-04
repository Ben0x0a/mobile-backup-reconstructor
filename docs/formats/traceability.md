# Traceability artefacts

Every run writes two files into `_traceability/` inside the output folder or
zip. Every filename carries the tool tag, so an artefact separated from its
output is still attributable.

```text
_traceability/
├── mobile-backup-reconstruct.provenance.traceability.json
└── mobile-backup-reconstruct.file-manifest.traceability.csv
```

When a run fails closed, the same pair is written to
`failed_traceability_reports/<output-name>-<UTC timestamp>/` instead.

## Zip archives: root artefacts and the hash sidecar

The Full File System-like layout is always a zip (see
[why](../getting-started.md#why-the-ffs-like-output-is-a-zip)). Every zip — iOS or
Android — carries extra artefacts at its root, beside the device tree, and a hash
file beside the archive:

```text
output.zip
├── private/var/...                        # iOS device tree   (or data/..., storage/... for Android)
├── Manifest.db                            # iOS only: decrypted (or original) Manifest.db
├── Manifest.mobile-backup-reconstruct.enriched.db  # iOS only: Manifest.db + Files.zipPath
├── mobile-backup-reconstruct.traceability.txt      # human-readable summary
└── _traceability/...
output.zip.sha256                          # SHA-256 of the archive itself
```

| Artefact | Content |
| --- | --- |
| `Manifest.db` | The `Manifest.db` the run walked: decrypted for an encrypted backup, an exact copy otherwise. Its SHA-256 is `backup.manifest_db_plaintext_sha256` in the provenance |
| `Manifest.mobile-backup-reconstruct.enriched.db` | A copy of that `Manifest.db` with one added column, `Files.zipPath`: the member name of each row inside the archive. `NULL` when the row was not written (missing blob, failure, cancelled before it). Every other table and column is unchanged, so existing queries still work |
| `mobile-backup-reconstruct.traceability.txt` | UTF-8 (with BOM) summary: run, source and device, SHA-256 of every source manifest file and of every root artefact, output options, statistics, and (Android) the package list. Written last, because it lists the others' digests |
| `<output>.zip.sha256` | One line in `sha256sum` format, outside the archive because an archive cannot contain its own digest. Verify with `sha256sum -c output.zip.sha256` or `shasum -a 256 -c output.zip.sha256` |

The device tree never collides with a root artefact: their names are claimed
before any device path, so a device file with the same name gets a `~1` suffix.

Example — the archive path of every SMS database row:

```sql
SELECT domain, relativePath, zipPath FROM Files WHERE relativePath LIKE '%sms.db';
```

## Provenance JSON

One object describing the run.

| Key | Meaning |
| --- | --- |
| `tool`, `tool_version` | Which build produced the output |
| `created_utc` | ISO-8601 UTC timestamp of the run |
| `host.system`, `host.release`, `host.python` | Execution environment |
| `command` | The command line, with any password argument redacted |
| `backup.path` | Source backup directory |
| `backup.manifest_plist_sha256` | SHA-256 of `Manifest.plist` as read |
| `platform` | `ios` or `android` |
| `backup.manifest_db_sha256` | SHA-256 of `Manifest.db` as read (ciphertext, if encrypted) |
| `backup.manifest_db_plaintext_sha256` | SHA-256 of the `Manifest.db` walked and written to the zip root (equals the above when unencrypted) |
| `backup.info_plist_sha256` | SHA-256 of `Info.plist` as read |
| `backup.status_plist_sha256` | SHA-256 of `Status.plist` as read |
| `backup.encrypted` | Whether the backup was encrypted |
| `backup.manifest_version`, `backup.system_domains_version`, `backup.manifest_date` | Backup-level metadata |
| `backup.status.*` | Snapshot state, whether the backup was full, its date |
| `backup.device.*` | Device name, product name and type, iOS version, serial, identifier |
| `output.path`, `output.format`, `output.layout` | What was produced and how |
| `output.domain_map`, `output.domain_map_name`, `output.domain_map_ios_versions` | Which mapping was applied |
| `output.dry_run`, `output.continue_on_error` | Which mode the run used |
| `output.try_default_passwords` | Whether acquisition-tool default passwords were tried |
| `output.cancelled` | Whether the operator stopped the run early, leaving an incomplete tree |
| `stats` | `records`, `written`, `missing`, `failed`, `directories` |

The password is never recorded, in any form.

## File manifest CSV

One row per `Manifest.db` record, written UTF-8 with a header.

| Column | Meaning |
| --- | --- |
| `file_id` | `fileID` from `Manifest.db`; the blob's filename |
| `domain` | Backup domain |
| `relative_path` | Path within the domain |
| `flags` | `1` = file, `2` = directory record |
| `source_path` | Absolute path of the source blob |
| `output_path` | Final destination path (folder output) or archive member name (zip) |
| `source_sha256` | Digest of the bytes read from the backup |
| `output_sha256` | Digest of the bytes written to the output |
| `source_size` | Size of the source blob on disk |
| `output_size` | Bytes written |
| `declared_size` | `Size` from the record's metadata, if present |
| `status` | See below |
| `error` | Failure message, when `status` is `failed` |

### Status values

| Status | Meaning |
| --- | --- |
| `written` | Content reconstructed successfully |
| `directory_record` | A `flags = 2` row; a directory was created. Not a missing file |
| `missing_source` | `Manifest.db` lists the file, but its blob is absent from the backup |
| `planned` | `--dry-run` only: the file would have been written here |
| `failed` | Reconstruction raised; see `error` |
| `pending` | Transient; never present in a completed manifest |

### Interpreting the digests

For an **unencrypted** backup, `source_sha256` and `output_sha256` are equal for
every `written` row: the blob is copied verbatim.

For an **encrypted** backup they necessarily differ — the source digest covers
the stored ciphertext, the output digest the decrypted plaintext. Compare
`output_size` with `declared_size` instead.

`declared_size` is recorded but never enforced on unencrypted output, so a
mismatch indicates stale metadata in the backup rather than data loss.


## Android provenance and file manifest

An Android run writes the same two files with Android-specific content.

Provenance `backup.*`: `path`, `format` (`adb backup (.ab)`), `sha256` and `size`
of the `.ab` file, `format_version`, `compressed`, `encryption` (`none` or
`AES-256`), `pbkdf2_rounds`, `key_derivation` (which PBKDF2 regime unlocked it),
`packages` (every package seen) and `stream_error` (set when the payload ended
early). `output.path_map` / `output.path_map_name` name the
[Android path map](../concepts/android-backup.md) applied.

The file manifest has one row per tar member:

| Column | Meaning |
| --- | --- |
| `archive_path` | Member name inside the `.ab` tar (`apps/<package>/<token>/...`, `shared/0/...`) |
| `member_type` | `file`, `directory` or `other` (link, device) |
| `package`, `token` | Parsed from `archive_path`; `token` is `shared/<volume>` for shared storage |
| `output_path` | Member name in the output zip |
| `size`, `mtime_utc`, `mode` | From the tar header |
| `source_sha256`, `output_sha256` | Digest of the content; equal, because `.ab` stores files verbatim |
| `status` | `written`, `directory_record`, `planned` (dry run), `unsupported_member` (no content to copy; recorded, not failed), `failed` |
| `error` | Failure message, or the link target of an `unsupported_member` |
