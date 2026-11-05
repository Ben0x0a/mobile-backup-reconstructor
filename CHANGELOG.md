# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] — 2026-11-05

### Fixed

- **Directory entries in the zip keep their device timestamp.** They were
  stamped with the time of the run, which replaced the directory's modification
  time recorded in the backup (the tar header for Android, the `Files.file`
  metadata for iOS). Found on a real Android backup, whose 25 file contents were
  also checked byte for byte against an independent decode of the `.ab`.

## [0.3.0] — 2026-11-04

### Internal

- `core/reconstructor.py` (about 1,800 lines, mixing crypto, manifest walking,
  mapping, traceability, the pipeline and the CLI) is split by concern into
  `ios_backup`, `ios_crypto`, `ios_domain_map`, `ios_traceability`,
  `ios_reconstructor`, `traceability`, `run_control`, `errors`, `crypto_backend`
  and `package_resources`; the CLI moves to `launcher/cli.py`. Function bodies
  are unchanged. `core.reconstructor` keeps `reconstruct_backup` and
  `inspect_backup`; library code importing other names from it must import them
  from their new module (see docs/architecture.md). Diagnostics are now logged
  under each module's own logger in the `core` package rather than
  `core.reconstructor`.

### Changed

- **Renamed to `mobile-backup-reconstruct`** (package `mobile-backup-reconstructor`)
  now that Android backups are supported. Every artefact name carries the new
  tag, e.g. `_traceability/mobile-backup-reconstruct.provenance.traceability.json`;
  the console script is `mobile-backup-reconstruct`. **Breaking** for anything
  matching on the old `ios-backup-reconstruct` names.
- **The Full File System-like layout is always written as a zip, streamed.** As
  a folder tree its device paths exceed Windows' 260-character limit and broke
  the output for tools that do not handle long paths; inside a zip a path is only
  a member name. `--format auto` gives a zip for this layout on every platform,
  and an explicit `--format folder` is refused with the reason. The iOS `backup`
  layout can still be written as a folder. The GUI locks the output type to zip
  for this layout.
- GUI wording: the rebuild mode is now *Reconstruct structure like a Full File
  System acquisition*, the layouts *Full File System-like (zip)* and *iOS backup
  domains*; **Browse** picks a `Manifest.plist` or `.ab` file.

### Added

- **Zip-root artefacts** in every zip output:
  - `Manifest.db` — the decrypted `Manifest.db` (an exact copy when unencrypted);
  - `Manifest.mobile-backup-reconstruct.enriched.db` — the same database with a
    `Files.zipPath` column giving each row's member name in the archive (`NULL`
    when the row was not written);
  - `mobile-backup-reconstruct.traceability.txt` — a readable summary: source
    and device, SHA-256 of every source manifest file and every root artefact,
    options and statistics.
- **`<output>.zip.sha256`** beside the archive, in `sha256sum` format (an archive
  cannot contain its own digest). The CLI/GUI result reports `sha256` and
  `sha256_file`.
- Provenance records `platform` and `backup.manifest_db_plaintext_sha256`.
- **Android `adb backup` (`.ab`) support**, recognised by its header: format
  versions 1–5, compressed or not, and AES-256 encrypted archives (PBKDF2 key
  unlock with checksum validation, as AOSP does, including the version-1 8-bit
  fallback). The payload is decrypted, inflated and untarred as a stream into
  the same Full File System-like zip; paths are mapped by
  `config/android_maps/aosp_full_backup.yaml` (overridable with `--domain-map`).
  A truncated or corrupt payload fails closed. `--mode decrypt`, `--layout
  backup`, `--format folder` and `--try-default-passwords` are refused for `.ab`
  input, with the reason.

### Fixed

- The staging directory is removed through the Windows extended-length path, so
  a staged tree with long paths no longer makes the cleanup itself fail.

## [0.2.2] — 2026-10-01

### Fixed

- **`Status.plist` and `Info.plist` are no longer required.** Older backups may
  not carry them, and the tool rejected those outright with "Missing required
  backup file" — even though neither is read by reconstruction or decryption.
  Both carry provenance only; the genuinely load-bearing files are
  `Manifest.plist` (encryption state and key material) and `Manifest.db` (the file
  table), and those are still required.

  The filesystem layout still selects the right domain map without `Info.plist`,
  because the product version already falls back to `Manifest.plist`'s `Lockdown`
  dictionary.

  Absence is recorded, not glossed over: provenance gains an `absent_files` list,
  and the digest of a file the backup does not carry is `null` rather than
  fabricated — so a null can never be misread as "the tool failed to read it".
  `--info-only` reports `absent_files` too.

  A file that is *present but malformed* still raises. Missing means an older
  backup; corrupt means a problem the operator needs to see.

- **Long output paths no longer fail on Windows.** A reconstruction stopped with
  "path too long" partway through, because a rebuilt iOS path
  (`private/var/mobile/Containers/Data/Application/<bundle id>/Library/...`) plus
  the operator's destination easily exceeds Windows' 260-character limit. Output
  I/O now goes through the extended-length path form, which raises the limit to
  roughly 32,767 characters, so the files are written rather than skipped — losing
  evidence would be the worse failure. The run reports how many destinations
  exceed 260 characters (`stats.long_paths`), since a tool that does not handle
  long paths will not be able to open them. Traceability still records the plain
  path, not the prefixed one.

- The GUI mode selector is now a pair of radio buttons rather than a dropdown, so
  both options are visible at once.

- **Reconstruct and Decrypt now work on the first click in the GUI.** Pressing
  either on a fresh window runs an encryption check first, then the run. That
  chained run was started from the check's *finish* handler, which fires while the
  check's thread is still tearing down — so the teardown cleared the new run's
  thread reference, the thread was destroyed mid-run, and nothing was written.
  The window said "Reconstruction started..." and produced no output, and the
  operator had to press **Check encryption** first to work around it. The chained
  run now starts from the teardown handler instead, once the previous thread is
  fully finished.

- **The manifest walk is now ordered by logical name**, not by SQLite's table
  order. The order decides which of two colliding output paths keeps the
  unsuffixed name, and table order depends on SQLite internals — so a manifest
  rewritten by another tool could reorder the same content and move the `~1`.
  Sorting makes the output reproducible, and matches mf-scan, so the two tools now
  produce byte-identical trees from the same backup (verified on a real 815-file
  iPhone backup). SQLite performs the sort, so the walk stays streaming.

- **A leading dot is no longer stripped from filenames.** `sanitise_segment`
  trimmed dots and spaces from *both* ends of every path segment. Trimming the
  trailing end is right — Windows rejects trailing dots and spaces — but a leading
  dot is a legitimate, meaningful part of a Unix filename, and removing it renamed
  the evidence: `.GlobalPreferences.plist` was written out as
  `GlobalPreferences.plist`, a different file from the one the backup recorded.

  Found by validating against a real iPhone backup, where it affected
  `.GlobalPreferences.plist`, `.GlobalPreferences_m.plist`, `.FirstUnlock` and the
  `.backup/` directory. After the fix, the reconstruction agrees byte-for-byte
  with an independent implementation on every shared path.

- **An unreadable backup now fails with an actionable message.** Some acquisition
  tools write every file mode 000 — unreadable even by the owner — and that
  surfaced as a `PermissionError` traceback from deep inside the pipeline. The
  backup's files are now checked for readability up front, and the error names the
  cause and how to fix it on a working copy.

## [0.2.0] — 2026-09-30

### Added

- **`--mode decrypt`** — produce the same backup with its content in the clear,
  keeping the hash-addressed layout, instead of reconstructing a directory tree.
  The output is a structurally valid *unencrypted* backup, so tools that read iOS
  backups but cannot decrypt them can open it. Verified against an independent
  implementation (mf-scan), which reads the result as an unencrypted backup and
  confirms the recomputed digests with its own SHA-1 attestation.

  `--mode rebuild` (the default) is unchanged and still decrypts on the way.

  Because an encrypted backup records each `Digest` as the SHA-1 of the
  *ciphertext* and an unencrypted one records the SHA-1 of the *content*, three
  things are rewritten and all three are recorded in the traceability output:
  `Manifest.plist` (`IsEncrypted` false, key material removed), each `Files.file`
  record (`EncryptionKey` removed, `Digest` recomputed), and `Manifest.db` itself.
  Nothing else changes — records are re-encoded from the same decoded object graph,
  so uninterpreted fields survive byte-for-byte.

- The file manifest gains `manifest_digest_original` and
  `manifest_digest_rewritten` columns, so a rewritten digest is always auditable
  against the source's own value. Both are empty in `rebuild` mode.

- GUI mode selector. The action button names whichever mode is selected
  (**Reconstruct** / **Decrypt**), and the layout and output-type controls are
  disabled when they do not apply.

### Fixed

- **Keybag class keys are delimited by `CLAS`, not by `UUID`.** The parser started
  a new protection-class record at each `UUID` tag, so a keybag written without a
  per-class `UUID` yielded **no class keys at all** — and the failure surfaced as
  *"Could not unlock backup keybag. Check the backup password."* when the password
  was correct. Real iOS keybags do carry those UUIDs, so this only bit keybags
  written otherwise, but the misleading error would have sent an examiner after
  entirely the wrong problem. `CLAS` is the tag that defines a class, so it is now
  the one that delimits — matching mf-scan's independent parser.

- A keybag containing no protection-class keys is now reported as malformed rather
  than as a bad password.

### Changed

- `--layout`, `--domain-map` and `--format` are refused with `--mode decrypt`
  rather than silently ignored.

## [0.1.1] — 2026-09-28

### Fixed

- **`CameraRollDomain` and `MediaDomain` produced a doubled path segment** under
  the default `filesystem` layout. Both were mapped to
  `private/var/mobile/Media`, but their `relativePath` values already begin with
  `Media/`, so files were written to `private/var/mobile/Media/Media/…`. Both now
  map to `private/var/mobile`. Verified against 2,638 rows of a real iPhone
  reconstruction, where 35 paths were affected; the fix reduces doubled-segment
  paths from 39 to 4, and those 4 are genuine nested directories on the device
  (`model.mdl/model/model`, `Recents/Recents`), not mapping errors.

  A `MediaDomain` file whose `relativePath` did *not* begin with `Media/` was
  also misplaced — under `Media/Library/…` rather than `Library/…`.

  **If you reconstructed a backup with 0.1.0 using the default layout**, camera
  roll and media paths in that output carry an extra `Media` segment. The file
  contents and all recorded digests are unaffected; only the output paths, and
  the `output_path` column of the file manifest, are wrong. Re-running with
  0.1.1 produces the corrected tree.

## [0.1.0] — 2026-09-27

First public release.

### Added

- Reconstruct an iOS local backup from `Manifest.plist` and `Manifest.db` into a
  folder or a zip archive, in either a filesystem-like layout (the default) or
  the raw backup-domain layout.
- Decryption of encrypted backups: keybag parsing, PBKDF2 key derivation,
  AES key unwrapping and AES-CBC file decryption.
- Forensic traceability on every run — a provenance record (tool version, host,
  source manifest digests, device metadata, redacted command line) and a
  per-record file manifest with source and output SHA-256 digests.
- Domain-to-path mapping driven by editable YAML maps with iOS version ranges
  (`config/domain_maps/`).
- `--dry-run` to plan output paths without reconstructing content.
- `--continue-on-error` to keep successful files when some rows fail; the default
  is to fail closed and write a failure report instead.
- `--info-only` to print backup metadata without reconstructing.
- `--try-default-passwords` to opt in to trying the backup passwords commonly set
  by acquisition tools. Off by default, and recorded in the provenance artefact.
- Progress reporting: a terminal counter for the CLI (`--quiet` to suppress) and a
  progress bar in the GUI.
- Cancellation in the GUI. A cancelled run keeps what it wrote and is recorded as
  `cancelled` in the traceability output; the CLI reports exit code `3`.
- PySide6 interface with drag-and-drop input and output paths, an encryption
  check, and reconstruction on a background thread.
- Documentation in `docs/` covering the backup format, the encryption scheme, the
  CLI, task workflows, the traceability formats and the library API.

### Security

- The CLI does not accept a backup password as an argument, so it cannot leak into
  shell history or the process table. Passwords are read via `getpass`, and only
  when stdin is a terminal.
- Output path segments from the backup are sanitised, and output is always written
  relative to the chosen destination, so a crafted manifest cannot escape it.
