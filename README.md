# Mobile Backup Reconstructor

Reconstructs a structure like a Full File System acquisition from a mobile
backup, as one zip archive:

- **iOS** local backups (iTunes / Finder): rebuilds the original paths from
  `Manifest.plist` and `Manifest.db`, which the backup flattens into hashed
  blobs. The decrypted `Manifest.db` and an enriched copy giving each file's
  path inside the zip are placed at the archive root.
- **Android** `adb backup` files (`.ab`): maps each app's data and shared storage
  back to its device path (`data/data/<package>/...`, `storage/emulated/0/...`).

Encrypted backups of both kinds are decrypted when the password is known. The
source is opened read-only and never modified. Every run writes traceability
artefacts — a readable summary with every hash, a provenance JSON, a per-file
manifest, and the archive's own SHA-256 beside it.

It is written to be **read as much as run**: the decryption path, the domain
mapping and the traceability output are all deliberately plain Python, and
[docs/](docs/README.md) explains the mechanism rather than just the options. If
you want to understand how an iOS backup is keyed and laid out, the source is the
point.

## Install

```bash
uv sync
```

## First run

Inspect a backup without writing anything:

```bash
uv run python main.py /path/to/ios-backup /path/to/output --info-only
```

Decrypt it, keeping the backup's own layout, into a backup any tool can read:

```bash
uv run python main.py /path/to/ios-backup /path/to/output --mode decrypt
```

Reconstruct it into `output.zip`, with a progress counter on a terminal:

```bash
uv run python main.py /path/to/ios-backup /path/to/output
uv run python main.py /path/to/backup.ab /path/to/output     # Android
```

Start the graphical interface:

```bash
uv run python main.py
```

## Documentation

Full documentation lives in [docs/](docs/README.md):

- [Getting started](docs/getting-started.md) — install, first reconstruction, reading the output
- [Concepts](docs/concepts/index.md) — how iOS and Android backups are laid out and what the tool can recover
- [CLI reference](docs/cli/index.md) — every option
- [Workflows](docs/workflows/index.md) — end-to-end task guides
- [Formats](docs/formats/index.md) — traceability artefacts and domain-map files
- [Library](docs/library/index.md) — using the engine from Python
- [Architecture](docs/architecture.md) — how the codebase is layered

## Related: mf-scan

[`mf-scan`](https://github.com/Ben0x0a) implements the same backup decryption in
Rust as part of a broader mobile-forensics toolkit. The two are complementary,
and which one you want depends on the job:

| | this tool | mf-scan |
| --- | --- | --- |
| Language | Python | Rust |
| Interface | CLI **and** drag-and-drop GUI | CLI |
| Best for | understanding the format; smaller backups; no toolchain needed | large acquisitions, searching and diffing across many archives |
| Speed | adequate; not optimised | memory-mapped, SIMD, multi-threaded |
| Blob integrity | SHA-256 of what it read and wrote | additionally verifies each blob's SHA-1 against `Manifest.db` |

If you are processing a large acquisition or need search and diff, use mf-scan.
If you want a GUI, or to read a straightforward implementation of the crypto, use
this one.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).

PySide6 is used under its LGPL-3.0 option and `cryptography` under
Apache-2.0/BSD-3-Clause; neither is redistributed here. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md), which also covers what changes
if you ever ship this as a frozen binary.

## Development & AI use

Generative AI was used in this project mainly to assist during the coding phase.
The original ideas and the overall structure are the owner's, and all core logic
has been reviewed. Even so, mistakes or bugs may have slipped past proof-reading —
please report anything unexpected.
