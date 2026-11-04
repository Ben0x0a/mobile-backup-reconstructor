# Documentation

Reference documentation for the Mobile Backup Reconstructor (iOS and Android backups).

## Pages

| Page | What it covers |
| --- | --- |
| [Getting started](getting-started.md) | Install, run a first reconstruction, read the output |
| [Concepts](concepts/index.md) | iOS backup layout, domains, encryption, Android `.ab` backups, what is recoverable |
| [CLI reference](cli/index.md) | Every command-line option, in workflow order |
| [Workflows](workflows/index.md) | Task-oriented, end-to-end guides |
| [Formats](formats/index.md) | Traceability artefacts and domain-map files |
| [Library](library/index.md) | Driving the engine from Python |
| [Architecture](architecture.md) | How the codebase is layered and why |

## Design principles

The tool is built for forensic use, which drives three rules that show up
throughout the code:

1. **The source is read-only evidence.** The backup directory is opened
   read-only and never written to. Output always goes somewhere else, and the
   tool refuses an output path inside the source backup.
2. **Fail closed.** If any row fails, no output is produced and a failure
   report is written instead. Partial output requires an explicit
   `--continue-on-error`.
3. **Everything is attributable.** Each run records the tool and version,
   source manifest hashes, per-file source and output SHA-256 digests, and the
   command line (with passwords redacted).
