# Using the GUI

```bash
uv run python main.py
```

Running with no arguments starts the PySide6 interface.

## Fields

| Field | Purpose |
| --- | --- |
| Input backup | An iOS backup directory or its `Manifest.plist`, or an Android `.ab` file. Accepts drag and drop; **Browse** opens a file picker for `Manifest.plist` or `.ab` |
| Output folder | Where to write. Must already exist. Accepts drag and drop |
| Output type | Backup folder or zip archive. Locked to zip for the Full File System-like layout |
| Mode | *Reconstruct structure like a Full File System acquisition*, or *Decrypt only* (iOS: keep the backup's own layout) |
| Output layout | *Full File System-like (zip)* (default), or *iOS backup domains* |
| Output name | Name of the folder or archive created inside the output folder |
| Password | Required only for encrypted backups |
| Overwrite | Append to an existing folder, or replace an existing zip |

## Buttons

- **Check encryption** inspects the backup and reports device, iOS version and
  whether a password is needed, without writing anything.
- **Reconstruct** / **Decrypt** — the button names whichever the Mode field
  selects. It runs on a background thread, leaving the
  interface responsive. A progress bar shows files completed against the total
  from `Manifest.db`, with the current path beneath it (for an Android `.ab`,
  whose file count is unknown until the end, a busy bar and a running count). If the backup is
  encrypted and the password field is empty, it stops immediately and says so
  rather than failing minutes later.
- **Cancel** stops after the file in flight. Everything already written is kept,
  and the traceability manifest records the run as `cancelled` — so a stopped
  reconstruction is still attributable evidence, never a silently truncated tree
  that looks complete. The CLI reports the same outcome with exit code `3`.

## Differences from the CLI

The GUI never prompts for a password and never guesses one: it runs unattended
on a background thread, so it requires the password up front for an encrypted
backup and uses exactly what you typed. Use the CLI's
`--try-default-passwords` if you want acquisition-tool defaults tried. It always uses the shipped domain maps; use the CLI for
`--domain-map`, `--dry-run` or `--continue-on-error`.
