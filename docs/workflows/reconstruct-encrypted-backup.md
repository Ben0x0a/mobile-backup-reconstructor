# Reconstruct an encrypted backup

## 1. Confirm encryption

```bash
uv run python main.py /path/to/backup /path/to/out --info-only
```

Look for `"encrypted": true`. This step needs neither the password nor the
`cryptography` package.

## 2. Plan the output

```bash
uv run python main.py /path/to/backup /path/to/out --dry-run
```

You will be asked for the password, because the planned paths come from
`Manifest.db`, which is itself encrypted. Review
`_traceability/mobile-backup-reconstruct.file-manifest.traceability.csv` to check
the mapping before committing disk space.

## 3. Reconstruct

```bash
uv run python main.py /path/to/backup /path/to/out
```

Enter the password at the prompt. Do not pass it as an argument — there is no
option for it, precisely so it cannot leak into shell history.

If the backup came from an acquisition tool that sets a known default password,
you can have those tried first:

```bash
uv run python main.py /path/to/backup /path/to/out --try-default-passwords
```

This is opt-in, and the run records that you enabled it. See
[Encryption](../concepts/encryption.md#default-passwords-are-opt-in).

## 4. Handle failures

By default the tool fails closed: if any row fails, nothing is produced and a
report is written to
`failed_traceability_reports/<output-name>-<timestamp>/`.

Read that report first. If the failures are understood and acceptable — for
example a handful of blobs missing from a truncated acquisition — rerun with:

```bash
uv run python main.py /path/to/backup /path/to/out --continue-on-error
```

This exits `2` and records every failed row in the file manifest.

## Disk space

Reconstruction writes into a staging directory alongside the output and
promotes it on success, so plan for the reconstructed size to be available at
the destination while the run is in progress.
