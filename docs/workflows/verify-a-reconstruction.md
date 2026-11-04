# Verify a reconstruction

Every run produces the evidence needed to check itself. The examples read a
zip output, `out.zip`; for a folder output read the same files from
`out/_traceability/` directly.

## Confirm the archive is the one produced

```bash
shasum -a 256 -c out.zip.sha256        # or: sha256sum -c out.zip.sha256
```

Then open `mobile-backup-reconstruct.traceability.txt` at the archive root: it
lists the source digests and the digest of every other root artefact.

```bash
unzip -p out.zip mobile-backup-reconstruct.traceability.txt
```

## Confirm the source was unchanged

`mobile-backup-reconstruct.provenance.traceability.json` records SHA-256 digests of
`Manifest.plist`, `Manifest.db`, `Info.plist` and `Status.plist` as they were
read. Re-hash the source backup and compare:

```bash
shasum -a 256 /path/to/backup/Manifest.db
unzip -p out.zip _traceability/mobile-backup-reconstruct.provenance.traceability.json \
  | jq -r '.backup.manifest_db_sha256' 
```

For an encrypted backup, the decrypted `Manifest.db` at the archive root matches
`backup.manifest_db_plaintext_sha256`:

```bash
unzip -p out.zip Manifest.db | shasum -a 256
```

## Confirm each file arrived intact

The file manifest carries `source_sha256` and `output_sha256` per row.

For an **unencrypted** backup the two must be identical — the blob is copied
verbatim:

```bash
unzip -p out.zip _traceability/mobile-backup-reconstruct.file-manifest.traceability.csv \
  | awk -F, 'NR>1 && $12=="written" && $7!=$8 {print "MISMATCH:", $3}' 
```

For an **encrypted** backup they differ by definition: `source_sha256` is the
ciphertext as stored, `output_sha256` the decrypted plaintext. Compare
`output_size` against `declared_size` instead.

## Confirm nothing was silently dropped

```bash
unzip -p out.zip _traceability/mobile-backup-reconstruct.provenance.traceability.json | jq '.stats' 
```

`records` must equal `written + missing + failed + directories`. A
`missing_source` row means `Manifest.db` listed a file whose blob is absent
from the backup — a property of the acquisition, not of the reconstruction.

## Confirm the output paths

Each row's `output_path` is the final destination (the member name, in a zip),
not a temporary one. For iOS, the enriched manifest at the archive root carries
the same member name per `Manifest.db` row, so the check is one query:

```bash
unzip -p out.zip Manifest.mobile-backup-reconstruct.enriched.db > enriched.db
sqlite3 enriched.db "SELECT COUNT(*) FROM Files WHERE zipPath IS NULL"
```

A `NULL` `zipPath` is a row that was not written; the file manifest says why.
