# Android backups (`adb backup`)

An `.ab` file is what `adb backup` writes. The format is defined by AOSP:
`PerformAdbBackupTask.java` writes it and `PerformAdbRestoreTask.java` reads it
(frameworks/base, `services/backup/`).

## Layout

A short text header, then the payload:

| Line | Content |
| --- | --- |
| 1 | `ANDROID BACKUP` |
| 2 | Format version, 1–5 |
| 3 | `1` if the payload is zlib-compressed, `0` otherwise |
| 4 | `none`, or `AES-256` |
| 5–9 | Only when encrypted: user-password salt, key-checksum salt, PBKDF2 rounds, user-key IV, encrypted key blob (all hex but the rounds) |

The payload is a **tar** archive, compressed then encrypted as the header says.
The tool recognises an `.ab` by line 1, never by its file name.

## From archive path to device path

There is no file table like iOS's `Manifest.db`: the tar member names are the
index. Each app's data is stored as `apps/<package>/<token>/<path>`, where the
token names one app directory (AOSP `FullBackup.java`, `*_TREE_TOKEN`):

| Token | Device directory (user 0) |
| --- | --- |
| `r` | `data/data/<package>` (app data root) |
| `f`, `db`, `sp`, `c`, `nb` | `files`, `databases`, `shared_prefs`, `cache`, `no_backup` under it |
| `d_r`, `d_f`, `d_db`, `d_sp`, `d_c`, `d_nb` | The same, under device-protected storage `data/user_de/0/<package>` |
| `ef` | `storage/emulated/0/Android/data/<package>/files` |
| `obb` | `storage/emulated/0/Android/obb/<package>` |
| `a` | `data/app/<package>` — the real directory name is randomised on the device and not recorded |
| `k` | Key/value backup records: no device path, kept under `backup_only/` |

`shared/<n>/` is shared storage; volume `0` maps to `storage/emulated/0`.
Entries with no device location — each app's `_manifest` and `_meta`, unknown
tokens, anything else — are kept under `backup_only/`, so nothing is dropped.

The mapping is the YAML file `config/android_maps/aosp_full_backup.yaml`; pass
another with `--domain-map`.

`data/data/<package>` is user 0's credential-encrypted data directory; on current
Android it is the same directory as `data/user/0/<package>`.

## What a backup does and does not contain

`adb backup` includes only apps that allow backup (`android:allowBackup`), and an
app can exclude files through its backup rules. It is deprecated on recent
Android versions, and many apps opt out. An empty or small package list is
therefore a property of the backup, not a reconstruction failure.

## Encryption

When line 4 is `AES-256`:

1. The **user key** is PBKDF2-HMAC-SHA1(password, user salt, rounds, 256 bits).
2. It decrypts the key blob (AES-256-CBC, user IV), which holds the payload IV,
   the payload key, and a checksum of that key.
3. The checksum is recomputed — PBKDF2 over the key bytes, each widened to a Java
   `char` exactly as AOSP's `PasswordUtils.makeKeyChecksum` does — and must match.
   A wrong password fails here, before anything is written.
4. The payload is decrypted with AES-256-CBC under that key and IV.

Version-1 archives may have been written with the older "8-bit" PBKDF2 variant;
like AOSP, the tool tries it as a fallback for version 1 only. Which one worked
is recorded as `key_derivation` in the provenance.

The tool prompts for the password on a terminal; the GUI takes it in the
password field. `--try-default-passwords` lists iOS acquisition-tool defaults and
is refused for `.ab` files.

## Integrity

A truncated or damaged payload (bad AES padding, a compressed stream with no end
marker, a broken tar block) fails the run closed, like any other read failure;
with `--continue-on-error` the members read before the damage are kept and
`backup.stream_error` records what happened.
