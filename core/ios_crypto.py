"""iOS backup decryption: keybag, Manifest.db and per-file keys.

Defines: keybag TLV parsing and unlocking (`Keybag`), `Manifest.db` decryption,
password handling (`prepare_manifest_db`, including the opt-in default
passwords), per-file key unwrapping and streamed AES-CBC file decryption.
Used by: core.ios_reconstructor, core.decryptor.
Depends on: core.crypto_backend, core.errors, core.ios_backup, config.settings.

See docs/concepts/encryption.md for the mechanism.
"""

from __future__ import annotations

import getpass
import hashlib
import logging
import struct
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

from config.settings import (
    CHUNK_SIZE,
    DEFAULT_BACKUP_PASSWORDS,
)
from core.crypto_backend import require_crypto
from core.errors import BackupError
from core.ios_backup import first_present, plist_data_value
from core.models import FileRecord

_LOG = logging.getLogger(__name__)


ZERO_IV = b"\x00" * 16


KEYBAG_CLASSKEY_TAGS = {b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"}


WRAP_PASSCODE = 2


def tlv_blocks(blob: bytes) -> Iterator[tuple[bytes, bytes]]:
    offset = 0
    while offset + 8 <= len(blob):
        tag = blob[offset : offset + 4]
        length = struct.unpack(">L", blob[offset + 4 : offset + 8])[0]
        start = offset + 8
        end = start + length
        if end > len(blob):
            raise BackupError(f"Malformed keybag TLV block {tag!r}: length exceeds blob")
        yield tag, blob[start:end]
        offset = end
    if offset != len(blob):
        raise BackupError("Malformed keybag TLV data: trailing bytes")


class Keybag:
    def __init__(self, data: bytes) -> None:
        self.attrs: dict[bytes, Any] = {}
        self.class_keys: dict[int, dict[bytes, Any]] = {}
        self._parse(data)

    def _parse(self, data: bytes) -> None:
        """Split the TLV stream into header attributes and per-class key records.

        HOW: walks the records in order. Everything before the first `CLAS` is a
        header attribute; each `CLAS` starts a new protection-class record, and the
        class tags that follow belong to it until the next `CLAS`.

        WHY `CLAS` delimits rather than `UUID`: a real keybag carries a per-class
        `UUID` before each `CLAS`, and delimiting on that appears to work — but a
        keybag written without those per-class UUIDs then yields NO class keys at
        all, and the failure surfaces as "check the backup password" when the
        password was right. `CLAS` is the tag that actually defines a class, so it
        is the one that delimits. Per-class `UUID`/`KTYP`/`PBKY` are not needed for
        an offline unwrap.
        """
        current: dict[bytes, Any] | None = None
        for tag, value in tlv_blocks(data):
            parsed: Any = struct.unpack(">L", value)[0] if len(value) == 4 else value
            if tag == b"CLAS":
                if current:
                    self._store_class_key(current)
                current = {tag: parsed}
                continue
            if current is not None and tag in KEYBAG_CLASSKEY_TAGS:
                current[tag] = parsed
                continue
            # A `UUID` seen inside the class section belongs to that class and is
            # not needed; keeping the header's own UUID means not overwriting it.
            if tag == b"UUID" and (current is not None or tag in self.attrs):
                continue
            self.attrs[tag] = parsed
        if current:
            self._store_class_key(current)

    def _store_class_key(self, class_key: dict[bytes, Any]) -> None:
        protection_class = class_key.get(b"CLAS")
        if not isinstance(protection_class, int):
            raise BackupError("Malformed keybag: class key missing CLAS")
        self.class_keys[protection_class] = class_key

    def unlock(self, password: str) -> None:
        _, _, _, aes_key_unwrap = require_crypto()
        try:
            dpsl = self.attrs[b"DPSL"]
            dpic = self.attrs[b"DPIC"]
            salt = self.attrs[b"SALT"]
            iterations = self.attrs[b"ITER"]
        except KeyError as exc:
            raise BackupError("Backup keybag is missing password derivation parameters") from exc

        password_bytes = password.encode("utf-8")
        passcode1 = hashlib.pbkdf2_hmac("sha256", password_bytes, dpsl, dpic, 32)
        passcode_key = hashlib.pbkdf2_hmac("sha1", passcode1, salt, iterations, 32)

        # No class keys means the walk found nothing to unwrap. Reporting that as
        # a bad password would send an examiner hunting for the wrong problem.
        if not self.class_keys:
            raise BackupError("Backup keybag contains no protection-class keys (malformed keybag)")

        failures = []
        for protection_class, class_key in self.class_keys.items():
            wrapped_key = class_key.get(b"WPKY")
            wrap_flags = class_key.get(b"WRAP", 0)
            if not isinstance(wrapped_key, bytes):
                failures.append(protection_class)
                continue
            if wrap_flags & WRAP_PASSCODE:
                try:
                    class_key[b"KEY"] = aes_key_unwrap(passcode_key, wrapped_key)
                except Exception:
                    failures.append(protection_class)
            else:
                class_key[b"KEY"] = wrapped_key
        if failures:
            raise BackupError("Could not unlock backup keybag. Check the backup password.")

    def unwrap_key(self, protection_class: int, persistent_key: bytes) -> bytes:
        _, _, _, aes_key_unwrap = require_crypto()
        class_key = self.class_keys.get(protection_class)
        if not class_key or b"KEY" not in class_key:
            raise BackupError(f"No unlocked key for protection class {protection_class}")
        try:
            return aes_key_unwrap(class_key[b"KEY"], persistent_key)
        except Exception as exc:
            raise BackupError(f"Could not unwrap key for class {protection_class}") from exc


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    Cipher, algorithms, modes, _ = require_crypto()
    if len(data) % 16:
        raise BackupError("Encrypted data length is not a multiple of AES block size")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def strip_pkcs7_if_present(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or pad_len > len(data):
        return data
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return data
    return data[:-pad_len]


def decrypt_manifest_db(backup_dir: Path, manifest: dict[str, Any], keybag: Keybag) -> bytes:
    manifest_key_blob = manifest.get("ManifestKey")
    if not isinstance(manifest_key_blob, bytes) or len(manifest_key_blob) < 8:
        raise BackupError("Manifest.plist does not contain a valid ManifestKey")
    protection_class = struct.unpack("<L", manifest_key_blob[:4])[0]
    manifest_key = keybag.unwrap_key(protection_class, manifest_key_blob[4:])
    encrypted = (backup_dir / "Manifest.db").read_bytes()
    decrypted = strip_pkcs7_if_present(aes_cbc_decrypt(encrypted, manifest_key))
    if not decrypted.startswith(b"SQLite format 3\x00"):
        raise BackupError("Decrypted Manifest.db does not look like SQLite")
    return decrypted


def try_unlock_keybag(keybag_blob: bytes, password: str) -> Keybag:
    keybag = Keybag(keybag_blob)
    keybag.unlock(password)
    return keybag


def prepare_manifest_db(
    backup_dir: Path,
    encrypted: bool,
    manifest: dict[str, Any],
    password: str | None,
    allow_prompt: bool = True,
    try_default_passwords: bool = False,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None, Keybag | None]:
    """Return a readable `Manifest.db`, decrypting it first when necessary.

    `try_default_passwords` opts in to trying `DEFAULT_BACKUP_PASSWORDS` before
    prompting. WHY it is opt-in: guessing passwords, even from a four-entry list
    of acquisition-tool defaults, is an action an examiner should choose and be
    able to account for, not a silent default. Whether it was enabled is
    recorded in the provenance artefact.
    """
    if not encrypted:
        return backup_dir / "Manifest.db", None, None
    require_crypto()
    keybag_blob = manifest.get("BackupKeyBag")
    if not isinstance(keybag_blob, bytes):
        raise BackupError("Encrypted backup is missing BackupKeyBag")

    candidate_passwords: list[str] = []
    tried_defaults = False
    prompted = False
    if password:
        candidate_passwords.append(password)
    else:
        if try_default_passwords:
            candidate_passwords.extend(DEFAULT_BACKUP_PASSWORDS)
            tried_defaults = True
        # Prompt only on a real terminal. WHY: getpass raises EOFError when
        # stdin is a pipe or closed, which would escape as a traceback on a
        # perfectly legitimate non-interactive run (CI, cron, a shell pipeline).
        if allow_prompt and sys.stdin is not None and sys.stdin.isatty():
            try:
                candidate_passwords.append(getpass.getpass("Backup password: "))
                prompted = True
            except (EOFError, KeyboardInterrupt) as exc:
                raise BackupError("No backup password was entered.") from exc

    # With no password, no usable prompt and no opt-in there is nothing to try,
    # and an empty loop would otherwise report a misleading "could not unlock".
    if not candidate_passwords:
        raise BackupError(
            "This backup is encrypted and no password was supplied. Provide one, "
            "or pass --try-default-passwords to try common acquisition-tool defaults first."
        )

    last_error: Exception | None = None
    for candidate in candidate_passwords:
        try:
            keybag = try_unlock_keybag(keybag_blob, candidate)
            decrypted_db = decrypt_manifest_db(backup_dir, manifest, keybag)
            tmp = tempfile.TemporaryDirectory(prefix="mobile_backup_manifest_")
            tmp_db = Path(tmp.name) / "Manifest.db"
            tmp_db.write_bytes(decrypted_db)
            if tried_defaults and candidate in DEFAULT_BACKUP_PASSWORDS:
                _LOG.warning(f"Backup unlocked with the default password {candidate!r}")
            return tmp_db, tmp, keybag
        except BackupError as exc:
            last_error = exc

    if password:
        raise BackupError("Could not unlock backup keybag. Check the backup password.") from last_error
    sources = ["the default passwords"] if tried_defaults else []
    if prompted:
        sources.append("the entered password")
    raise BackupError(f"Could not unlock backup keybag with {' or '.join(sources)}.") from last_error


def file_key_for_record(record: FileRecord, keybag: Keybag) -> bytes | None:
    key_blob = plist_data_value(first_present(record.metadata, ("EncryptionKey", "encryptionKey")))
    if key_blob is None:
        return None
    protection_class = first_present(record.metadata, ("ProtectionClass", "protectionClass"))
    if not isinstance(protection_class, int):
        raise BackupError("Encrypted backup record has no protection class")
    if len(key_blob) <= 4:
        raise BackupError("Invalid file encryption key blob")
    return keybag.unwrap_key(protection_class, key_blob[4:])


def decrypt_copy(src: Path, dst: BinaryIO, key: bytes, limit: int | None) -> tuple[int, str, str]:
    Cipher, algorithms, modes, _ = require_crypto()
    src_digest = hashlib.sha256()
    out_digest = hashlib.sha256()
    written = 0
    decryptor = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV)).decryptor()
    trailing = b""
    with src.open("rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            src_digest.update(chunk)
            data = trailing + chunk
            block_len = (len(data) // 16) * 16
            trailing = data[block_len:]
            if block_len:
                plain = decryptor.update(data[:block_len])
                plain = trim_to_limit(plain, written, limit)
                if plain:
                    dst.write(plain)
                    out_digest.update(plain)
                    written += len(plain)
    if trailing:
        raise BackupError("Encrypted file length is not a multiple of AES block size")
    final = decryptor.finalize()
    if final:
        final = trim_to_limit(final, written, limit)
        if final:
            dst.write(final)
            out_digest.update(final)
            written += len(final)
    return written, src_digest.hexdigest(), out_digest.hexdigest()


def trim_to_limit(data: bytes, written: int, limit: int | None) -> bytes:
    if limit is None:
        return data
    if written >= limit:
        return b""
    return data[: max(0, limit - written)]
