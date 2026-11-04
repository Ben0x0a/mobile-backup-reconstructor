"""Read an Android `adb backup` (.ab) file as a stream of tar members.

Defines: header parsing (`AbHeader`, `read_ab_header`, `is_android_backup`),
password unlocking of an encrypted archive (`unlock_encryption_key`), the
streamed decrypt -> inflate -> tar chain (`open_ab_tar`), and `inspect_android_backup`.
Used by: core.android_reconstructor, core.reconstructor (input detection, inspection).
Depends on: core.reconstructor (BackupError, require_crypto), cryptography (only
for encrypted archives).

── The format, as written by AOSP ─────────────────────────────────────────────
Source: frameworks/base services/backup/.../fullbackup/PerformAdbBackupTask.java
(writer) and restore/PerformAdbRestoreTask.java (reader). Text header lines,
each ending in `\\n`:

    1  ANDROID BACKUP                 magic
    2  <version>                      1..5 (BACKUP_FILE_VERSION = 5)
    3  1 | 0                          zlib-compressed or not
    4  none | AES-256                 encryption
    -- only when AES-256 --
    5  user password salt  [hex]
    6  key checksum salt   [hex]
    7  PBKDF2 rounds       [decimal]
    8  user key IV         [hex]
    9  encryption key blob [hex], AES-256-CBC under the user key; it holds
       [len][IV] [len][encryption key] [len][key checksum]

Then the payload: a tar stream, zlib-deflated when line 3 is 1, then
AES-256-CBC/PKCS5 encrypted under the blob's key and IV when line 4 is AES-256.

The user key is PBKDF2-HMAC-SHA1(password, user salt, rounds, 256 bits). The
checksum is the same PBKDF2 over the encryption key bytes, each widened to a
Java `char` exactly as `PasswordUtils.makeKeyChecksum` does. Version-1 archives
were written with the "8bit" PBKDF2 variant, so — like AOSP — both are tried.

The input file is only ever read.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from config.settings import CHUNK_SIZE
from core.reconstructor import BackupError, require_crypto

AB_MAGIC = b"ANDROID BACKUP\n"
# Highest archive version AOSP writes (UserBackupManagerService.BACKUP_FILE_VERSION).
AB_MAX_VERSION = 5
AB_ENCRYPTION_NONE = "none"
AB_ENCRYPTION_AES = "AES-256"
# Bound on a header line. WHY: a non-.ab file that happens to start with the
# magic must not make the reader slurp gigabytes looking for a newline.
AB_MAX_HEADER_LINE = 4096
# PBKDF2 output length used by AOSP (PasswordUtils.PBKDF2_KEY_SIZE, in bits / 8).
AB_KEY_BYTES = 32
# Key derivation regimes, named as in AOSP (BackupPasswordManager.PBKDF_*).
PBKDF_CURRENT = "PBKDF2WithHmacSHA1"
PBKDF_FALLBACK = "PBKDF2WithHmacSHA1And8bit"


class AndroidBackupError(BackupError):
    """Raised for an unreadable, unsupported or wrongly-unlocked `.ab` file."""


class AndroidPayloadError(AndroidBackupError):
    """Raised when the payload itself is truncated or corrupt.

    WHY distinct from AndroidBackupError: a wrong password or an unsupported
    header is refused outright, whereas a damaged payload is recorded as a
    failed run (fail closed, with a failure report) like any other read failure.
    """


# Everything a damaged payload can raise while being decrypted, inflated or untarred.
# Consumed by: core.android_reconstructor.
PAYLOAD_ERRORS = (AndroidPayloadError, tarfile.TarError, zlib.error, EOFError)


@dataclass
class AbHeader:
    """The parsed text header of an `.ab` file."""

    version: int
    compressed: bool
    encryption: str
    # Byte offset of the payload, just after the last header line.
    data_offset: int
    user_salt: bytes = b""
    checksum_salt: bytes = b""
    rounds: int = 0
    user_iv: bytes = b""
    key_blob: bytes = b""

    @property
    def encrypted(self) -> bool:
        return self.encryption != AB_ENCRYPTION_NONE


def is_android_backup(path: Path) -> bool:
    """Whether `path` is an `.ab` file, decided by its magic header, not its name."""
    if not path.is_file():
        return False
    try:
        with path.open("rb") as fh:
            return fh.read(len(AB_MAGIC)) == AB_MAGIC
    except OSError:
        return False


def _read_line(fh: BinaryIO) -> str:
    line = fh.readline(AB_MAX_HEADER_LINE)
    if not line.endswith(b"\n"):
        raise AndroidBackupError("Truncated or malformed Android backup header")
    return line[:-1].decode("ascii", errors="strict")


def read_ab_header(fh: BinaryIO) -> AbHeader:
    """Parse the header from the start of `fh`, leaving it at the payload."""
    if fh.read(len(AB_MAGIC)) != AB_MAGIC:
        raise AndroidBackupError("Not an Android backup: the file does not start with 'ANDROID BACKUP'")
    try:
        version = int(_read_line(fh))
        compressed = int(_read_line(fh)) != 0
        encryption = _read_line(fh)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AndroidBackupError("Malformed Android backup header") from exc
    # WHY refuse a newer version rather than try: AOSP itself refuses it, and a
    # format change we do not know about would be misread silently.
    if not 1 <= version <= AB_MAX_VERSION:
        raise AndroidBackupError(f"Unsupported Android backup version {version} (supported: 1-{AB_MAX_VERSION})")
    header = AbHeader(version=version, compressed=compressed, encryption=encryption, data_offset=0)
    if encryption == AB_ENCRYPTION_AES:
        try:
            header.user_salt = bytes.fromhex(_read_line(fh))
            header.checksum_salt = bytes.fromhex(_read_line(fh))
            header.rounds = int(_read_line(fh))
            header.user_iv = bytes.fromhex(_read_line(fh))
            header.key_blob = bytes.fromhex(_read_line(fh))
        except (ValueError, UnicodeDecodeError) as exc:
            raise AndroidBackupError("Malformed encryption header in Android backup") from exc
    elif encryption != AB_ENCRYPTION_NONE:
        raise AndroidBackupError(f"Unsupported Android backup encryption: {encryption!r}")
    header.data_offset = fh.tell()
    return header


def read_ab_header_from(path: Path) -> AbHeader:
    with path.open("rb") as fh:
        return read_ab_header(fh)


def _password_bytes(text: str, regime: str) -> bytes:
    """The bytes Java's PBKDF2 hashes for a char sequence, per regime.

    `PBKDF2WithHmacSHA1` encodes the chars as UTF-8; the `And8bit` variant keeps
    only the low 8 bits of each char.
    """
    if regime == PBKDF_CURRENT:
        return text.encode("utf-8")
    return bytes(ord(ch) & 0xFF for ch in text)


def _key_as_java_chars(key: bytes) -> str:
    """Widen each key byte to a Java `char`, as `makeKeyChecksum` does.

    HOW: `(char) b` on a signed Java byte sign-extends, so 0x00-0x7F stay as is
    and 0x80-0xFF become U+FF80-U+FFFF.
    WHY reproduce it: the stored checksum was computed over those chars, so a
    plain-bytes PBKDF2 would never match and every correct password would be
    reported as wrong.
    """
    return "".join(chr(b if b < 0x80 else 0xFF00 | b) for b in key)


def _pbkdf2(secret: bytes, salt: bytes, rounds: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", secret, salt, rounds, AB_KEY_BYTES)


def _aes_cbc_decrypt_unpad(key: bytes, iv: bytes, data: bytes) -> bytes | None:
    """AES-CBC decrypt and strip PKCS#7, or None when the padding is invalid."""
    Cipher, algorithms, modes, _ = require_crypto()
    from cryptography.hazmat.primitives import padding

    if len(data) % 16:
        return None
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        return None


def _split_key_blob(blob: bytes) -> tuple[bytes, bytes, bytes] | None:
    """Split `[len][IV][len][key][len][checksum]`, or None when it does not parse."""
    parts: list[bytes] = []
    offset = 0
    for _ in range(3):
        if offset >= len(blob):
            return None
        length = blob[offset]
        offset += 1
        if offset + length > len(blob):
            return None
        parts.append(blob[offset : offset + length])
        offset += length
    return parts[0], parts[1], parts[2]


def unlock_encryption_key(header: AbHeader, password: str) -> tuple[bytes, bytes, str]:
    """Return (key, IV, regime) for the payload, or raise on a wrong password.

    HOW: derive the user key, decrypt the key blob, and accept it only if the
    checksum recomputed over the recovered key matches the stored one — the
    same validation AOSP performs before it trusts a password.
    """
    regimes = [PBKDF_CURRENT] + ([PBKDF_FALLBACK] if header.version == 1 else [])
    for regime in regimes:
        user_key = _pbkdf2(_password_bytes(password, regime), header.user_salt, header.rounds)
        blob = _aes_cbc_decrypt_unpad(user_key, header.user_iv, header.key_blob)
        parts = _split_key_blob(blob) if blob is not None else None
        if parts is None:
            continue
        iv, key, checksum = parts
        computed = _pbkdf2(_password_bytes(_key_as_java_chars(key), regime), header.checksum_salt, header.rounds)
        if computed == checksum:
            return key, iv, regime
    raise AndroidBackupError("Could not unlock the Android backup. Check the backup password.")


class _TransformingReader(io.RawIOBase):
    """A read-only stream applying byte transforms (decrypt, inflate) on the fly.

    WHY: `tarfile` in stream mode wants a file object, and an `.ab` can be many
    gigabytes, so the payload is decrypted and inflated chunk by chunk rather
    than materialised.
    """

    def __init__(self, source: BinaryIO, stages: list[tuple[Callable[[bytes], bytes], Callable[[], bytes]]]) -> None:
        super().__init__()
        self._source = source
        self._stages = stages
        self._buffer = bytearray()
        self._eof = False

    def readable(self) -> bool:
        return True

    def _pump(self) -> None:
        chunk = self._source.read(CHUNK_SIZE)
        final = not chunk
        data = chunk
        for update, finish in self._stages:
            data = update(data) if data else b""
            if final:
                data += finish()
        self._buffer += data
        self._eof = final

    def readinto(self, target: Any) -> int:
        while not self._buffer and not self._eof:
            self._pump()
        count = min(len(target), len(self._buffer))
        target[:count] = self._buffer[:count]
        del self._buffer[:count]
        return count


def _decrypt_stage(key: bytes, iv: bytes) -> tuple[Callable[[bytes], bytes], Callable[[], bytes]]:
    Cipher, algorithms, modes, _ = require_crypto()
    from cryptography.hazmat.primitives import padding

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()

    def update(data: bytes) -> bytes:
        return unpadder.update(decryptor.update(data))

    def finish() -> bytes:
        try:
            return unpadder.update(decryptor.finalize()) + unpadder.finalize()
        except ValueError as exc:
            raise AndroidPayloadError("Android backup payload is truncated or corrupt (bad AES padding)") from exc

    return update, finish


def _inflate_stage() -> tuple[Callable[[bytes], bytes], Callable[[], bytes]]:
    inflater = zlib.decompressobj()

    def finish() -> bytes:
        tail = inflater.flush()
        # WHY check `eof`: `flush()` returns whatever it has without complaint
        # when the stream stops early, and tar tolerates a missing end-of-archive
        # marker — so a truncated backup would otherwise reconstruct "cleanly".
        if not inflater.eof:
            raise AndroidPayloadError("Android backup payload is truncated (the compressed stream does not end)")
        return tail

    return inflater.decompress, finish


@contextmanager
def open_ab_tar(path: Path, password: str | None) -> Iterator[tuple[AbHeader, str | None, tarfile.TarFile]]:
    """Open the archive's payload as a streaming tar.

    Yields (header, key-derivation regime or None, tar). The tar is in stream
    mode (`r|`): members must be read in order, each before the next is requested.
    """
    with path.open("rb") as fh:
        header = read_ab_header(fh)
        stages = []
        regime: str | None = None
        if header.encrypted:
            if not password:
                raise AndroidBackupError("This Android backup is encrypted and no password was supplied.")
            key, iv, regime = unlock_encryption_key(header, password)
            stages.append(_decrypt_stage(key, iv))
        if header.compressed:
            stages.append(_inflate_stage())
        reader = io.BufferedReader(_TransformingReader(fh, stages), CHUNK_SIZE)
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            yield header, regime, tar


def inspect_android_backup(path: Path) -> dict[str, Any]:
    """The header facts the GUI and `--info-only` show, without reading the payload."""
    header = read_ab_header_from(path)
    return {
        "backup": str(path.resolve()),
        "platform": "android",
        "encrypted": header.encrypted,
        "encryption": header.encryption,
        "format_version": header.version,
        "compressed": header.compressed,
        "device": None,
        "product": "Android (adb backup)",
        "ios": None,
    }
