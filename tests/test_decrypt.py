"""Tests for `--mode decrypt`: producing a valid unencrypted backup.

Defines: an inline encrypted-backup builder and the tests that prove the decrypted
output is structurally a real unencrypted backup — decrypted content, metadata
rewritten exactly where it must be, and nothing else touched.
Used by: pytest / unittest discovery.
Depends on: core.decryptor, core.reconstructor, cryptography.

The fixtures are built in-process rather than committed, so the test states the
format it expects instead of trusting an opaque blob.
"""

import hashlib
import plistlib
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

from config import settings
from core import decryptor, errors, ios_crypto

PASSWORD = "1234"
PROTECTION_CLASS = 3
SALT = bytes(range(20))
DPSL = bytes(range(32))
ITER = 1000
DPIC = 1000
CLASS_KEY = bytes((i * 7 + 1) & 0xFF for i in range(32))
MANIFEST_KEY = bytes((i * 11 + 3) & 0xFF for i in range(32))


def aes_cbc(key: bytes, data: bytes) -> bytes:
    return Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).encryptor().update(data)


def pad16(data: bytes) -> bytes:
    return data if len(data) % 16 == 0 else data + bytes(16 - len(data) % 16)


def keybag_key() -> bytes:
    """The double-PBKDF2 derivation iOS 10.2+ uses for the backup keybag."""
    first = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), DPSL, DPIC, 32)
    return hashlib.pbkdf2_hmac("sha1", first, SALT, ITER, 32)


def tlv(tag: bytes, value: bytes) -> bytes:
    return tag + struct.pack(">I", len(value)) + value


def keybag_blob(with_class_uuid: bool = True) -> bytes:
    """A BackupKeyBag with one passcode-wrapped class.

    `with_class_uuid` controls whether a per-class `UUID` precedes the `CLAS`
    record. A real keybag carries one; the parser must not depend on it.
    """
    wrapped = aes_key_wrap(keybag_key(), CLASS_KEY)
    parts = [
        tlv(b"VERS", struct.pack(">I", 4)),
        tlv(b"TYPE", struct.pack(">I", 1)),
        tlv(b"UUID", bytes(16)),
        tlv(b"HMCK", bytes(40)),
        tlv(b"WRAP", struct.pack(">I", 0)),
        tlv(b"SALT", SALT),
        tlv(b"ITER", struct.pack(">I", ITER)),
        tlv(b"DPSL", DPSL),
        tlv(b"DPIC", struct.pack(">I", DPIC)),
    ]
    if with_class_uuid:
        parts.append(tlv(b"UUID", bytes(16)))
    parts += [
        tlv(b"CLAS", struct.pack(">I", PROTECTION_CLASS)),
        tlv(b"WRAP", struct.pack(">I", 3)),
        tlv(b"WPKY", wrapped),
    ]
    return b"".join(parts)


def mbfile(size: int, digest: bytes | None, encryption_key: bytes | None) -> bytes:
    """An NSKeyedArchiver MBFile carrying Size and optionally Digest/EncryptionKey."""
    record = {"Size": size}
    objects = ["$null", record]
    if encryption_key is not None:
        record["ProtectionClass"] = PROTECTION_CLASS
        record["EncryptionKey"] = plistlib.UID(len(objects))
        objects.append(encryption_key)
    if digest is not None:
        record["Digest"] = plistlib.UID(len(objects))
        objects.append(digest)
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)},
            "$objects": objects,
        },
        fmt=plistlib.FMT_BINARY,
    )


# (domain, relativePath, content, on_disk, has_digest)
FILES = [
    ("HomeDomain", "Library/SMS/sms.db", b"SQLite format 3\x00 marker\n", True, True),
    ("AppDomain-com.test.app", "Documents/notes.txt", b"hello SECRET world\n", True, False),
    ("HomeDomain", "Library/Missing/ghost.db", b"never written\n", False, True),
]


def file_id(domain: str, rel: str) -> str:
    return hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()  # noqa: S324 - the format's own rule


def build_encrypted_backup(root: Path, with_class_uuid: bool = True) -> Path:
    """An encrypted backup whose plaintext is known, for round-trip checking."""
    backup = root / "encrypted"
    backup.mkdir(parents=True)
    rows = []
    for domain, rel, content, on_disk, has_digest in FILES:
        fid = file_id(domain, rel)
        file_key = bytes((i * 13 + len(rel)) & 0xFF for i in range(32))
        ciphertext = aes_cbc(file_key, pad16(content))
        enc_key = struct.pack("<I", PROTECTION_CLASS) + aes_key_wrap(CLASS_KEY, file_key)
        # An encrypted backup records the digest of the CIPHERTEXT.
        digest = hashlib.sha1(ciphertext).digest() if has_digest else None  # noqa: S324
        rows.append((fid, domain, rel, 1, mbfile(len(content), digest, enc_key)))
        if on_disk:
            blob = backup / fid[:2] / fid
            blob.parent.mkdir(parents=True, exist_ok=True)
            blob.write_bytes(ciphertext)
    rows.append((("b" * 40), "HomeDomain", "Library", 2, mbfile(0, None, None)))

    plain_db = root / "plain.db"
    conn = sqlite3.connect(plain_db)
    conn.execute(
        "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)"
    )
    conn.executemany("INSERT INTO Files VALUES (?, ?, ?, ?, ?)", rows)
    conn.commit()
    conn.close()
    (backup / "Manifest.db").write_bytes(aes_cbc(MANIFEST_KEY, pad16(plain_db.read_bytes())))
    plain_db.unlink()

    manifest_key_blob = struct.pack("<I", PROTECTION_CLASS) + aes_key_wrap(CLASS_KEY, MANIFEST_KEY)
    (backup / "Manifest.plist").write_bytes(
        plistlib.dumps(
            {
                "IsEncrypted": True,
                "Version": "10.0",
                "BackupKeyBag": keybag_blob(with_class_uuid),
                "ManifestKey": manifest_key_blob,
                "Lockdown": {"ProductVersion": "17.0"},
            }
        )
    )
    (backup / "Info.plist").write_bytes(plistlib.dumps({"Device Name": "Test", "Product Version": "17.0"}))
    (backup / "Status.plist").write_bytes(plistlib.dumps({"IsFullBackup": True}))
    return backup


def manifest_rows(db: Path) -> dict[str, dict]:
    """Decoded MBFile records of an unencrypted Manifest.db, keyed by path.

    The connection is closed explicitly. WHY it matters: on Windows an open handle
    blocks deletion, so leaking it here made the temporary directory's cleanup fail
    — passing on Linux and macOS, which happily delete an open file, and failing
    only in CI.
    """
    out = {}
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT relativePath, flags, file FROM Files").fetchall()
    finally:
        conn.close()
    for rel, flags, blob in rows:
        if flags != 1:
            continue
        parsed = plistlib.loads(blob)
        objects = parsed["$objects"]
        record = objects[parsed["$top"]["root"].data]
        digest = None
        if isinstance(record.get("Digest"), plistlib.UID):
            digest = objects[record["Digest"].data]
        out[rel] = {"record": record, "digest": digest}
    return out


class DecryptTests(unittest.TestCase):
    def test_output_is_a_valid_unencrypted_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_encrypted_backup(root)
            out = root / "decrypted"
            result = decryptor.decrypt_backup(backup, out, password=PASSWORD, allow_password_prompt=False)

            self.assertFalse(result.cancelled)
            self.assertEqual(result.stats["written"], 2)
            self.assertEqual(result.stats["missing"], 1)
            self.assertEqual(result.stats["directories"], 1)

            # Content decrypts to the known plaintext, in the backup's own layout.
            for domain, rel, content, on_disk, _ in FILES:
                if not on_disk:
                    continue
                fid = file_id(domain, rel)
                self.assertEqual((out / fid[:2] / fid).read_bytes(), content, rel)

            # Manifest.plist now describes an unencrypted backup, with no key material.
            manifest = plistlib.loads((out / "Manifest.plist").read_bytes())
            self.assertIs(manifest["IsEncrypted"], False)
            self.assertNotIn("BackupKeyBag", manifest)
            self.assertNotIn("ManifestKey", manifest)
            # Unrelated keys survive untouched.
            self.assertEqual(manifest["Lockdown"], {"ProductVersion": "17.0"})

            # Manifest.db is readable plaintext SQLite with the keys stripped.
            rows = manifest_rows(out / "Manifest.db")
            for rel, row in rows.items():
                self.assertNotIn("EncryptionKey", row["record"], f"{rel} kept a wrapped key")

            # Digests now cover the PLAINTEXT, which is what an unencrypted backup
            # records — the whole reason the manifest has to be rewritten.
            sms = rows["Library/SMS/sms.db"]
            self.assertEqual(sms["digest"], hashlib.sha1(FILES[0][2]).digest())  # noqa: S324

            # A file with no recorded digest keeps none: adding one would invent
            # metadata the source never held.
            self.assertIsNone(rows["Documents/notes.txt"]["digest"])

            # Fields this tool does not interpret survive the re-encode.
            self.assertEqual(sms["record"]["Size"], len(FILES[0][2]))

    def test_missing_file_loses_its_key_but_keeps_its_recorded_digest(self):
        """A file the manifest lists but the backup does not hold cannot be
        decrypted, so its digest still describes ciphertext — but no wrapped key
        may survive in an output that declares itself unencrypted."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_encrypted_backup(root)
            out = root / "decrypted"
            decryptor.decrypt_backup(backup, out, password=PASSWORD, allow_password_prompt=False)

            ghost = manifest_rows(out / "Manifest.db")["Library/Missing/ghost.db"]
            self.assertNotIn("EncryptionKey", ghost["record"])
            self.assertIsNotNone(ghost["digest"], "the source's own record must survive")

    def test_traceability_records_both_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_encrypted_backup(root)
            out = root / "decrypted"
            decryptor.decrypt_backup(backup, out, password=PASSWORD, allow_password_prompt=False)

            manifest = (out / settings.TRACEABILITY_DIR_NAME / settings.TRACEABILITY_FILE_MANIFEST_NAME).read_text()
            self.assertIn("manifest_digest_original", manifest)
            self.assertIn("manifest_digest_rewritten", manifest)
            # The rewrite must be auditable: the original ciphertext digest is kept.
            original = hashlib.sha1(  # noqa: S324
                aes_cbc(
                    bytes((i * 13 + len("Library/SMS/sms.db")) & 0xFF for i in range(32)),
                    pad16(FILES[0][2]),
                )
            ).hexdigest()
            self.assertIn(original, manifest)

            provenance = (out / settings.TRACEABILITY_DIR_NAME / settings.TRACEABILITY_PROVENANCE_NAME).read_text()
            self.assertIn("rewritten_metadata", provenance)

    def test_decrypt_works_without_status_plist(self):
        """An older encrypted backup carrying no Status.plist still decrypts, and
        the output simply does not carry one either."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_encrypted_backup(root)
            (backup / "Status.plist").unlink()
            out = root / "decrypted"
            result = decryptor.decrypt_backup(backup, out, password=PASSWORD, allow_password_prompt=False)
            self.assertEqual(result.stats["written"], 2)
            self.assertFalse((out / "Status.plist").exists())
            self.assertTrue((out / "Info.plist").is_file(), "a file that IS present is copied")
            self.assertTrue((out / "Manifest.db").is_file())

    def test_decrypting_an_unencrypted_backup_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "plain"
            backup.mkdir()
            for name, payload in {
                "Manifest.plist": {"IsEncrypted": False},
                "Info.plist": {},
                "Status.plist": {},
            }.items():
                (backup / name).write_bytes(plistlib.dumps(payload))
            conn = sqlite3.connect(backup / "Manifest.db")
            conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
            conn.commit()
            conn.close()

            with self.assertRaises(errors.BackupError) as caught:
                decryptor.decrypt_backup(backup, root / "out", allow_password_prompt=False)
            self.assertIn("not encrypted", str(caught.exception))

    def test_keybag_parses_without_per_class_uuid(self):
        """Regression: class keys are delimited by `CLAS`, not by `UUID`.

        Delimiting on `UUID` yielded no class keys at all for a keybag written
        without per-class UUIDs, and the failure surfaced as "check the backup
        password" when the password was correct.
        """
        for with_uuid in (True, False):
            with self.subTest(per_class_uuid=with_uuid):
                keybag = ios_crypto.Keybag(keybag_blob(with_class_uuid=with_uuid))
                self.assertIn(PROTECTION_CLASS, keybag.class_keys)
                keybag.unlock(PASSWORD)
                self.assertEqual(keybag.class_keys[PROTECTION_CLASS][b"KEY"], CLASS_KEY)

    def test_a_keybag_with_no_class_keys_is_reported_as_malformed(self):
        """Not as a bad password — that sends an examiner after the wrong problem."""
        header_only = b"".join(
            [
                tlv(b"VERS", struct.pack(">I", 4)),
                tlv(b"SALT", SALT),
                tlv(b"ITER", struct.pack(">I", ITER)),
                tlv(b"DPSL", DPSL),
                tlv(b"DPIC", struct.pack(">I", DPIC)),
            ]
        )
        with self.assertRaises(errors.BackupError) as caught:
            ios_crypto.Keybag(header_only).unlock(PASSWORD)
        self.assertIn("malformed", str(caught.exception).lower())


if __name__ == "__main__":
    unittest.main()
