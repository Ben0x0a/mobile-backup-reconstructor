"""Tests for Android `adb backup` (.ab) reconstruction.

Defines: a synthetic `.ab` writer (plain, compressed, AES-256 encrypted), and
tests for header parsing, password unlocking, path mapping and the end-to-end
Full File System-like zip.
Used by: pytest / unittest discovery.
Depends on: core.android_backup, core.android_reconstructor, core.reconstructor,
config.settings, cryptography.

The writer follows AOSP PerformAdbBackupTask.emitAesBackupHeader. It is a
deliberate second implementation of the format's WRITE side: the reader under
test must agree with it, which a fixture produced by the reader itself could
never prove.
"""

import contextlib
import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import settings
from core import android_backup as ab
from core import android_reconstructor as arecon
from core import errors, output_paths, traceability
from core import reconstructor as recon
from launcher import cli

ROUNDS = 1000  # AOSP uses 10000; fewer keeps the suite fast and is equally valid


def build_tar(members: dict[str, bytes], directories: tuple[str, ...] = ()) -> bytes:
    buffer = io.BytesIO()
    # PAX when a name needs it, as AOSP does (libs/androidfw/BackupHelpers.cpp
    # write_tarfile: pax extended headers for long or non-7-bit-clean paths).
    needs_pax = any(len(name) > 100 or not name.isascii() for name in (*members, *directories))
    tar_format = tarfile.PAX_FORMAT if needs_pax else tarfile.USTAR_FORMAT
    with tarfile.open(fileobj=buffer, mode="w", format=tar_format) as tar:
        for name in directories:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mtime = 1_700_000_000
            tar.addfile(info)
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def aes_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def java_chars_utf8(key: bytes) -> bytes:
    return "".join(chr(b if b < 0x80 else 0xFF00 | b) for b in key).encode("utf-8")


def build_ab(tar_bytes: bytes, compressed: bool = True, password: str | None = None, version: int = 5) -> bytes:
    payload = zlib.compress(tar_bytes) if compressed else tar_bytes
    header = f"ANDROID BACKUP\n{version}\n{1 if compressed else 0}\n"
    if password is None:
        return (header + "none\n").encode() + payload
    user_salt, ck_salt = os.urandom(64), os.urandom(64)
    user_iv, data_iv = os.urandom(16), os.urandom(16)
    # Force high bytes into the key so the Java char-widening path is exercised.
    data_key = bytes([0xFF, 0x80]) + os.urandom(30)
    user_key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), user_salt, ROUNDS, 32)
    checksum = hashlib.pbkdf2_hmac("sha1", java_chars_utf8(data_key), ck_salt, ROUNDS, 32)
    blob = bytes([16]) + data_iv + bytes([32]) + data_key + bytes([32]) + checksum
    header += f"AES-256\n{user_salt.hex().upper()}\n{ck_salt.hex().upper()}\n{ROUNDS}\n"
    header += f"{user_iv.hex().upper()}\n{aes_encrypt(user_key, user_iv, blob).hex().upper()}\n"
    return header.encode() + aes_encrypt(data_key, data_iv, payload)


MEMBERS = {
    "apps/com.example.chat/_manifest": b"manifest",
    "apps/com.example.chat/db/messages.db": b"SQLite format 3\x00rows",
    "apps/com.example.chat/sp/prefs.xml": b"<map/>",
    "apps/com.example.chat/f/media/a.jpg": b"\xff\xd8jpeg",
    "apps/com.example.chat/d_db/de.db": b"device protected",
    "apps/com.example.chat/ef/cache.bin": b"external",
    "shared/0/DCIM/Camera/IMG_0001.jpg": b"\xff\xd8photo",
}


def run_cli(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()):
        return cli.main(argv)


class AndroidBackupTests(unittest.TestCase):
    def write_ab(self, root: Path, **kwargs) -> Path:
        path = root / "backup.ab"
        path.write_bytes(build_ab(build_tar(MEMBERS, ("apps/com.example.chat/f/media",)), **kwargs))
        return path

    def test_detection_is_by_header_not_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            renamed = root / "something.bin"
            renamed.write_bytes(build_ab(build_tar(MEMBERS)))
            self.assertTrue(ab.is_android_backup(renamed))
            fake = root / "fake.ab"
            fake.write_bytes(b"not a backup")
            self.assertFalse(ab.is_android_backup(fake))

    def test_header_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            header = ab.read_ab_header_from(self.write_ab(Path(tmp), password="secret"))
            self.assertEqual(header.version, 5)
            self.assertTrue(header.compressed)
            self.assertTrue(header.encrypted)
            self.assertEqual(header.rounds, ROUNDS)

    def test_newer_version_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.ab"
            path.write_bytes(b"ANDROID BACKUP\n6\n0\nnone\n")
            with self.assertRaises(ab.AndroidBackupError):
                ab.read_ab_header_from(path)

    def test_path_mapping(self):
        amap = arecon.load_android_map()
        cases = {
            "apps/com.x/db/a.db": "data/data/com.x/databases/a.db",
            "apps/com.x/r/app_webview/Cookies": "data/data/com.x/app_webview/Cookies",
            "apps/com.x/d_sp/p.xml": "data/user_de/0/com.x/shared_prefs/p.xml",
            "apps/com.x/ef/e.bin": "storage/emulated/0/Android/data/com.x/files/e.bin",
            "apps/com.x/_manifest": "backup_only/apps/com.x/_manifest",
            "apps/com.x/zz/q": "backup_only/apps/com.x/zz/q",
            "shared/0/DCIM/x.jpg": "storage/emulated/0/DCIM/x.jpg",
            "shared/1/x": "backup_only/shared/1/x",
            "odd/entry": "backup_only/odd/entry",
        }
        for archive_path, expected in cases.items():
            with self.subTest(archive_path=archive_path):
                self.assertEqual(arecon.android_output_path(archive_path, amap)[0].as_posix(), expected)

    def reconstruct(self, ab_path: Path, password: str | None = None) -> Path:
        output = ab_path.parent / "out.zip"
        arecon.reconstruct_android_backup(ab_path, output, password=password, allow_password_prompt=False)
        return output

    def assert_reconstructed(self, output: Path) -> None:
        with zipfile.ZipFile(output) as zf:
            self.assertEqual(
                zf.read("data/data/com.example.chat/databases/messages.db"),
                MEMBERS["apps/com.example.chat/db/messages.db"],
            )
            self.assertEqual(zf.read("storage/emulated/0/DCIM/Camera/IMG_0001.jpg"), b"\xff\xd8photo")
            self.assertIn("data/data/com.example.chat/files/media/", zf.namelist())
            # Regression: directories kept the run time instead of their tar mtime.
            self.assertEqual(
                zf.getinfo("data/data/com.example.chat/files/media/").date_time,
                datetime.fromtimestamp(1_700_000_000, UTC).timetuple()[:6],
            )
            provenance = json.loads(
                zf.read(f"{settings.TRACEABILITY_DIR_NAME}/{settings.TRACEABILITY_PROVENANCE_NAME}")
            )
            summary = zf.read(settings.ROOT_TRACEABILITY_TEXT_NAME).decode("utf-8-sig")
        self.assertEqual(provenance["platform"], "android")
        self.assertEqual(provenance["backup"]["packages"], ["com.example.chat"])
        self.assertEqual(provenance["stats"]["written"], len(MEMBERS))
        self.assertIn(provenance["backup"]["sha256"], summary)
        sidecar = output.with_name(output.name + settings.ZIP_HASH_SIDECAR_SUFFIX)
        self.assertTrue(sidecar.read_text().startswith(traceability.sha256_file(output)))

    def test_plain_uncompressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_reconstructed(self.reconstruct(self.write_ab(Path(tmp), compressed=False)))

    def test_plain_compressed_via_cli_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            ab_path = self.write_ab(Path(tmp))
            self.assertEqual(run_cli([str(ab_path), str(Path(tmp) / "out")]), 0)
            self.assert_reconstructed(Path(tmp) / "out.zip")

    def test_encrypted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_reconstructed(self.reconstruct(self.write_ab(Path(tmp), password="sécret"), "sécret"))

    def test_default_passwords_are_tried_only_when_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            ab_path = self.write_ab(Path(tmp), password="1234")
            with self.assertRaises(errors.BackupError):
                self.reconstruct(ab_path)  # no password, no opt-in: refused
            output = ab_path.parent / "out.zip"
            arecon.reconstruct_android_backup(ab_path, output, allow_password_prompt=False, try_default_passwords=True)
            self.assert_reconstructed(output)
            with zipfile.ZipFile(output) as zf:
                provenance = json.loads(
                    zf.read(f"{settings.TRACEABILITY_DIR_NAME}/{settings.TRACEABILITY_PROVENANCE_NAME}")
                )
            self.assertTrue(provenance["output"]["try_default_passwords"])

    def test_no_default_password_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            ab_path = self.write_ab(Path(tmp), password="not-a-default")
            with self.assertRaises(errors.BackupError) as caught:
                arecon.reconstruct_android_backup(
                    ab_path, ab_path.parent / "out.zip", allow_password_prompt=False, try_default_passwords=True
                )
            self.assertIn("none of the default passwords", str(caught.exception))

    def test_wrong_password_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            ab_path = self.write_ab(Path(tmp), password="right")
            with self.assertRaises(ab.AndroidBackupError):
                self.reconstruct(ab_path, "wrong")
            self.assertFalse((Path(tmp) / "out.zip").exists())

    def test_truncated_payload_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            ab_path = self.write_ab(Path(tmp))
            ab_path.write_bytes(ab_path.read_bytes()[:-40])
            with self.assertRaises(errors.ReconstructionFailedError):
                self.reconstruct(ab_path)
            self.assertFalse((Path(tmp) / "out.zip").exists())

    def test_paths_over_the_windows_limit_are_a_complete_zip(self):
        """Same guarantee as iOS: an over-length device path is only a zip member."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deep = "/".join(["AVeryDeeplyNestedDirectoryName" * 2] * 5) + "/payload.bin"
            ab_path = root / "long.ab"
            ab_path.write_bytes(build_ab(build_tar({f"apps/com.example.chat/f/{deep}": b"y" * 8}), password="pw"))
            output = self.reconstruct(ab_path, "pw")
            member = f"data/data/com.example.chat/files/{deep}"
            self.assertGreater(len(str(root / member)), output_paths.WINDOWS_MAX_PATH, "must exceed the limit")
            with zipfile.ZipFile(output) as zf:
                self.assertEqual(zf.read(member), b"y" * 8)

    def test_meaningless_options_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            ab_path = self.write_ab(Path(tmp))
            for argv in (["--layout", "backup"], ["--format", "folder"], ["--mode", "decrypt"]):
                with self.subTest(argv=argv):
                    self.assertEqual(run_cli([str(ab_path), str(Path(tmp) / "out"), *argv]), 1)

    def test_info_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = recon.inspect_backup(self.write_ab(Path(tmp), password="x"))
            self.assertEqual(info["platform"], "android")
            self.assertTrue(info["encrypted"])


if __name__ == "__main__":
    unittest.main()
