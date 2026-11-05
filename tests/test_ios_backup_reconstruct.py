"""Tests for the iOS backup reconstruction engine.

Defines: end-to-end reconstruction tests (folder and zip), domain-mapping
tests, and regression tests for traceability paths, size handling and
directory-record collisions.
Used by: pytest / unittest discovery.
Depends on: core.reconstructor, config.settings.
"""

import contextlib
import io
import json
import logging
import os
import plistlib
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from config import settings
from core import errors, ios_backup, ios_crypto, ios_domain_map, ios_reconstructor, models, output_paths, traceability
from launcher import cli


def run_cli(argv: list[str]) -> tuple[int, str]:
    """Invoke the CLI quietly, returning its exit code and logged diagnostics.

    HOW: swallows the JSON result on stdout and attaches a capturing handler to
    the root logger for the duration of the call.
    WHY: reconstruction prints its result to stdout and logs diagnostics to
    stderr by design, which would otherwise bury the test report. A handler is
    used rather than `redirect_stderr` because `logging.basicConfig` binds its
    stream at first call and ignores later redirection.
    """
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    root = logging.getLogger()
    root.addHandler(handler)
    previous_level = root.level
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(argv)
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)
    return rc, buffer.getvalue()


class ReconstructionTests(unittest.TestCase):
    def make_backup(self, root: Path, include_directory: bool = False) -> tuple[Path, bytes]:
        backup = root / "backup"
        backup.mkdir()
        for name, payload in {
            "Manifest.plist": {"IsEncrypted": False, "Version": "10.0"},
            "Info.plist": {"Device Name": "Test iPhone", "Product Version": "17.0"},
            "Status.plist": {"SnapshotState": "finished"},
        }.items():
            with (backup / name).open("wb") as fh:
                plistlib.dump(payload, fh)

        payload = b"hello forensic world"
        file_id = "0123456789abcdef0123456789abcdef01234567"
        source_dir = backup / file_id[:2]
        source_dir.mkdir()
        (source_dir / file_id).write_bytes(payload)

        conn = sqlite3.connect(backup / "Manifest.db")
        conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        metadata = plistlib.dumps({"Size": len(payload)})
        conn.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
            (file_id, "HomeDomain", "Library/SMS/sms.db", 1, metadata),
        )
        if include_directory:
            conn.execute(
                "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                ("b" * 40, "HomeDomain", "Library/SMS", 2, plistlib.dumps({})),
            )
        conn.commit()
        conn.close()
        return backup, payload

    def make_backup_with_sizes(self, root: Path, entries: dict[str, tuple[bytes, int]]) -> Path:
        """Build a backup whose rows declare a chosen ``Size``, which may differ
        from the real blob length."""
        backup = root / "backup"
        backup.mkdir()
        for name, payload in {
            "Manifest.plist": {"IsEncrypted": False},
            "Info.plist": {"Product Version": "17.0"},
            "Status.plist": {},
        }.items():
            (backup / name).write_bytes(plistlib.dumps(payload))
        conn = sqlite3.connect(backup / "Manifest.db")
        conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
        for index, (relative_path, (blob, declared_size)) in enumerate(entries.items()):
            file_id = f"{index:02x}" + "a" * 38
            (backup / file_id[:2]).mkdir(exist_ok=True)
            (backup / file_id[:2] / file_id).write_bytes(blob)
            conn.execute(
                "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
                (file_id, "HomeDomain", relative_path, 1, plistlib.dumps({"Size": declared_size})),
            )
        conn.commit()
        conn.close()
        return backup

    def test_info_only_encrypted_backup_does_not_need_crypto(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup, _ = self.make_backup(Path(tmp))
            with (backup / "Manifest.plist").open("wb") as fh:
                plistlib.dump({"IsEncrypted": True}, fh)
            with mock.patch("core.ios_crypto.require_crypto", side_effect=AssertionError("crypto used")):
                rc, _ = run_cli([str(backup), "unused", "--info-only"])
            self.assertEqual(rc, 0)

    def test_reconstruct_unencrypted_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, payload = self.make_backup(root, include_directory=True)
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
            self.assertEqual(rc, 0)
            restored = output / "HomeDomain" / "Library" / "SMS" / "sms.db"
            self.assertEqual(restored.read_bytes(), payload)
            trace = output / settings.TRACEABILITY_DIR_NAME / settings.TRACEABILITY_FILE_MANIFEST_NAME
            trace_text = trace.read_text()
            self.assertIn("written", trace_text)
            self.assertIn("directory_record", trace_text)

    def test_folder_output_ignores_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, payload = self.make_backup(root)
            output = root / "out"
            output.mkdir()
            (output / ".DS_Store").write_bytes(b"finder metadata")
            rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
            self.assertEqual(rc, 0)
            restored = output / "HomeDomain" / "Library" / "SMS" / "sms.db"
            self.assertEqual(restored.read_bytes(), payload)

    def test_folder_output_blocks_existing_traceability_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            output = root / "out"
            (output / settings.TRACEABILITY_DIR_NAME).mkdir(parents=True)
            rc, _ = run_cli([str(backup), str(output), "--format", "folder"])
            self.assertEqual(rc, 1)

    def test_reconstruct_unencrypted_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, payload = self.make_backup(root)
            output = root / "out.zip"
            rc, _ = run_cli([str(backup), str(output), "--format", "zip", "--layout", "backup"])
            self.assertEqual(rc, 0)
            with zipfile.ZipFile(output) as zf:
                self.assertEqual(zf.read("HomeDomain/Library/SMS/sms.db"), payload)
                self.assertIn(
                    f"{settings.TRACEABILITY_DIR_NAME}/{settings.TRACEABILITY_PROVENANCE_NAME}", zf.namelist()
                )

    def test_default_reconstructs_unencrypted_filesystem_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, payload = self.make_backup(root)
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output)])
            self.assertEqual(rc, 0)
            # The Full File System-like layout is always a zip, on every platform.
            with zipfile.ZipFile(root / "out.zip") as zf:
                self.assertEqual(zf.read("private/var/mobile/Library/SMS/sms.db"), payload)

    def test_filesystem_layout_refuses_an_explicit_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            rc, logged = run_cli([str(backup), str(root / "out"), "--format", "folder"])
            self.assertEqual(rc, 1)
            self.assertIn("always written as a zip", logged)
            self.assertFalse((root / "out").exists())

    def test_zip_root_carries_manifest_enriched_manifest_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root, include_directory=True)
            output = root / "out.zip"
            rc, _ = run_cli([str(backup), str(output)])
            self.assertEqual(rc, 0)
            with zipfile.ZipFile(output) as zf:
                names = zf.namelist()
                self.assertEqual(zf.read(settings.ROOT_MANIFEST_DB_NAME), (backup / "Manifest.db").read_bytes())
                enriched = root / "enriched.db"
                enriched.write_bytes(zf.read(settings.ENRICHED_MANIFEST_NAME))
                summary = zf.read(settings.ROOT_TRACEABILITY_TEXT_NAME).decode("utf-8-sig")
            conn = sqlite3.connect(enriched)
            zip_paths = dict(conn.execute(f"SELECT relativePath, {settings.ENRICHED_ZIP_PATH_COLNAME} FROM Files"))
            conn.close()
            # Every enriched path names a real member of the archive.
            self.assertEqual(zip_paths["Library/SMS/sms.db"], "private/var/mobile/Library/SMS/sms.db")
            for zip_path in zip_paths.values():
                self.assertIn(zip_path, names)
            self.assertIn(traceability.sha256_file(backup / "Manifest.plist"), summary)
            self.assertIn(settings.TOOL_NAME, summary)
            sidecar = root / f"out.zip{settings.ZIP_HASH_SIDECAR_SUFFIX}"
            self.assertEqual(sidecar.read_text(), f"{traceability.sha256_file(output)}  out.zip\n")

    def test_filesystem_domain_mapping(self):
        self.assertEqual(
            ios_domain_map.mapped_output_path("AppDomain-com.example.app", "Library/test.db", "filesystem").as_posix(),
            "private/var/mobile/Containers/Data/Application/com.example.app/Library/test.db",
        )
        self.assertEqual(
            ios_domain_map.mapped_output_path(
                "SysSharedContainerDomain-systemgroup.example", "data.db", "filesystem"
            ).as_posix(),
            "private/var/containers/Shared/SystemGroup/systemgroup.example/data.db",
        )
        self.assertEqual(
            ios_domain_map.mapped_output_path("HealthDomain", "Health/healthdb.sqlite", "filesystem").as_posix(),
            "private/var/mobile/Library/Health/healthdb.sqlite",
        )
        self.assertEqual(
            ios_domain_map.mapped_output_path(
                "HomeKitDomain", "Library/homed/datastore.sqlite", "filesystem"
            ).as_posix(),
            "private/var/mobile/Library/homed/datastore.sqlite",
        )
        self.assertEqual(
            ios_domain_map.mapped_output_path(
                "KeyboardDomain", "Library/Keyboard/user_model_database.sqlite", "filesystem"
            ).as_posix(),
            "private/var/mobile/Library/Keyboard/user_model_database.sqlite",
        )

    def test_domain_roots_do_not_double_a_relative_path_segment(self):
        """Regression: a domain root must not repeat a segment the relativePath
        already carries.

        Verified against 2,638 rows of a real iPhone reconstruction: every
        CameraRollDomain path begins `Media/`, so a root of
        `private/var/mobile/Media` produced `private/var/mobile/Media/Media/...`.
        35 paths were affected, under the DEFAULT filesystem layout.
        """
        cases = [
            ("CameraRollDomain", "Media/PhotoData/Photos.sqlite", "private/var/mobile/Media/PhotoData/Photos.sqlite"),
            (
                "CameraRollDomain",
                "Media/DCIM/100APPLE/IMG_0001.JPG",
                "private/var/mobile/Media/DCIM/100APPLE/IMG_0001.JPG",
            ),
            ("MediaDomain", "Media/Recordings/x.m4a", "private/var/mobile/Media/Recordings/x.m4a"),
            # A MediaDomain path not starting with Media/ lands under Library,
            # not under Media/Library.
            ("MediaDomain", "Library/Logs/x.log", "private/var/mobile/Library/Logs/x.log"),
            # Unchanged mappings, guarding against over-correction.
            ("HomeDomain", "Library/SMS/sms.db", "private/var/mobile/Library/SMS/sms.db"),
            ("HealthDomain", "Health/healthdb.sqlite", "private/var/mobile/Library/Health/healthdb.sqlite"),
        ]
        for domain, relative_path, expected in cases:
            with self.subTest(domain=domain, relative_path=relative_path):
                mapped = ios_domain_map.mapped_output_path(domain, relative_path, "filesystem").as_posix()
                self.assertEqual(mapped, expected)
                segments = mapped.split("/")
                doubled = [a for a, b in zip(segments, segments[1:], strict=False) if a == b]
                self.assertEqual(doubled, [], f"doubled segment in {mapped}")

    def test_custom_domain_map_yaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping = Path(tmp) / "domain_mounts.yaml"
            mapping.write_text(
                "\n".join(
                    [
                        "name: Custom test map",
                        "ios_versions:",
                        "  min: '1.0'",
                        "  max: '99.0'",
                        "exact_domains:",
                        "  HomeDomain: custom/mobile",
                        "prefix_domains:",
                        "  AppDomain-: custom/apps/{suffix}",
                        "unknown_domain_template: custom/unknown/{domain}",
                    ]
                ),
                encoding="utf-8",
            )
            domain_map = ios_domain_map.load_domain_mounts(mapping)
            self.assertEqual(
                ios_domain_map.mapped_output_path("HomeDomain", "Library/test.db", "filesystem", domain_map).as_posix(),
                "custom/mobile/Library/test.db",
            )
            self.assertEqual(
                ios_domain_map.mapped_output_path(
                    "AppDomain-com.example", "Documents/a.txt", "filesystem", domain_map
                ).as_posix(),
                "custom/apps/com.example/Documents/a.txt",
            )

    def test_domain_map_directory_selects_first_matching_ios_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_map = root / "01_old.yaml"
            current_map = root / "02_current.yaml"
            old_map.write_text(
                "\n".join(
                    [
                        "name: Old map",
                        "ios_versions:",
                        "  min: '1.0'",
                        "  max: '12.999'",
                        "exact_domains:",
                        "  HomeDomain: old/mobile",
                    ]
                ),
                encoding="utf-8",
            )
            current_map.write_text(
                "\n".join(
                    [
                        "name: Current map",
                        "ios_versions:",
                        "  min: '13.0'",
                        "  max: '18.999'",
                        "exact_domains:",
                        "  HomeDomain: current/mobile",
                        "prefix_domains:",
                        "unknown_domain_template: unknown/{domain}",
                    ]
                ),
                encoding="utf-8",
            )
            domain_map = ios_domain_map.load_domain_mounts(root, "14.0.1")
            self.assertEqual(domain_map["name"], "Current map")
            self.assertEqual(
                ios_domain_map.mapped_output_path("HomeDomain", "Library/test.db", "filesystem", domain_map).as_posix(),
                "current/mobile/Library/test.db",
            )

    def test_failed_reconstruction_does_not_leave_output_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            output = root / "out.zip"
            with mock.patch("core.ios_reconstructor.copy_plain", side_effect=RuntimeError("copy failed")):
                rc, stderr_text = run_cli([str(backup), str(output), "--format", "zip"])
            self.assertEqual(rc, 1)
            self.assertFalse(output.exists())
            self.assertIn("Failure report:", stderr_text)
            reports = list((root / settings.FAILURE_REPORT_DIR_NAME).glob("out-*"))
            self.assertEqual(len(reports), 1)
            report = reports[0] / settings.TRACEABILITY_FILE_MANIFEST_NAME
            self.assertIn("copy failed", report.read_text())

    def test_continue_on_error_produces_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            output = root / "out.zip"
            with mock.patch("core.ios_reconstructor.copy_plain", side_effect=RuntimeError("copy failed")):
                rc, _ = run_cli([str(backup), str(output), "--format", "zip", "--continue-on-error"])
            self.assertEqual(rc, 2)
            self.assertTrue(output.exists())
            with zipfile.ZipFile(output) as zf:
                report = zf.read(
                    f"{settings.TRACEABILITY_DIR_NAME}/{settings.TRACEABILITY_FILE_MANIFEST_NAME}"
                ).decode()
            self.assertIn("failed", report)
            self.assertIn("copy failed", report)

    def test_dry_run_writes_traceability_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            output = root / "out.zip"
            rc, _ = run_cli([str(backup), str(output), "--dry-run"])
            self.assertEqual(rc, 0)
            with zipfile.ZipFile(output) as zf:
                self.assertNotIn("private/var/mobile/Library/SMS/sms.db", zf.namelist())
                self.assertIn(
                    "planned",
                    zf.read(f"{settings.TRACEABILITY_DIR_NAME}/{settings.TRACEABILITY_FILE_MANIFEST_NAME}").decode(),
                )

    def test_directory_record_after_its_children_does_not_duplicate(self):
        """Regression: a directory row arriving after its files kept the real
        folder and no longer produces an empty ``~1`` decoy beside it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root, include_directory=True)
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
            self.assertEqual(rc, 0)
            sms_dir = output / "HomeDomain" / "Library" / "SMS"
            self.assertTrue((sms_dir / "sms.db").is_file())
            self.assertFalse((output / "HomeDomain" / "Library" / "SMS~1").exists())

    def test_plain_copy_is_not_truncated_to_declared_size(self):
        """Regression: an unencrypted blob is copied verbatim. A stale or zero
        ``Size`` in the metadata must not silently truncate intact evidence."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = self.make_backup_with_sizes(root, {"a/zerosize.bin": (b"X" * 100, 0)})
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
            self.assertEqual(rc, 0)
            restored = output / "HomeDomain" / "a" / "zerosize.bin"
            self.assertEqual(restored.read_bytes(), b"X" * 100)
            manifest = (output / settings.TRACEABILITY_DIR_NAME / settings.TRACEABILITY_FILE_MANIFEST_NAME).read_text()
            row = [line for line in manifest.splitlines() if "zerosize.bin" in line][0]
            # Source and output digests match: nothing was dropped.
            self.assertEqual(row.split(",")[6], row.split(",")[7])

    def test_file_manifest_records_the_final_output_path(self):
        """Regression: rows recorded the temporary staging directory, leaving a
        forensic manifest pointing at a path that no longer exists."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
            self.assertEqual(rc, 0)
            manifest_path = output / settings.TRACEABILITY_DIR_NAME / settings.TRACEABILITY_FILE_MANIFEST_NAME
            manifest = manifest_path.read_text()
            self.assertNotIn("mobile_backup_output_", manifest)
            row = [line for line in manifest.splitlines() if "sms.db" in line][0]
            recorded = Path(row.split(",")[5])
            self.assertEqual(recorded, output / "HomeDomain" / "Library" / "SMS" / "sms.db")
            self.assertTrue(recorded.is_file())

    def test_traceability_filenames_carry_the_tool_tag(self):
        self.assertIn(settings.TOOL_NAME, settings.TRACEABILITY_PROVENANCE_NAME)
        self.assertIn(settings.TOOL_NAME, settings.TRACEABILITY_FILE_MANIFEST_NAME)

    def test_mode_defaults_to_rebuild(self):
        self.assertEqual(cli.parse_args(["backup", "output"]).mode, "rebuild")
        self.assertEqual(cli.parse_args(["backup", "output", "--mode", "decrypt"]).mode, "decrypt")

    def test_flags_with_no_meaning_in_decrypt_mode_are_refused(self):
        """Silently ignoring them would hand the operator an output they did not
        ask for, with no way to notice."""
        for flag in (["--layout", "filesystem"], ["--domain-map", "x"], ["--format", "zip"]):
            with self.subTest(flag=flag[0]):
                argv = ["backup", "output", "--mode", "decrypt", *flag]
                args = cli.parse_args(argv)
                with self.assertRaises(errors.BackupError) as caught:
                    cli.reject_conflicting_mode_flags(args, argv)
                self.assertIn(flag[0], str(caught.exception))

    def test_rebuild_mode_accepts_every_flag(self):
        argv = ["backup", "output", "--layout", "filesystem", "--format", "zip"]
        cli.reject_conflicting_mode_flags(cli.parse_args(argv), argv)

    def test_backup_without_the_optional_plists_still_reconstructs(self):
        """Older backups may carry no Status.plist (and no Info.plist).

        Neither is read by reconstruction or decryption — they carry provenance
        only — so requiring them rejected backups this tool can handle.
        """
        for absent in (["Status.plist"], ["Info.plist"], ["Status.plist", "Info.plist"]):
            with self.subTest(absent=absent), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                backup, payload = self.make_backup(root)
                for name in absent:
                    (backup / name).unlink()
                output = root / "out"
                rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
                self.assertEqual(rc, 0)
                restored = output / "HomeDomain" / "Library" / "SMS" / "sms.db"
                self.assertEqual(restored.read_bytes(), payload)

    def test_absent_optional_files_are_recorded_not_fabricated(self):
        """A null digest must never be ambiguous between 'the backup lacks the
        file' and 'the tool could not read it'."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            (backup / "Status.plist").unlink()
            output = root / "out.zip"
            rc, _ = run_cli([str(backup), str(output)])
            self.assertEqual(rc, 0)

            with zipfile.ZipFile(output) as zf:
                provenance = json.loads(
                    zf.read(f"{settings.TRACEABILITY_DIR_NAME}/{settings.TRACEABILITY_PROVENANCE_NAME}")
                )["backup"]
            self.assertEqual(provenance["absent_files"], ["Status.plist"])
            self.assertIsNone(provenance["status_plist_sha256"])
            # The file that IS present still gets a real digest.
            self.assertIsNotNone(provenance["info_plist_sha256"])

    def test_the_domain_map_is_still_selected_without_info_plist(self):
        """Product version falls back to Manifest.plist's Lockdown dict."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, payload = self.make_backup(root)
            (backup / "Info.plist").unlink()
            with (backup / "Manifest.plist").open("wb") as fh:
                plistlib.dump({"IsEncrypted": False, "Lockdown": {"ProductVersion": "17.0"}}, fh)
            output = root / "out.zip"
            rc, _ = run_cli([str(backup), str(output)])
            self.assertEqual(rc, 0)
            # The filesystem layout requires a domain map, so this proves one was chosen.
            with zipfile.ZipFile(output) as zf:
                self.assertEqual(zf.read("private/var/mobile/Library/SMS/sms.db"), payload)

    def test_manifest_files_are_still_required(self):
        for name in ("Manifest.plist", "Manifest.db"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                backup, _ = self.make_backup(root)
                (backup / name).unlink()
                with self.assertRaises(errors.BackupError) as caught:
                    ios_backup.resolve_backup_dir(backup)
                self.assertIn(name, str(caught.exception))

    def test_a_present_but_malformed_optional_plist_still_raises(self):
        """Missing means an older backup; corrupt means a problem to surface."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            (backup / "Status.plist").write_bytes(b"not a plist at all")
            with self.assertRaises(plistlib.InvalidFileException):
                ios_backup.read_optional_plist(backup / "Status.plist")

            # A plist that parses but is not a dictionary is also a problem.
            with (backup / "Status.plist").open("wb") as fh:
                plistlib.dump(["not", "a", "dict"], fh)
            with self.assertRaises(errors.BackupError):
                ios_backup.read_optional_plist(backup / "Status.plist")

    def test_an_unreadable_backup_fails_with_an_actionable_message(self):
        """Some acquisition tools write the backup mode 000 — unreadable even by
        its owner. That surfaced as a PermissionError traceback from deep in the
        pipeline; it must be one sentence naming the cause and the fix."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup, _ = self.make_backup(root)
            target = backup / "Manifest.db"
            original_mode = target.stat().st_mode
            target.chmod(0o000)
            try:
                if os.access(target, os.R_OK):
                    self.skipTest("cannot drop read permission here (running as root?)")
                with self.assertRaises(errors.BackupError) as caught:
                    ios_backup.resolve_backup_dir(backup)
                message = str(caught.exception)
                self.assertIn("Manifest.db", message)
                self.assertIn("permission denied", message.lower())
                # The message must tell the operator what to do about it.
                self.assertIn("chmod", message)
            finally:
                target.chmod(original_mode)

    def test_a_leading_dot_is_preserved_but_a_trailing_one_is_not(self):
        """Regression: a leading dot is part of a Unix filename; stripping it
        renames the evidence. A TRAILING dot or space is illegal on Windows and is
        still removed.

        Found against a real iPhone backup, where `.GlobalPreferences.plist`,
        `.FirstUnlock` and `.backup/` were all written out without their dot.
        """
        keep = [
            ".GlobalPreferences.plist",
            ".FirstUnlock",
            ".backup",
            ".Photos_SUPPORT",
            ".hidden.with.dots",
        ]
        for segment in keep:
            with self.subTest(segment=segment):
                self.assertEqual(output_paths.sanitise_segment(segment), segment)

        # Trailing dots/spaces are still removed (Windows rejects them).
        self.assertEqual(output_paths.sanitise_segment("trailing."), "trailing")
        self.assertEqual(output_paths.sanitise_segment("trailing "), "trailing")
        self.assertEqual(output_paths.sanitise_segment(".both. "), ".both")
        # A segment that is only dots/spaces still yields a usable name.
        self.assertEqual(output_paths.sanitise_segment("  "), "_")

    def test_dotfiles_survive_a_full_reconstruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = self.make_backup_with_sizes(root, {"Library/.GlobalPreferences.plist": (b"x" * 8, 8)})
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
            self.assertEqual(rc, 0)
            self.assertTrue(
                (output / "HomeDomain" / "Library" / ".GlobalPreferences.plist").is_file(),
                "the dotfile must keep its name",
            )

    def test_the_manifest_walk_is_ordered_by_logical_name(self):
        """The order decides which of two colliding paths keeps the plain name, so
        it must not depend on SQLite's internal row order."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = self.make_backup_with_sizes(
                root,
                {
                    "z/last.bin": (b"z", 1),
                    "a/first.bin": (b"a", 1),
                    "m/middle.bin": (b"m", 1),
                },
            )
            names = [
                f"{domain}/{rel}" for _, domain, rel, _, _ in ios_backup.iter_manifest_rows(backup / "Manifest.db")
            ]
            self.assertEqual(names, sorted(names))

    def test_a_path_over_the_windows_limit_is_still_written(self):
        """Regression: on Windows a destination over 260 characters failed with
        "path too long" partway through a reconstruction.

        A rebuilt iOS path is long before the operator's destination is added, so
        this is the normal case for a real backup, not an edge case. The fix is the
        extended-length path form; refusing to write the file would lose evidence.

        This runs on every platform — it is a genuine over-length path everywhere —
        but it is Windows CI that proves the fix.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Several nested segments rather than one huge name: Windows limits the
            # whole path, while most file systems limit each component to 255.
            deep = "/".join(["AVeryDeeplyNestedDirectoryName" * 2] * 5) + "/payload.bin"
            backup = self.make_backup_with_sizes(root, {deep: (b"x" * 16, 16)})
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output), "--format", "folder", "--layout", "backup"])
            self.assertEqual(rc, 0, "a long destination must not fail the run")

            written = output / "HomeDomain" / Path(deep)
            self.assertTrue(len(str(written)) > output_paths.WINDOWS_MAX_PATH, "the test path must be over the limit")
            self.assertTrue(written.is_file(), f"not written: {written}")
            self.assertEqual(written.read_bytes(), b"x" * 16)

            # The run reports how many destinations exceed the limit, so an operator
            # knows the output needs long-path-aware tools.
            provenance = json.loads(
                (output / settings.TRACEABILITY_DIR_NAME / settings.TRACEABILITY_PROVENANCE_NAME).read_text()
            )
            self.assertGreaterEqual(provenance["stats"]["long_paths"], 1)

    def test_ffs_layout_over_the_windows_limit_is_a_complete_zip(self):
        """The default run turns paths too long for a Windows folder tree into a zip.

        WHY: the FFS-like layout is always a zip precisely so these paths never
        touch the file system. Runs on every platform; Windows CI is the real check.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deep = "/".join(["AVeryDeeplyNestedDirectoryName" * 2] * 5) + "/payload.bin"
            backup = self.make_backup_with_sizes(root, {deep: (b"x" * 16, 16)})
            output = root / "out"
            rc, _ = run_cli([str(backup), str(output)])
            self.assertEqual(rc, 0)
            self.assertFalse(output.exists(), "no folder tree may be written")
            member = f"private/var/mobile/{deep}"
            self.assertGreater(len(str(root / member)), output_paths.WINDOWS_MAX_PATH, "must exceed the limit")
            with zipfile.ZipFile(root / "out.zip") as zf:
                self.assertEqual(zf.read(member), b"x" * 16)
                self.assertIn(settings.ROOT_MANIFEST_DB_NAME, zf.namelist())
            self.assertTrue((root / f"out.zip{settings.ZIP_HASH_SIDECAR_SUFFIX}").is_file())

    def test_auto_format_is_zip_on_windows_for_every_layout(self):
        for layout in ("filesystem", "backup"):
            with self.subTest(layout=layout), mock.patch("platform.system", return_value="Windows"):
                self.assertEqual(ios_reconstructor.normalise_output_format("auto", layout), "zip")

    def test_long_path_is_a_no_op_off_windows(self):
        p = Path("/tmp/some/path")
        if os.name == "nt":
            self.assertTrue(str(output_paths.long_path(p)).startswith("\\\\?\\"))
        else:
            self.assertEqual(output_paths.long_path(p), p)

    def test_version_flag(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit):
            cli.parse_args(["--version"])
        self.assertIn(settings.TOOL_VERSION, stdout.getvalue())

    def test_password_redaction(self):
        self.assertEqual(
            cli.redact_password_args(["tool", "-p", "secret", "--password=also-secret"]),
            ["tool", "-p", "<redacted>", "--password=<redacted>"],
        )

    def test_cli_rejects_password_argument(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli.parse_args(["backup", "output", "-p", "secret"])

    def test_file_key_uses_nsdata_and_protection_class(self):
        record = models.FileRecord(
            file_id="a" * 40,
            domain="HomeDomain",
            relative_path="Library/test.db",
            flags=1,
            metadata={"ProtectionClass": 7, "EncryptionKey": {"NS.data": b"HEAD" + b"x" * 40}},
            source_path=Path("unused"),
            output_path=output_paths.safe_output_path("HomeDomain", "Library/test.db"),
        )
        keybag = mock.Mock()
        keybag.unwrap_key.return_value = b"file-key"
        self.assertEqual(ios_crypto.file_key_for_record(record, keybag), b"file-key")
        keybag.unwrap_key.assert_called_once_with(7, b"x" * 40)

    def test_encrypted_backup_without_a_tty_fails_cleanly(self):
        """A non-interactive run (pipe, CI, cron) must raise BackupError rather
        than letting getpass' EOFError escape as a traceback."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "backup"
            backup.mkdir()
            for name, payload in {
                "Manifest.plist": {"IsEncrypted": True, "BackupKeyBag": b"keybag"},
                "Info.plist": {"Product Version": "17.0"},
                "Status.plist": {},
            }.items():
                (backup / name).write_bytes(plistlib.dumps(payload))
            (backup / "Manifest.db").write_bytes(b"encrypted")
            with mock.patch("core.ios_crypto.require_crypto"), mock.patch("sys.stdin") as stdin:
                stdin.isatty.return_value = False
                rc, logged = run_cli([str(backup), str(root / "out")])
            self.assertEqual(rc, 1)
            self.assertIn("no password was supplied", logged)

    def test_default_passwords_are_not_tried_without_the_opt_in(self):
        """Guessing is opt-in: with no password, no prompt and no flag, the tool
        refuses rather than silently trying the acquisition-tool defaults."""
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / "backup"
            backup.mkdir()
            manifest = {"BackupKeyBag": b"keybag"}
            attempts = []

            def fake_unlock(_blob, password):
                attempts.append(password)
                raise errors.BackupError("bad password")

            with (
                mock.patch("core.ios_crypto.require_crypto"),
                mock.patch("core.ios_crypto.try_unlock_keybag", side_effect=fake_unlock),
            ):
                with self.assertRaises(errors.BackupError) as caught:
                    ios_crypto.prepare_manifest_db(backup, True, manifest, None, allow_prompt=False)

            self.assertEqual(attempts, [])
            self.assertIn("--try-default-passwords", str(caught.exception))

    def test_try_default_passwords_flag_defaults_to_off(self):
        self.assertFalse(cli.parse_args(["backup", "output"]).try_default_passwords)
        self.assertTrue(cli.parse_args(["backup", "output", "--try-default-passwords"]).try_default_passwords)

    def test_default_passwords_tried_when_opted_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "backup"
            backup.mkdir()
            (backup / "Manifest.db").write_bytes(b"encrypted")
            manifest = {"BackupKeyBag": b"keybag"}
            attempts = []

            def fake_unlock(_blob, password):
                attempts.append(password)
                if password == "123456":
                    return object()
                raise errors.BackupError("bad password")

            with (
                mock.patch("core.ios_crypto.require_crypto"),
                mock.patch("core.ios_crypto.try_unlock_keybag", side_effect=fake_unlock),
                mock.patch("core.ios_crypto.decrypt_manifest_db", return_value=b"SQLite format 3\x00"),
                # The default-password unlock logs a warning by design; keep it
                # out of the test report.
                mock.patch("core.ios_crypto._LOG"),
            ):
                db_path, tmp_dir, keybag = ios_crypto.prepare_manifest_db(
                    backup, True, manifest, None, allow_prompt=False, try_default_passwords=True
                )
                try:
                    self.assertTrue(db_path.exists())
                    self.assertIsNotNone(keybag)
                finally:
                    tmp_dir.cleanup()

            self.assertEqual(attempts, ["1234", "12345", "123456"])


if __name__ == "__main__":
    unittest.main()
