"""Tests for the PySide6 interface.

Defines: construction of the main window, its default state, output-path
composition, the worker lifecycle, and an end-to-end reconstruction driven
through the worker with progress and cancellation.
Used by: pytest / unittest discovery.
Depends on: gui.interface, core.reconstructor, PySide6.

These run headless under the offscreen Qt platform, which is set before the
first PySide6 import because QApplication picks its platform plugin once.
"""

import os
import plistlib
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6 import QtWidgets

    PYSIDE_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only where PySide6 is absent
    PYSIDE_AVAILABLE = False

from core import reconstructor as recon


def build_backup(root: Path, file_count: int = 6) -> Path:
    """A minimal unencrypted backup with `file_count` one-block files."""
    backup = root / "backup"
    backup.mkdir()
    for name, payload in {
        "Manifest.plist": {"IsEncrypted": False},
        "Info.plist": {"Product Version": "17.0", "Device Name": "Test iPhone"},
        "Status.plist": {},
    }.items():
        (backup / name).write_bytes(plistlib.dumps(payload))
    conn = sqlite3.connect(backup / "Manifest.db")
    conn.execute("CREATE TABLE Files (fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    for index in range(file_count):
        file_id = f"{index:040x}"
        (backup / file_id[:2]).mkdir(exist_ok=True)
        (backup / file_id[:2] / file_id).write_bytes(b"payload")
        conn.execute(
            "INSERT INTO Files VALUES (?, ?, ?, ?, ?)",
            (file_id, "HomeDomain", f"Library/f{index}.bin", 1, plistlib.dumps({"Size": 7})),
        )
    conn.commit()
    conn.close()
    return backup


@unittest.skipUnless(PYSIDE_AVAILABLE, "PySide6 is not installed")
class GuiTests(unittest.TestCase):
    """Construct the real window offscreen and drive it without an event loop."""

    @classmethod
    def setUpClass(cls) -> None:
        # One QApplication per process; Qt forbids a second.
        cls.app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])

    def setUp(self) -> None:
        self.windows: list = []

    def tearDown(self) -> None:
        # A QThread destroyed while running aborts the process (SIGABRT), so any
        # thread a test started must be stopped before its window is collected.
        for window in self.windows:
            thread = window._worker_thread
            if thread is not None and thread.isRunning():
                worker = window._worker
                if worker is not None and hasattr(worker, "cancel"):
                    worker.cancel()
                thread.quit()
                thread.wait(5000)
        self.windows.clear()

    def make_window(self):
        """Build a real MainWindow headlessly, tracked for thread cleanup."""
        import gui.interface as interface

        window = interface.build_main_window()
        self.windows.append(window)
        return window

    def test_window_constructs_with_expected_defaults(self):
        window = self.make_window()
        self.assertEqual(window.output_name.text(), "reconstructed")
        # The configured default layout must be preselected, not merely first.
        self.assertEqual(window._selected_output_layout(), recon.DEFAULT_OUTPUT_LAYOUT)
        self.assertFalse(window.cancel_button.isEnabled())
        self.assertTrue(window.progress.isHidden(), "the bar starts hidden until a run reports")

    def test_main_window_does_not_shadow_qobject_thread(self):
        """Regression: `self.thread` shadowed the inherited QObject.thread()."""
        window = self.make_window()
        self.assertTrue(callable(window.thread), "QObject.thread() must stay callable")
        self.assertIsNone(window._worker_thread)
        self.assertIsNone(window._worker)

    def test_the_action_button_names_the_selected_mode(self):
        """The button must say what it will actually do."""
        window = self.make_window()
        self.assertEqual(window.reconstruct_button.text(), "Reconstruct")
        self.assertTrue(window.output_layout.isEnabled())
        # The default Full File System-like layout is always a zip, so the type is locked.
        self.assertFalse(window.output_type.isEnabled())
        self.assertEqual(window.output_type.currentData(), "zip")
        window.output_layout.setCurrentIndex(window.output_layout.findData("backup"))
        self.assertTrue(window.output_type.isEnabled())

        window.mode_decrypt.setChecked(True)
        self.assertEqual(window.reconstruct_button.text(), "Decrypt")
        # Neither applies to a decryption, so neither should look effective.
        self.assertFalse(window.output_layout.isEnabled())
        self.assertFalse(window.output_type.isEnabled())

        window.mode_rebuild.setChecked(True)
        self.assertEqual(window.reconstruct_button.text(), "Reconstruct")
        self.assertTrue(window.output_layout.isEnabled())

    def test_output_path_composition(self):
        window = self.make_window()
        with tempfile.TemporaryDirectory() as tmp:
            window.output_folder.setText(tmp)
            window.output_name.setText("rebuilt")
            self.assertEqual(window._output_path(), Path(tmp) / "rebuilt.zip", "FFS-like is always a zip")
            window.output_layout.setCurrentIndex(window.output_layout.findData("backup"))
            window.output_type.setCurrentIndex(window.output_type.findData("folder"))
            self.assertEqual(window._output_path(), Path(tmp) / "rebuilt")
            window.output_type.setCurrentIndex(window.output_type.findData("zip"))
            self.assertEqual(window._output_path(), Path(tmp) / "rebuilt.zip")

    def test_encrypted_backup_without_password_is_refused(self):
        window = self.make_window()
        # Set the paths FIRST: input_path.textChanged clears the cached backup
        # info, so assigning it before would silently discard it.
        window.input_path.setText("/nonexistent")
        window.output_folder.setText(tempfile.gettempdir())
        window.last_backup_info = {"backup": "x", "encrypted": True}
        window._start_reconstruction()
        self.assertIn("encrypted", window.status.toPlainText().lower())
        self.assertIsNone(window._worker, "no worker may start without a password")

    def test_editing_the_input_path_clears_cached_backup_info(self):
        """The cache must not survive pointing at a different backup."""
        window = self.make_window()
        window.last_backup_info = {"backup": "x", "encrypted": False}
        window.input_path.setText("/some/other/backup")
        self.assertIsNone(window.last_backup_info)

    def test_progress_updates_the_bar(self):
        window = self.make_window()
        window._on_progress(3, 12, "HomeDomain/Library/f3.bin")
        self.assertFalse(window.progress.isHidden(), "reporting progress must reveal the bar")
        self.assertEqual(window.progress.value(), 3)
        self.assertEqual(window.progress.maximum(), 12)
        self.assertIn("f3.bin", window.status.toPlainText())

    def test_worker_reconstructs_and_reports_progress(self):
        """Drive the real worker synchronously: no thread, no event loop."""
        import gui.interface as interface

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_backup(root, file_count=6)
            output = root / "out"
            worker = interface.build_reconstruction_worker(str(backup), str(output), "folder", "", False, "backup")
            seen: list[tuple[int, int]] = []
            results: list[dict] = []
            failures: list[str] = []
            worker.progressed.connect(lambda d, t, _p: seen.append((d, t)))
            worker.finished.connect(results.append)
            worker.failed.connect(failures.append)
            worker.run()

            self.assertEqual(failures, [])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["stats"]["written"], 6)
            self.assertFalse(results[0]["cancelled"])
            self.assertEqual(seen[-1], (6, 6), "progress must reach the total")
            self.assertTrue((output / "HomeDomain" / "Library" / "f0.bin").is_file())

    def test_worker_cancellation_keeps_partial_output(self):
        import gui.interface as interface

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_backup(root, file_count=20)
            output = root / "out"
            worker = interface.build_reconstruction_worker(str(backup), str(output), "folder", "", False, "backup")
            results: list[dict] = []
            worker.finished.connect(results.append)
            # Cancel once a few files are through.
            worker.progressed.connect(lambda done, _t, _p: worker.cancel() if done >= 5 else None)
            worker.run()

            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]["cancelled"])
            self.assertEqual(results[0]["stats"]["records"], 5)
            written = list((output / "HomeDomain" / "Library").glob("*.bin"))
            self.assertEqual(len(written), 5)
            manifest = output / recon.TRACEABILITY_DIR_NAME / recon.TRACEABILITY_FILE_MANIFEST_NAME
            self.assertTrue(manifest.is_file(), "a cancelled run must still be attributable")

    def test_threaded_reconstruction_end_to_end(self):
        """Drive the window the way a user does: a real QThread and event loop.

        WHY this exists separately from the synchronous worker tests: those call
        `worker.run()` directly and so never exercise `moveToThread`, the signal
        marshalling, or the teardown in `_worker_done` — which is where Qt
        lifetime bugs actually live.

        Two things this test deliberately does NOT do:
        - It does not monkeypatch `_on_progress` or `_worker_finished`. Replacing
          a bound method with a plain function makes Qt fall back to a DIRECT
          connection (it can no longer see a receiver QObject with a thread), so
          the slot would run in the worker thread and touch widgets from it.
        - It pre-sets the cached backup info so exactly ONE worker runs. Unset,
          `_reconstruct` runs an inspect pass and chains onward, and an "is the
          window idle" check cannot tell the gap between phases from the end.
        """
        from PySide6 import QtCore

        window = self.make_window()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_backup(root, file_count=8)
            # Paths first: input_path.textChanged clears the cached info.
            window.input_path.setText(str(backup))
            window.output_folder.setText(str(root))
            window.output_name.setText("rebuilt")
            window.output_layout.setCurrentIndex(window.output_layout.findData("backup"))
            window.output_type.setCurrentIndex(window.output_type.findData("folder"))
            window.last_backup_info = {"backup": str(backup), "encrypted": False}

            window._reconstruct()
            self.assertIsNotNone(window._worker_thread, "a worker thread must have started")
            self.assertTrue(window.cancel_button.isEnabled(), "cancel must be live during a run")

            # Quit once the window has torn the thread down and reported.
            guard = QtCore.QTimer()
            guard.setInterval(20)

            def check_done() -> None:
                if window._worker_thread is None and "finished" in window.status.toPlainText().lower():
                    guard.stop()
                    self.app.quit()

            guard.timeout.connect(check_done)
            guard.start()
            timeout = QtCore.QTimer()
            timeout.setSingleShot(True)
            timeout.timeout.connect(self.app.quit)
            timeout.start(30000)
            self.app.exec()
            guard.stop()
            timeout.stop()

            status = window.status.toPlainText()
            self.assertIn("finished", status.lower())
            self.assertIn("Written: 8", status, "the summary must report every file")
            self.assertIsNone(window._worker_thread, "the thread must be torn down")
            self.assertIsNone(window._worker, "the worker reference must be dropped")
            self.assertTrue(window.reconstruct_button.isEnabled(), "the UI must be re-enabled")
            self.assertFalse(window.cancel_button.isEnabled(), "cancel must be disabled when idle")
            self.assertTrue(window.progress.isHidden(), "the bar must be hidden once idle")
            rebuilt = root / "rebuilt" / "HomeDomain" / "Library"
            self.assertEqual(len(list(rebuilt.glob("*.bin"))), 8)
            self.assertTrue(
                (root / "rebuilt" / recon.TRACEABILITY_DIR_NAME / recon.TRACEABILITY_PROVENANCE_NAME).is_file()
            )

    def test_reconstruct_works_without_clicking_check_encryption_first(self):
        """Regression: pressing Reconstruct on a fresh window must just work.

        `_reconstruct` runs an inspect pass first when it has no cached backup
        info. That chained reconstruction used to be started from the inspect's
        FINISH handler, which runs while the inspect thread is still tearing down —
        so the inspect's teardown cleared the new run's thread reference, the
        reconstruction thread was destroyed mid-run, and nothing was written. The
        window reported "Reconstruction started..." and produced no output, and the
        operator had to click Check encryption first to work around it.

        This drives the real chained path with a live event loop, which the other
        threaded test deliberately avoids by pre-setting the cached info.
        """
        from PySide6 import QtCore

        window = self.make_window()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = build_backup(root, file_count=5)
            window.input_path.setText(str(backup))
            window.output_folder.setText(str(root))
            window.output_name.setText("out")
            window.output_layout.setCurrentIndex(window.output_layout.findData("backup"))
            window.output_type.setCurrentIndex(window.output_type.findData("folder"))

            # Exactly what the operator does: press Reconstruct, nothing else.
            self.assertIsNone(window.last_backup_info, "no inspect has run yet")
            window._reconstruct()
            self.assertTrue(window._pending_reconstruct, "the run must be queued behind the inspect")

            guard = QtCore.QTimer()
            guard.setInterval(20)

            def check_done() -> None:
                idle = window._worker_thread is None and not window._pending_reconstruct
                if idle and "finished" in window.status.toPlainText().lower():
                    guard.stop()
                    self.app.quit()

            guard.timeout.connect(check_done)
            guard.start()
            timeout = QtCore.QTimer()
            timeout.setSingleShot(True)
            timeout.timeout.connect(self.app.quit)
            timeout.start(30000)
            self.app.exec()
            guard.stop()
            timeout.stop()

            status = window.status.toPlainText()
            self.assertIn("finished", status.lower(), f"status was: {status!r}")
            self.assertIn("Written: 5", status)
            out = root / "out" / "HomeDomain" / "Library"
            self.assertEqual(len(list(out.glob("*.bin"))), 5, "every file must be written")
            self.assertIsNone(window._worker_thread, "the thread must be torn down")
            self.assertFalse(window._pending_reconstruct)
            self.assertTrue(window.reconstruct_button.isEnabled())

    def test_cancel_event_is_thread_safe_type(self):
        import gui.interface as interface

        worker = interface.build_reconstruction_worker("a", "b", "folder", "", False, "backup")
        self.assertIsInstance(worker.cancel_event, threading.Event)


if __name__ == "__main__":
    unittest.main()
