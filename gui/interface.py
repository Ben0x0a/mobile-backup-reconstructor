"""PySide6 GUI interface for iOS and Android backup reconstruction.

Defines: the main window, its drag-and-drop path fields, and the background
workers that run inspection and reconstruction off the UI thread.
Used by: launcher.gui.
Depends on: core.reconstructor, config.settings, PySide6.
"""

from __future__ import annotations

import threading
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from config.settings import DEFAULT_OUTPUT_LAYOUT, FFS_LAYOUT
from core.decryptor import decrypt_backup
from core.reconstructor import inspect_backup, reconstruct_backup


def _load_pyside() -> Any:
    try:
        from PySide6 import QtCore, QtGui, QtWidgets
    except ImportError as exc:
        raise RuntimeError("PySide6 is required for the GUI. Install it with: uv sync") from exc
    return QtCore, QtGui, QtWidgets


class ReconstructionWorkerMixin:
    """Run a reconstruction off the UI thread, reporting progress by signal.

    WHY a mixin: the Qt signal declarations must live on a QObject subclass built
    inside `launch()` (after PySide6 is known to be importable), while the logic
    itself needs no Qt and stays testable without a running application.
    """

    def run_reconstruction(self) -> None:
        try:
            if self.mode == "decrypt":
                decrypted = decrypt_backup(
                    Path(self.backup_path),
                    Path(self.output_path),
                    self.password or None,
                    self.force,
                    ["gui"],
                    False,
                    # The GUI requires the password up front, so it never guesses.
                    False,
                    progress=self._emit_progress,
                    cancel=self.cancel_event,
                )
                self.finished.emit(decrypted.as_dict())
                return
            result = reconstruct_backup(
                Path(self.backup_path),
                Path(self.output_path),
                self.output_format,
                self.password or None,
                self.force,
                ["gui"],
                False,
                self.output_layout,
                None,
                False,
                False,
                # The GUI requires the password up front, so it never guesses.
                False,
                progress=self._emit_progress,
                cancel=self.cancel_event,
            )
            self.finished.emit(result.as_dict())
        except Exception as exc:
            self.failed.emit(str(exc))

    def _emit_progress(self, done: int, total: int, path: str) -> None:
        # Emitting a signal is the only thread-safe way to reach the widgets:
        # Qt marshals it onto the UI thread's event loop. Never touch a widget
        # from here.
        self.progressed.emit(done, total, path)


class InspectWorkerMixin:
    def run_inspection(self) -> None:
        try:
            self.finished.emit(inspect_backup(Path(self.backup_path)))
        except Exception as exc:
            self.failed.emit(str(exc))


@lru_cache(maxsize=1)
def _widget_classes() -> SimpleNamespace:
    """Define and return the widget classes, loading PySide6 on first use.

    WHY the classes are built here rather than at module scope: they subclass Qt
    types, so defining them requires PySide6 to be importable — and this module
    must still import without it, so `launch()` can fail with an install hint
    instead of an ImportError traceback. Caching keeps one set of classes per
    process, as Qt expects.

    WHY a factory rather than nesting them inside `launch()`: nested classes are
    unreachable without starting an event loop, which is how a bug as plain as
    `self.thread` shadowing `QObject.thread()` survived review. The factories
    below let the tests construct the real window headlessly.
    """
    QtCore, QtGui, QtWidgets = _load_pyside()

    class DropPathEdit(QtWidgets.QLineEdit):
        def __init__(self, mode: str, parent: QtWidgets.QWidget | None = None) -> None:
            super().__init__(parent)
            self.mode = mode
            self.setAcceptDrops(True)
            self.setPlaceholderText("Drop a folder here")

        def dragEnterEvent(self, event: QtGui.QDragEnterEvent) -> None:
            if event.mimeData().hasUrls():
                event.acceptProposedAction()
            else:
                event.ignore()

        def dropEvent(self, event: QtGui.QDropEvent) -> None:
            urls = event.mimeData().urls()
            if not urls:
                return
            path = Path(urls[0].toLocalFile())
            if self.mode == "output" and path.is_file():
                path = path.parent
            self.setText(str(path))
            event.acceptProposedAction()

    class ReconstructionWorker(QtCore.QObject, ReconstructionWorkerMixin):
        finished = QtCore.Signal(dict)
        failed = QtCore.Signal(str)
        progressed = QtCore.Signal(int, int, str)

        def __init__(
            self,
            backup_path: str,
            output_path: str,
            output_format: str,
            password: str,
            force: bool,
            output_layout: str,
            mode: str = "rebuild",
        ) -> None:
            super().__init__()
            self.backup_path = backup_path
            self.output_path = output_path
            self.output_format = output_format
            self.password = password
            self.force = force
            self.output_layout = output_layout
            self.mode = mode
            self.cancel_event = threading.Event()

        def cancel(self) -> None:
            self.cancel_event.set()

        @QtCore.Slot()
        def run(self) -> None:
            self.run_reconstruction()

    class InspectWorker(QtCore.QObject, InspectWorkerMixin):
        finished = QtCore.Signal(dict)
        failed = QtCore.Signal(str)

        def __init__(self, backup_path: str) -> None:
            super().__init__()
            self.backup_path = backup_path

        @QtCore.Slot()
        def run(self) -> None:
            self.run_inspection()

    class MainWindow(QtWidgets.QWidget):
        def __init__(self) -> None:
            super().__init__()
            # NOT `self.thread`: QWidget inherits QObject.thread(), and assigning
            # an attribute of that name shadows the method the bindings rely on.
            self._worker_thread: QtCore.QThread | None = None
            self._worker: QtCore.QObject | None = None
            self.last_backup_info: dict[str, Any] | None = None
            # Set when a reconstruction is waiting on an inspect pass to finish.
            self._pending_reconstruct = False
            self.setWindowTitle("Mobile Backup Reconstructor")
            self.resize(760, 420)

            self.input_path = DropPathEdit("input")
            self.input_path.setPlaceholderText("Drop an iOS backup folder or Manifest.plist, or an Android .ab file")
            self.output_folder = DropPathEdit("output")
            self.output_folder.setPlaceholderText("Drop output folder")
            self.output_type = QtWidgets.QComboBox()
            self.output_type.addItem("Backup folder", "folder")
            self.output_type.addItem("Zip archive", "zip")
            # Radio buttons rather than a dropdown: there are exactly two modes and
            # they do different things to the output, so both should be visible at
            # once instead of one hiding behind a click.
            self.mode_rebuild = QtWidgets.QRadioButton("Reconstruct structure like a Full File System acquisition")
            self.mode_rebuild.setToolTip(
                "Write every file to the path it had on the device, as in a Full File System extraction, "
                "decrypting first when the backup is encrypted. iOS and Android (.ab) backups."
            )
            self.mode_decrypt = QtWidgets.QRadioButton("Decrypt only — keep the iOS backup layout")
            self.mode_decrypt.setToolTip(
                "Write the same iOS backup with its content in the clear, so other tools "
                "that cannot decrypt can read it. Requires an encrypted iOS backup."
            )
            self.mode_rebuild.setChecked(True)
            # A group makes the exclusivity explicit rather than relying on the two
            # happening to share a parent widget.
            self.mode_group = QtWidgets.QButtonGroup(self)
            self.mode_group.addButton(self.mode_rebuild)
            self.mode_group.addButton(self.mode_decrypt)
            self.output_layout = QtWidgets.QComboBox()
            self.output_layout.addItem("Full File System-like (zip)", FFS_LAYOUT)
            self.output_layout.addItem("iOS backup domains", "backup")
            self.output_layout.setCurrentIndex(self.output_layout.findData(DEFAULT_OUTPUT_LAYOUT))
            self.output_name = QtWidgets.QLineEdit("reconstructed")
            self.password = QtWidgets.QLineEdit()
            self.password.setEchoMode(QtWidgets.QLineEdit.Password)
            self.password.setPlaceholderText("Required only for encrypted backups")
            self.force = QtWidgets.QCheckBox("Overwrite existing zip or append to existing folder")

            self.input_browse = QtWidgets.QPushButton("Browse")
            self.output_browse = QtWidgets.QPushButton("Browse")
            self.inspect_button = QtWidgets.QPushButton("Check encryption")
            self.reconstruct_button = QtWidgets.QPushButton("Reconstruct")
            self.cancel_button = QtWidgets.QPushButton("Cancel")
            self.cancel_button.setEnabled(False)
            self.progress = QtWidgets.QProgressBar()
            self.progress.setVisible(False)
            self.status = QtWidgets.QPlainTextEdit()
            self.status.setReadOnly(True)
            self.status.setMinimumHeight(130)

            self._build_layout()
            self._connect()
            # After the widgets exist: _mode_changed touches the status pane.
            self._mode_changed()
            self._update_preview()

        def _build_layout(self) -> None:
            layout = QtWidgets.QVBoxLayout(self)
            form = QtWidgets.QFormLayout()

            input_row = QtWidgets.QHBoxLayout()
            input_row.addWidget(self.input_path)
            input_row.addWidget(self.input_browse)
            form.addRow("Input backup", input_row)

            output_row = QtWidgets.QHBoxLayout()
            output_row.addWidget(self.output_folder)
            output_row.addWidget(self.output_browse)
            form.addRow("Output folder", output_row)

            mode_row = QtWidgets.QVBoxLayout()
            mode_row.setSpacing(2)
            mode_row.addWidget(self.mode_rebuild)
            mode_row.addWidget(self.mode_decrypt)
            form.addRow("Mode", mode_row)
            form.addRow("Output type", self.output_type)
            form.addRow("Output layout", self.output_layout)
            form.addRow("Output name", self.output_name)
            form.addRow("Password", self.password)
            form.addRow("", self.force)
            layout.addLayout(form)

            button_row = QtWidgets.QHBoxLayout()
            button_row.addStretch(1)
            button_row.addWidget(self.inspect_button)
            button_row.addWidget(self.reconstruct_button)
            button_row.addWidget(self.cancel_button)
            layout.addLayout(button_row)
            layout.addWidget(self.progress)
            layout.addWidget(self.status)

        def _connect(self) -> None:
            self.input_browse.clicked.connect(self._choose_input)
            self.output_browse.clicked.connect(self._choose_output_folder)
            self.inspect_button.clicked.connect(self._inspect_backup)
            self.reconstruct_button.clicked.connect(self._reconstruct)
            self.cancel_button.clicked.connect(self._cancel)
            self.input_path.textChanged.connect(self._clear_backup_info)
            self.mode_group.buttonToggled.connect(self._mode_changed)
            self.output_type.currentIndexChanged.connect(self._update_preview)
            self.output_layout.currentIndexChanged.connect(self._layout_changed)
            self.output_folder.textChanged.connect(self._update_preview)
            self.output_name.textChanged.connect(self._update_preview)

        def _clear_backup_info(self) -> None:
            self.last_backup_info = None
            self._pending_reconstruct = False

        def _choose_input(self) -> None:
            # A file dialog rather than a folder one: it covers both inputs — an
            # iOS backup through its Manifest.plist, and an Android .ab file.
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self,
                "Select an iOS Manifest.plist or an Android .ab backup",
                "",
                "Mobile backups (Manifest.plist *.ab);;All files (*)",
            )
            if path:
                self.input_path.setText(path)

        def _choose_output_folder(self) -> None:
            path = QtWidgets.QFileDialog.getExistingDirectory(self, "Select output folder")
            if path:
                self.output_folder.setText(path)

        def _selected_output_format(self) -> str:
            return str(self.output_type.currentData())

        def _selected_output_layout(self) -> str:
            return str(self.output_layout.currentData())

        def _selected_mode(self) -> str:
            return "decrypt" if self.mode_decrypt.isChecked() else "rebuild"

        def _mode_changed(self) -> None:
            """Match the controls and the action label to the chosen mode.

            Decryption writes the backup's own hash-addressed layout into a folder,
            so neither the layout nor the output type applies. Greying them out says
            so before the run, rather than leaving them looking effective — and the
            button names the action it will actually perform.
            """
            decrypting = self._selected_mode() == "decrypt"
            self.output_layout.setEnabled(not decrypting)
            self._layout_changed()
            self.reconstruct_button.setText("Decrypt" if decrypting else "Reconstruct")
            self._update_preview()

        def _layout_changed(self) -> None:
            """The Full File System-like layout is always a zip; show it, and lock it.

            WHY: its device paths exceed Windows' path limit as a folder tree, so
            the engine refuses a folder for it — the control must not offer one.
            """
            ffs = self._selected_output_layout() == FFS_LAYOUT
            if ffs:
                self.output_type.setCurrentIndex(self.output_type.findData("zip"))
            self.output_type.setEnabled(not ffs and self._selected_mode() != "decrypt")
            self._update_preview()

        def _output_path(self) -> Path:
            folder = Path(self.output_folder.text()).expanduser()
            name = self.output_name.text().strip() or "reconstructed"
            output = folder / name
            # Decryption always writes a folder, so a .zip suffix would lie.
            if self._selected_mode() == "decrypt":
                return output
            if self._selected_output_format() == "zip" and output.suffix.lower() != ".zip":
                output = output.with_suffix(".zip")
            return output

        def _update_preview(self) -> None:
            folder = self.output_folder.text().strip()
            if not folder:
                self._set_status("", append=False)
                return
            self._set_status(f"Output path: {self._output_path()}", append=False)

        def _set_status(self, message: str, append: bool = True) -> None:
            if append and self.status.toPlainText():
                self.status.appendPlainText(message)
            else:
                self.status.setPlainText(message)

        def _set_busy(self, busy: bool, cancellable: bool = False) -> None:
            self.inspect_button.setEnabled(not busy)
            self.reconstruct_button.setEnabled(not busy)
            self.input_browse.setEnabled(not busy)
            self.output_browse.setEnabled(not busy)
            self.cancel_button.setEnabled(busy and cancellable)
            if not busy:
                self.progress.setVisible(False)

        def _cancel(self) -> None:
            worker = self._worker
            if worker is not None and hasattr(worker, "cancel"):
                worker.cancel()
                self.cancel_button.setEnabled(False)
                self._set_status("Cancelling after the current file...")

        def _on_progress(self, done: int, total: int, path: str) -> None:
            self.progress.setVisible(True)
            if total <= 0:
                # An Android .ab is a tar stream: its file count is unknown until
                # the end, so show a busy bar and a running count instead.
                self.progress.setMaximum(0)
                self.status.setPlainText(f"Reconstructing...\n{done} files\n{path}")
                return
            self.progress.setMaximum(total)
            self.progress.setValue(done)
            self.progress.setFormat(f"%v / %m  ({done * 100 // total}%)")
            self.status.setPlainText(f"Reconstructing...\n{done} of {total}\n{path}")

        def _inspect_backup(self) -> None:
            backup = self.input_path.text().strip()
            if not backup:
                self._set_status("Select an input backup first.", append=False)
                return
            self._start_worker(InspectWorker(backup), "Inspecting backup...")

        def _reconstruct(self) -> None:
            backup = self.input_path.text().strip()
            output_folder = self.output_folder.text().strip()
            if not backup or not output_folder:
                self._set_status("Select input backup and output folder first.", append=False)
                return
            if not Path(output_folder).expanduser().is_dir():
                self._set_status("Output folder must exist.", append=False)
                return
            # The encryption check needs inspect_backup, which touches the disk.
            # WHY not inline: on a network or slow-mounted backup that read blocks
            # the window. If it has not been done yet, run it in the inspect
            # worker and continue from its callback.
            if self.last_backup_info is None:
                self._pending_reconstruct = True
                self._start_worker(InspectWorker(backup), "Checking the backup...")
                return
            self._start_reconstruction()

        def _start_reconstruction(self) -> None:
            info = self.last_backup_info or {}
            # Fail fast rather than letting the worker report an unlock failure
            # minutes into a long run.
            if info.get("encrypted") and not self.password.text():
                self._set_status(
                    "This backup is encrypted. Enter the backup password before reconstructing.",
                    append=False,
                )
                return
            mode = self._selected_mode()
            if mode == "decrypt" and info.get("platform") == "android":
                self._set_status(
                    "Decrypt only applies to iOS backups. An encrypted Android backup is decrypted "
                    "during the reconstruction: switch the mode to Reconstruct.",
                    append=False,
                )
                return
            if mode == "decrypt" and not info.get("encrypted"):
                self._set_status(
                    "This backup is not encrypted, so there is nothing to decrypt. Switch the mode to Rebuild.",
                    append=False,
                )
                return
            worker = ReconstructionWorker(
                self.input_path.text().strip(),
                str(self._output_path()),
                self._selected_output_format(),
                self.password.text(),
                self.force.isChecked(),
                self._selected_output_layout(),
                mode,
            )
            started = "Decryption started..." if mode == "decrypt" else "Reconstruction started..."
            self._start_worker(worker, started)

        def _start_worker(self, worker: QtCore.QObject, message: str) -> None:
            cancellable = hasattr(worker, "cancel")
            self._set_busy(True, cancellable=cancellable)
            self._set_status(message, append=False)
            thread = QtCore.QThread(self)
            self._worker_thread = thread
            self._worker = worker
            worker.moveToThread(thread)
            thread.started.connect(worker.run)
            # These must stay BOUND METHODS of this QObject. Connect a plain
            # function or lambda instead and Qt cannot see a receiver with a
            # thread affinity, so it falls back to a direct connection and the
            # slot runs in the worker thread — touching widgets from there.
            if hasattr(worker, "progressed"):
                worker.progressed.connect(self._on_progress)
            worker.finished.connect(self._worker_finished)
            worker.failed.connect(self._worker_failed)
            worker.finished.connect(thread.quit)
            worker.failed.connect(thread.quit)
            worker.finished.connect(worker.deleteLater)
            worker.failed.connect(worker.deleteLater)
            thread.finished.connect(thread.deleteLater)
            thread.finished.connect(self._worker_done)
            thread.start()

        def _worker_done(self) -> None:
            """Tear down the finished run, then start anything queued behind it.

            WHY the chained reconstruction starts HERE rather than from
            `_worker_finished`: that handler runs while the inspect thread is still
            finishing. Starting the reconstruction there assigned its thread to
            `_worker_thread`, and the inspect's own teardown — arriving immediately
            after — cleared that reference. The reconstruction thread lost its only
            owner, was destroyed mid-run ("QThread: Destroyed while thread is still
            running"), and nothing was written. By the time this runs the previous
            thread has finished, so the next one can be started safely.
            """
            # Drop the references: both objects have been deleteLater'd, so
            # holding them would leave Python names pointing at dead C++ objects.
            self._worker = None
            self._worker_thread = None
            self._set_busy(False)
            if self._pending_reconstruct:
                self._pending_reconstruct = False
                self._start_reconstruction()

        def _worker_finished(self, payload: dict[str, Any]) -> None:
            if "backup" in payload:
                self.last_backup_info = payload
                # A reconstruction waiting on this inspect is started from
                # _worker_done, NOT from here: this handler runs while the inspect
                # thread is still tearing down, and starting the next run now would
                # have its thread reference cleared by that teardown.
                if self._pending_reconstruct:
                    return
                if payload.get("platform") == "android":
                    lines = [
                        "Backup checked: Android adb backup (.ab).",
                        f"Path: {payload.get('backup')}",
                        f"Format version: {payload.get('format_version')}",
                        f"Compressed: {payload.get('compressed')}",
                        f"Encrypted: {payload.get('encrypted')}",
                    ]
                else:
                    lines = [
                        "Backup checked: iOS backup.",
                        f"Path: {payload.get('backup')}",
                        f"Device: {payload.get('device') or 'unknown'}",
                        f"Product: {payload.get('product') or 'unknown'}",
                        f"iOS: {payload.get('ios') or 'unknown'}",
                        f"Encrypted: {payload.get('encrypted')}",
                    ]
                self._set_status("\n".join(lines), append=False)
                return
            stats = payload.get("stats", {})
            if payload.get("mode") == "decrypt":
                lines = [
                    "Decryption CANCELLED - the output is NOT a usable backup."
                    if payload.get("cancelled")
                    else "Decryption finished. The output is an unencrypted backup.",
                    f"Output: {payload.get('output')}",
                    f"Files decrypted: {stats.get('written', 0)}",
                    f"Missing source: {stats.get('missing', 0)}",
                    f"Failed: {stats.get('failed', 0)}",
                    "Manifest metadata was rewritten; see the traceability output.",
                ]
                self._set_status("\n".join(lines), append=False)
                return
            lines = [
                "Reconstruction CANCELLED - the output is incomplete."
                if payload.get("cancelled")
                else "Reconstruction finished.",
                f"Output: {payload.get('output')}",
                f"Type: {payload.get('format')}",
                f"Layout: {payload.get('layout')}",
                f"Records: {stats.get('records', 0)}",
                f"Written: {stats.get('written', 0)}",
                f"Missing source: {stats.get('missing', 0)}",
                f"Failed: {stats.get('failed', 0)}",
                *(
                    [
                        f"NOTE: {stats['long_paths']} path(s) exceed Windows' 260-character "
                        "limit. Written correctly, but some tools cannot open them."
                    ]
                    if stats.get("long_paths")
                    else []
                ),
                f"Traceability: {payload.get('traceability')}",
                *(
                    [f"SHA-256: {payload['sha256']}", f"Hash file: {payload.get('sha256_file')}"]
                    if payload.get("sha256")
                    else []
                ),
            ]
            self._set_status("\n".join(lines), append=False)

        def _worker_failed(self, message: str) -> None:
            self._pending_reconstruct = False
            self._set_status(f"Error: {message}", append=False)

    return SimpleNamespace(
        DropPathEdit=DropPathEdit,
        ReconstructionWorker=ReconstructionWorker,
        InspectWorker=InspectWorker,
        MainWindow=MainWindow,
        QtWidgets=QtWidgets,
    )


def build_main_window() -> Any:
    """Construct the main window. Requires a QApplication to already exist."""
    return _widget_classes().MainWindow()


def build_reconstruction_worker(
    backup_path: str,
    output_path: str,
    output_format: str,
    password: str,
    force: bool,
    output_layout: str,
) -> Any:
    """Construct a reconstruction worker, runnable directly or on a QThread."""
    return _widget_classes().ReconstructionWorker(
        backup_path, output_path, output_format, password, force, output_layout
    )


def build_inspect_worker(backup_path: str) -> Any:
    """Construct an inspection worker, runnable directly or on a QThread."""
    return _widget_classes().InspectWorker(backup_path)


def launch() -> int:
    """Start the PySide6 GUI and return its exit code."""
    classes = _widget_classes()
    app = classes.QtWidgets.QApplication.instance() or classes.QtWidgets.QApplication([])
    window = classes.MainWindow()
    window.show()
    return int(app.exec())
