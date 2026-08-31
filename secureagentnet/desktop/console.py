"""Embedded `san` console — runs any SecureAgentNet CLI command from the GUI.

Commands run via QProcess (non-blocking, streamed) as
`python -m secureagentnet.interfaces.cli.terminal <args>`, so it works without
relying on the `san` script being on PATH. Output is the same you'd see in a
terminal (rich auto-disables colour when not a TTY).
"""
from __future__ import annotations

import shlex
import sys

from PySide6.QtCore import QProcess, QProcessEnvironment, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import QLineEdit, QPlainTextEdit, QVBoxLayout, QWidget


class SanConsole(QWidget):
    """An output pane + input line that executes `san` subcommands."""

    finished = Signal(int)  # exit code

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.output = QPlainTextEdit(readOnly=True)
        self.output.setObjectName("console")
        self.output.setPlaceholderText("Command output appears here…")
        # CLI output is wide and long — give the pane a real floor so it stays
        # readable however the rest of the page is sized, and never soft-wrap
        # table borders, which mangles rich's box drawing.
        self.output.setMinimumHeight(200)
        self.output.setLineWrapMode(QPlainTextEdit.NoWrap)

        self.input = QLineEdit()
        self.input.setObjectName("consoleInput")
        self.input.setPlaceholderText("Type a command, e.g.  agent list   (prefix 'san' optional)")
        self.input.setMinimumHeight(42)
        self.input.setClearButtonEnabled(True)
        self.input.returnPressed.connect(self._on_enter)

        layout.addWidget(self.output, 1)
        layout.addWidget(self.input, 0)

        self.proc: QProcess | None = None
        self._append("SecureAgentNet console — every `san` command is available here.\n"
                     "Try:  doctor   ·   agent list   ·   view-logs   ·   cloud status\n")

    # ── public API used by the action panels ──
    def run(self, args: list[str], echo: str | None = None) -> None:
        if self.proc is not None and self.proc.state() != QProcess.NotRunning:
            self._append("\n[a command is still running — wait for it to finish]\n")
            return
        self._append(f"\n$ san {echo if echo is not None else ' '.join(args)}\n")
        env = QProcessEnvironment.systemEnvironment()
        env.insert("NO_COLOR", "1")
        env.insert("PYTHONUNBUFFERED", "1")
        # Pin the subprocess to the database this app is already reading.
        # QProcess inherits the desktop's environment, so launching the app from a
        # shell without DATABASE_URL set left every console command resolving to the
        # default ~/.secureagentnet path while the window itself showed agents from
        # elsewhere — `agent list` and `agent commission` disagreeing about which
        # agents exist. Resolving it here means the console can never drift from
        # the app around it, however the app was started.
        # Pin the subprocess to the database this app already resolved, so a
        # console command cannot answer from a different store than the window
        # around it — whatever directory the app happens to be launched from.
        try:
            from secureagentnet.core.config import get_settings
            env.insert("DATABASE_URL", get_settings().database_url)
        except Exception:
            pass  # fall back to the CLI's own resolution
        self.proc = QProcess(self)
        self.proc.setProcessEnvironment(env)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._read)
        self.proc.finished.connect(self._on_done)
        self.proc.start(sys.executable,
                        ["-m", "secureagentnet.interfaces.cli.terminal", *args])

    # ── input handling ──
    def _on_enter(self) -> None:
        text = self.input.text().strip()
        if not text:
            return
        self.input.clear()
        if text.lower() in ("clear", "cls"):
            self.output.clear()
            return
        if text.startswith("san "):
            text = text[4:]
        try:
            args = shlex.split(text)
        except ValueError as exc:
            self._append(f"\n[parse error: {exc}]\n")
            return
        self.run(args, echo=text)

    def _read(self) -> None:
        if self.proc is None:
            return
        data = bytes(self.proc.readAllStandardOutput()).decode("utf-8", errors="replace")
        self._append(data)

    def _on_done(self, code: int, _status) -> None:
        self._append(f"\n[exit {code}]\n")
        self.finished.emit(int(code))

    def _append(self, text: str) -> None:
        self.output.moveCursor(QTextCursor.End)
        self.output.insertPlainText(text)
        self.output.moveCursor(QTextCursor.End)
