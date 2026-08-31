"""Desktop entry point for SecureAgentNet."""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

from PySide6.QtCore import QThread, Signal, qInstallMessageHandler
from PySide6.QtGui import QIcon, QPixmap, QColor, QPainter, QFont
from PySide6.QtWidgets import QApplication, QSystemTrayIcon

from secureagentnet.desktop.client import DaemonClient
from secureagentnet.desktop.main_window import MainWindow
from secureagentnet.desktop.theme import apply_palette
from secureagentnet.desktop.tray import SystemTray
from secureagentnet.daemon.process import start_daemon, daemon_status

logger = logging.getLogger("SecureAgentNet.Desktop")


def _ensure_app_data_dir() -> None:
    (Path.home() / ".secureagentnet").mkdir(parents=True, exist_ok=True)


# Benign, session-specific Qt warnings emitted when the desktop's StatusNotifier /
# notification host is missing or flaky. The app degrades to window-only gracefully,
# so these are pure noise — filter just these, and let every other Qt message through.
_SUPPRESSED_QT_WARNINGS = (
    "QDBusTrayIcon",
    "QSystemTrayIcon::showMessage",
    "No such object path",
    "org.kde.StatusNotifierWatcher",
)


def _qt_message_filter(mode, context, message: str) -> None:
    if any(marker in message for marker in _SUPPRESSED_QT_WARNINGS):
        logger.debug("Suppressed Qt tray/D-Bus warning: %s", message)
        return
    sys.stderr.write(message + "\n")


def _create_icon(color: str, size: int = 64) -> QIcon:
    """Generate a simple shield-shaped tray icon in memory."""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor("transparent"))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor(color))
    painter.setPen(QColor("#0f172a"))
    # Shield shape
    painter.drawRoundedRect(8, 8, size - 16, size - 16, 12, 12)
    painter.setPen(QColor("white"))
    font = QFont("Arial", size // 3, QFont.Bold)
    painter.setFont(font)
    painter.drawText(pixmap.rect(), 0x84, "S")
    painter.end()
    return QIcon(pixmap)


class AlertWorker(QThread):
    """Background thread that consumes the daemon WebSocket alert stream."""

    alert_received = Signal(dict)

    def __init__(self, client: DaemonClient, parent=None):
        super().__init__(parent)
        self.client = client
        self._running = True

    def run(self):
        import websockets

        async def _listen():
            try:
                async with websockets.connect(self.client.alert_stream_url()) as ws:
                    while self._running:
                        try:
                            message = await asyncio.wait_for(ws.recv(), timeout=1.0)
                            import json
                            self.alert_received.emit(json.loads(message))
                        except asyncio.TimeoutError:
                            continue
            except Exception as exc:
                logger.debug("Alert stream connection error: %s", exc)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_listen())
        finally:
            loop.close()

    def stop(self):
        self._running = False
        self.wait(2000)


class _DaemonStarter(QThread):
    """Starts the daemon off the UI thread.

    ``start_daemon`` spawns the process and then polls for its PID file for up to
    two seconds. Run inline that delay lands squarely between launch and first
    paint; here the window is already up and the poller connects when it connects.
    """

    finished_msg = Signal(bool, str)

    def run(self):
        running, msg = daemon_status()
        if running:
            self.finished_msg.emit(True, msg)
            return
        ok, msg = start_daemon(daemonize=True)
        self.finished_msg.emit(ok, msg)


class DesktopApplication:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setApplicationName("SecureAgentNet")
        apply_palette(self.app)
        # A system tray is only usable if the desktop session provides a tray host
        # (a StatusNotifier/AppIndicator). Minimal or Wayland sessions often don't —
        # constructing a tray icon there raises a D-Bus "ServiceUnknown" error. When
        # no tray is available we run as an ordinary window app instead.
        self.has_tray = QSystemTrayIcon.isSystemTrayAvailable()
        self.app.setQuitOnLastWindowClosed(not self.has_tray)

        self.icons = {
            "normal": _create_icon("#06b6d4"),
            "protected": _create_icon("#22c55e"),
            "warning": _create_icon("#eab308"),
            "alert": _create_icon("#ef4444"),
        }

        self.client = DaemonClient()
        self.main_window: MainWindow = MainWindow(self)
        # isSystemTrayAvailable() can still return True on sessions whose tray host
        # is flaky, where constructing the tray raises a QDBus error. Build it
        # defensively and fall back to a window-only app on any failure.
        self.tray = None
        if self.has_tray:
            try:
                self.tray = SystemTray(self)
            except Exception as exc:
                logger.warning("System tray unavailable (%s); running window-only.", exc)
                self._disable_tray()
        if not self.has_tray:
            logger.info("No system tray available; running as a window-only app.")
        self.alert_worker: AlertWorker = AlertWorker(self.client)
        self.alert_worker.alert_received.connect(self._on_alert)

    def _disable_tray(self) -> None:
        """Drop to window-only mode so the app stays usable and quittable."""
        self.tray = None
        self.has_tray = False
        self.app.setQuitOnLastWindowClosed(True)

    def start(self) -> int:
        _ensure_app_data_dir()
        if self.tray is not None:
            try:
                self.tray.show()
            except Exception as exc:
                logger.warning("Could not show system tray (%s); running window-only.", exc)
                self._disable_tray()
        self.alert_worker.start()
        self.main_window.refresh()
        # Paint the window before touching the daemon. Starting it can take a
        # couple of seconds (spawn, then poll for the PID file) and doing that
        # inline left the user staring at nothing for the whole wait.
        self.show_main_window()
        self._daemon_starter = _DaemonStarter()
        self._daemon_starter.finished_msg.connect(self._on_daemon_ready)
        self._daemon_starter.start()
        return self.app.exec()

    def _on_daemon_ready(self, ok: bool, msg: str) -> None:
        if not ok:
            logger.error("Could not start daemon: %s", msg)
        else:
            logger.info("%s", msg)

    def _on_alert(self, alert: dict) -> None:
        self.main_window.handle_alert(alert)
        if self.tray is not None:
            self.tray.handle_alert(alert)

    def show_main_window(self) -> None:
        self.main_window.show()
        self.main_window.raise_()
        self.main_window.activateWindow()

    def quit(self) -> None:
        self.alert_worker.stop()
        try:
            self.main_window._poller.stop()
        except Exception:
            pass
        try:
            self.main_window._host_poller.stop()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass
        self.app.quit()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    qInstallMessageHandler(_qt_message_filter)
    app = DesktopApplication()
    return app.start()


if __name__ == "__main__":
    sys.exit(main())
