"""System tray icon and menu for the SecureAgentNet desktop app."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QSystemTrayIcon, QMenu, QWidget
from PySide6.QtCore import Signal

if TYPE_CHECKING:
    from secureagentnet.desktop.app import DesktopApplication

logger = logging.getLogger("SecureAgentNet.Desktop.Tray")


class SystemTray(QWidget):
    """Cross-platform system tray widget."""

    show_window_signal = Signal()

    def __init__(self, app: "DesktopApplication"):
        super().__init__()
        self.app = app
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.app.icons["protected"])
        self.tray.setToolTip("SecureAgentNet — Protected")

        self.menu = QMenu()
        self.menu.setStyleSheet("color: #0f172a;")
        self._build_menu()
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._on_activated)

    def _build_menu(self) -> None:
        open_action = self.menu.addAction("Open Dashboard")
        open_action.triggered.connect(self.app.show_main_window)

        scan_action = self.menu.addAction("Scan Now")
        scan_action.triggered.connect(self.app.main_window._on_scan)

        activity_action = self.menu.addAction("View Activity")
        activity_action.triggered.connect(lambda: self._open_page("activity"))

        commands_action = self.menu.addAction("Commands")
        commands_action.triggered.connect(lambda: self._open_page("commands"))

        self.menu.addSeparator()

        quit_action = self.menu.addAction("Exit")
        quit_action.triggered.connect(self.app.quit)

    def _open_page(self, key: str) -> None:
        self.app.show_main_window()
        self.app.main_window._select(key)

    def _notify(self, title: str, message: str, icon, msecs: int) -> None:
        """Show a balloon notification, tolerating D-Bus/notification failures.

        On some Linux sessions the StatusNotifier host advertises itself but the
        org.freedesktop.Notifications service is missing or flaky, so showMessage
        raises a QDBus error. Skip it when the platform reports no message support,
        and swallow any residual error so a failed notification never breaks the app.
        """
        try:
            if not self.tray.supportsMessages():
                return
            self.tray.showMessage(title, message, icon, msecs)
        except Exception as exc:  # pragma: no cover - environment-dependent
            logger.debug("Tray notification suppressed (%s): %s", title, exc)

    def show(self) -> None:
        self.tray.show()
        self._notify(
            "SecureAgentNet",
            "Background protection is active.",
            QSystemTrayIcon.Information,
            3000,
        )

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.DoubleClick or reason == QSystemTrayIcon.Trigger:
            self.app.show_main_window()

    def handle_alert(self, alert: dict) -> None:
        severity = alert.get("severity", "INFO")
        if severity == "CRITICAL":
            self.tray.setIcon(self.app.icons["alert"])
            self.tray.setToolTip("SecureAgentNet — Critical Alert!")
            self._notify(
                alert.get("title", "Security Alert"),
                alert.get("message", ""),
                QSystemTrayIcon.Critical,
                8000,
            )
        elif severity == "WARNING":
            self.tray.setIcon(self.app.icons["warning"])
            self.tray.setToolTip("SecureAgentNet — Warning")
            self._notify(
                alert.get("title", "Security Warning"),
                alert.get("message", ""),
                QSystemTrayIcon.Warning,
                5000,
            )
