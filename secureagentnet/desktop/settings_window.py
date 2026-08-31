"""Settings window for the SecureAgentNet desktop app."""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QFormLayout,
    QMessageBox,
)

from secureagentnet.daemon.config import get_daemon_settings

from secureagentnet.desktop.theme import COLORS

if TYPE_CHECKING:
    from secureagentnet.desktop.main_window import MainWindow


class SettingsWindow(QDialog):
    def __init__(self, main_window: "MainWindow"):
        super().__init__(main_window)
        self.main_window = main_window
        self.setWindowTitle("Settings")
        self.setMinimumSize(500, 300)
        self.setStyleSheet(f"background-color: {COLORS['window']}; color: {COLORS['ink']};")

        layout = QVBoxLayout(self)
        header = QLabel("SecureAgentNet Settings")
        header.setStyleSheet(f"font-size: 17px; font-weight: 700; color: {COLORS['primary']};")
        layout.addWidget(header)

        form = QFormLayout()
        self.port_edit = QLineEdit()
        self.port_edit.setStyleSheet(f"background-color: #0e141b; color: {COLORS['ink']}; padding: 7px 10px;"f" border: 1px solid #2d3945; border-radius: 7px;")

        self.scan_interval_edit = QLineEdit()
        self.scan_interval_edit.setStyleSheet(self.port_edit.styleSheet())

        self.cloud_url_edit = QLineEdit()
        self.cloud_url_edit.setStyleSheet(self.port_edit.styleSheet())

        self.cloud_key_edit = QLineEdit()
        self.cloud_key_edit.setStyleSheet(self.port_edit.styleSheet())
        self.cloud_key_edit.setEchoMode(QLineEdit.Password)

        self.notifications_check = QCheckBox("Enable desktop notifications")
        self.notifications_check.setStyleSheet(f"color: {COLORS['ink']};")

        form.addRow("Daemon Port:", self.port_edit)
        form.addRow("Scan Interval (sec):", self.scan_interval_edit)
        form.addRow("Cloud Scan URL:", self.cloud_url_edit)
        form.addRow("Cloud API Key:", self.cloud_key_edit)
        form.addRow(self.notifications_check)
        layout.addLayout(form)

        save_btn = QPushButton("Save")
        save_btn.setStyleSheet(
            f"QPushButton {{ background-color: {COLORS['primary']}; color: #04120f; border: none;"f" border-radius: 7px; padding: 10px 20px; font-weight: 700; }}"
        )
        save_btn.clicked.connect(self._save)
        layout.addWidget(save_btn)

        self._load()

    def _load(self) -> None:
        settings = get_daemon_settings()
        self.port_edit.setText(str(settings.daemon_port))
        self.scan_interval_edit.setText(str(settings.discovery_interval_seconds))
        self.cloud_url_edit.setText(settings.cloud_scan_url or "")
        self.cloud_key_edit.setText(settings.cloud_scan_api_key or "")
        self.notifications_check.setChecked(settings.desktop_notifications)

    def _save(self) -> None:
        env_path = Path.home() / ".secureagentnet" / ".env"
        lines = []
        if env_path.exists():
            lines = env_path.read_text().splitlines()

        def update_or_add(key: str, value: str) -> None:
            for i, line in enumerate(lines):
                if line.startswith(f"{key}="):
                    lines[i] = f"{key}={value}"
                    return
            lines.append(f"{key}={value}")

        try:
            port = int(self.port_edit.text())
            interval = int(self.scan_interval_edit.text())
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Port and scan interval must be integers.")
            return

        update_or_add("SAN_DAEMON_PORT", str(port))
        update_or_add("SAN_DISCOVERY_INTERVAL_SECONDS", str(interval))
        update_or_add("SAN_CLOUD_SCAN_URL", self.cloud_url_edit.text())
        update_or_add("SAN_CLOUD_SCAN_API_KEY", self.cloud_key_edit.text())
        update_or_add("SAN_DESKTOP_NOTIFICATIONS", "true" if self.notifications_check.isChecked() else "false")

        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text("\n".join(lines) + "\n")
        QMessageBox.information(self, "Settings Saved", "Restart the daemon for changes to take effect.")
        self.close()
