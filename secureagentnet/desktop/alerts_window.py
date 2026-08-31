"""Full alert history window."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPushButton,
    QHBoxLayout,
    QMessageBox,
)

from secureagentnet.daemon.config import get_daemon_settings

from secureagentnet.desktop.theme import COLORS

if TYPE_CHECKING:
    from secureagentnet.desktop.main_window import MainWindow


class AlertsWindow(QDialog):
    def __init__(self, main_window: "MainWindow"):
        super().__init__(main_window)
        self.main_window = main_window
        self.setWindowTitle("Security Alerts")
        self.setMinimumSize(800, 500)
        self.setStyleSheet(f"background-color: {COLORS['window']}; color: {COLORS['ink']};")

        layout = QVBoxLayout(self)
        header = QLabel("Blocked Activity & Security Alerts")
        header.setStyleSheet(f"font-size: 17px; font-weight: 700; color: {COLORS['red']};")
        layout.addWidget(header)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Title", "Message", "Details"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setStyleSheet(
            f"QTableWidget {{ background-color: {COLORS['card']}; gridline-color: {COLORS['line_soft']};"f" border: 1px solid {COLORS['line']}; border-radius: 8px; color: {COLORS['ink']}; }}"
            f"QHeaderView::section {{ background-color: {COLORS['surface_2']}; color: {COLORS['muted']};"f" padding: 7px; border: none; border-bottom: 1px solid {COLORS['line']};"f" font-weight: 700; font-size: 9px; letter-spacing: 1px; }}"
        )
        self.table.itemClicked.connect(self._show_details)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(
            f"QPushButton {{ background-color: {COLORS['red']}; color: #1a0806; border: none;"f" border-radius: 7px; padding: 9px 16px; font-weight: 700; }}"
        )
        refresh_btn.clicked.connect(self.load)
        btn_layout.addStretch()
        btn_layout.addWidget(refresh_btn)
        layout.addLayout(btn_layout)

        self.load()

    def load(self) -> None:
        from secureagentnet.daemon.alerts import AlertManager
        alerts = AlertManager(settings=get_daemon_settings()).recent_alerts(limit=200)
        self.table.setRowCount(len(alerts))
        for row, alert in enumerate(reversed(alerts)):
            self.table.setItem(row, 0, QTableWidgetItem(str(alert.get("timestamp", ""))[:19]))
            self.table.setItem(row, 1, QTableWidgetItem(str(alert.get("severity", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(str(alert.get("title", ""))))
            self.table.setItem(row, 3, QTableWidgetItem(str(alert.get("message", ""))))
            detail_item = QTableWidgetItem("View")
            detail_item.setData(0x100, alert)  # Store full alert
            self.table.setItem(row, 4, detail_item)

    def _show_details(self, item: QTableWidgetItem) -> None:
        alert = item.data(0x100)
        if not alert:
            return
        detail = json.dumps(alert, indent=2, default=str)
        QMessageBox.information(self, "Alert Details", detail)
