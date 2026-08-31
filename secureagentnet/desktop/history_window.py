"""History / security log database viewer window."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QPushButton,
    QHBoxLayout,
)

from secureagentnet.database.repositories import AuditLogRepository

from secureagentnet.desktop.theme import COLORS

if TYPE_CHECKING:
    from secureagentnet.desktop.main_window import MainWindow


class HistoryWindow(QDialog):
    def __init__(self, main_window: "MainWindow"):
        super().__init__(main_window)
        self.main_window = main_window
        self.setWindowTitle("Security Log History")
        self.setMinimumSize(800, 500)
        self.setStyleSheet(f"background-color: {COLORS['window']}; color: {COLORS['ink']};")

        layout = QVBoxLayout(self)
        header = QLabel("Security Log Database")
        header.setStyleSheet(f"font-size: 17px; font-weight: 700; color: {COLORS['primary']};")
        layout.addWidget(header)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Time", "Agent", "Event", "Phase", "Severity", "Summary"])
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setStyleSheet(
            f"QTableWidget {{ background-color: {COLORS['card']}; gridline-color: {COLORS['line_soft']};"f" border: 1px solid {COLORS['line']}; border-radius: 8px; color: {COLORS['ink']}; }}"
            f"QHeaderView::section {{ background-color: {COLORS['surface_2']}; color: {COLORS['muted']};"f" padding: 7px; border: none; border-bottom: 1px solid {COLORS['line']};"f" font-weight: 700; font-size: 9px; letter-spacing: 1px; }}"
        )
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(
            f"QPushButton {{ background-color: {COLORS['primary']}; color: #04120f; border: none;"f" border-radius: 7px; padding: 9px 16px; font-weight: 700; }}"
        )
        refresh_btn.clicked.connect(self.load)
        btn_layout.addStretch()
        btn_layout.addWidget(refresh_btn)
        layout.addLayout(btn_layout)

        self.load()

    def load(self) -> None:
        events = AuditLogRepository.load_all()
        self.table.setRowCount(len(events))
        for row, event in enumerate(reversed(events[-200:])):
            self.table.setItem(row, 0, QTableWidgetItem(str(event.get("timestamp", ""))[:19]))
            self.table.setItem(row, 1, QTableWidgetItem(str(event.get("agent_id", "?"))[:8]))
            self.table.setItem(row, 2, QTableWidgetItem(str(event.get("event_type", ""))))
            self.table.setItem(row, 3, QTableWidgetItem(str(event.get("phase", ""))))
            self.table.setItem(row, 4, QTableWidgetItem(str(event.get("severity", ""))))
            self.table.setItem(row, 5, QTableWidgetItem(str(event.get("summary", ""))[:80]))
