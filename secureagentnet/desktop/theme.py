"""Visual theme for the SecureAgentNet desktop app.

Matches the SecureAgentNet product design system: a light app surface with a
dark slate sidebar, a blue primary action, a green/teal status accent, the four
ITCD phase colours (IDENTIFY green, TRACK blue, CONTAIN purple, DECIDE red) and a
navy terminal. Data and logs are set in a monospace face.
"""

COLORS = {
    "window": "#f5f8fc",
    "sidebar": "#0f172a",
    "sidebar_text": "#94a3b8",
    "card": "#ffffff",
    "line": "#e6ebf2",
    "ink": "#0f172a",
    "muted": "#64748b",
    "primary": "#2563eb",
    "accent": "#10b981",
    "teal": "#10b981",
    "green": "#16a34a",
    "blue": "#2563eb",
    "purple": "#7c3aed",
    "amber": "#b45309",
    "red": "#dc2626",
    # ITCD phase tints
    "identify": "#16a34a",
    "track": "#2563eb",
    "contain": "#7c3aed",
    "decide": "#dc2626",
    "console_bg": "#0b1220",
    "console_fg": "#cbd5e1",
}

# (objectName, accent, fill, border) for the four ITCD phase cards.
PHASES = [
    ("phaseIdentify", "#16a34a", "#ecfdf5", "#bbf7d0"),
    ("phaseTrack",    "#2563eb", "#eff6ff", "#bfdbfe"),
    ("phaseContain",  "#7c3aed", "#f5f3ff", "#ddd6fe"),
    ("phaseDecide",   "#dc2626", "#fef2f2", "#fecaca"),
]

STYLESHEET = """
#root { background: #f5f8fc; }

/* ── sidebar ── */
#sidebar { background: #0f172a; }
QLabel#logoText { color: #ffffff; font-size: 15px; font-weight: 700; }
QLabel#logoSub { color: #64748b; font-size: 10px; letter-spacing: 1px; }
QPushButton#nav {
  color: #94a3b8; text-align: left; padding: 10px 14px; border: none;
  border-radius: 8px; background: transparent; font-size: 13px; font-weight: 500;
}
QPushButton#nav:hover { background: rgba(255,255,255,0.06); color: #ffffff; }
QPushButton#nav:checked { background: #2563eb; color: #ffffff; font-weight: 600; }
QLabel#connDot { font-size: 11px; color: #94a3b8; }

/* ── content ── */
QLabel#pageTitle { font-size: 20px; font-weight: 700; color: #0f172a; }
QLabel#pageSub { font-size: 12px; color: #64748b; }
QLabel#sectionTitle { font-size: 14px; font-weight: 600; color: #0f172a; }
QLabel#statValue { font-size: 26px; font-weight: 700; color: #0f172a; }
QLabel#statLabel { font-size: 11px; color: #64748b; }
QLabel#fieldLabel { font-size: 12px; color: #334155; font-weight: 500; }

#card { background: #ffffff; border: 1px solid #e6ebf2; border-radius: 12px; }

/* ── ITCD phase cards ── */
QFrame#phaseIdentify { background: #ecfdf5; border: 1px solid #bbf7d0; border-radius: 12px; }
QFrame#phaseTrack    { background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 12px; }
QFrame#phaseContain  { background: #f5f3ff; border: 1px solid #ddd6fe; border-radius: 12px; }
QFrame#phaseDecide   { background: #fef2f2; border: 1px solid #fecaca; border-radius: 12px; }
QLabel#phaseTitle { font-size: 12px; font-weight: 700; letter-spacing: 1px; }
QLabel#phaseStat {
  font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace; font-size: 11px; color: #334155;
}

QPushButton#primary {
  background: #2563eb; color: #ffffff; border: none; border-radius: 8px;
  padding: 9px 16px; font-weight: 600; font-size: 13px;
}
QPushButton#primary:hover { background: #1d4ed8; }
QPushButton#primary:disabled { background: #93b4f5; }
QPushButton#danger { background: #dc2626; color: #fff; border: none; border-radius: 8px; padding: 9px 16px; font-weight: 600; }
QPushButton#danger:hover { background: #b91c1c; }
QPushButton#ghost { background: #ffffff; color: #0f172a; border: 1px solid #cbd5e1; border-radius: 8px; padding: 9px 16px; font-weight: 600; }
QPushButton#ghost:hover { background: #f1f5f9; }

QLineEdit, QComboBox {
  border: 1px solid #cbd5e1; border-radius: 8px; padding: 7px 10px;
  background: #ffffff; color: #0f172a; font-size: 13px;
}
QLineEdit:focus, QComboBox:focus { border-color: #2563eb; }

QTableWidget {
  background: #ffffff; border: 1px solid #e6ebf2; border-radius: 8px;
  gridline-color: #f1f5f9; color: #0f172a;
}
QHeaderView::section {
  background: #f1f5f9; color: #64748b; padding: 8px 10px; border: none;
  border-bottom: 1px solid #e6ebf2; font-weight: 600; font-size: 11px;
}
QTableWidget::item { padding: 4px 6px; }

QPlainTextEdit#console {
  background: #0b1220; color: #cbd5e1; border: 1px solid #1e293b;
  border-radius: 8px; font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace;
  font-size: 12px; padding: 8px;
}
QLineEdit#consoleInput {
  background: #0b1220; color: #cbd5e1; border: 1px solid #1e293b; border-radius: 8px;
  font-family: 'JetBrains Mono', monospace; font-size: 12px; padding: 8px 10px;
}
QScrollBar:vertical { background: transparent; width: 10px; }
QScrollBar::handle:vertical { background: #cbd5e1; border-radius: 5px; min-height: 30px; }
"""
