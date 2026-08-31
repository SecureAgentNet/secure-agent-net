"""Visual theme for the SecureAgentNet desktop app.

A dark operations console. The chrome recedes to near-black so that the only
saturated colour on screen is carrying information: the four ITCD phase hues, and
the allow / escalate / deny verdict signals. Data and logs are set in a monospace
face; chrome and labels in the UI sans.

Colour is a signal here, not decoration — nothing is tinted just to look lively.
Every token below is referenced by ``main_window.py`` rather than being written as
a literal, so the palette can be retuned in one place.
"""

def apply_palette(app) -> None:
    """Paint Qt's *default* widget colours dark.

    The stylesheet only reaches widgets it names. Plain containers — the page
    widgets inside the QStackedWidget, the viewport of every QScrollArea — keep
    the platform palette, which on a light desktop theme leaves the content plane
    white behind the dark cards. Setting the palette fixes those at the source,
    and the stylesheet keeps styling the named components on top.
    """
    from PySide6.QtGui import QColor, QPalette

    ground = QColor(COLORS["window"])
    surface = QColor(COLORS["card"])
    ink = QColor(COLORS["ink"])
    muted = QColor(COLORS["muted"])
    accent = QColor(COLORS["primary"])

    pal = QPalette()
    for group in (QPalette.Active, QPalette.Inactive, QPalette.Disabled):
        pal.setColor(group, QPalette.Window, ground)
        pal.setColor(group, QPalette.Base, QColor("#0e141b"))
        pal.setColor(group, QPalette.AlternateBase, surface)
        pal.setColor(group, QPalette.Button, surface)
        pal.setColor(group, QPalette.ToolTipBase, surface)
        pal.setColor(group, QPalette.Highlight, accent)
        pal.setColor(group, QPalette.Link, accent)
        text = muted if group == QPalette.Disabled else ink
        for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText,
                     QPalette.ToolTipText):
            pal.setColor(group, role, text)
        pal.setColor(group, QPalette.HighlightedText, QColor("#04120f"))
        pal.setColor(group, QPalette.PlaceholderText, QColor(COLORS["dim"]))
    app.setPalette(pal)


COLORS = {
    # ── ground & chrome ──
    "window": "#0b0f14",          # app ground
    "sidebar": "#070a0e",         # chrome sits *below* the content plane
    "sidebar_text": "#8896a4",
    "card": "#121820",            # raised surface
    "surface_2": "#18202a",       # insets: table headers, wells
    "line": "#232d38",
    "line_soft": "#1b242e",

    # ── type ──
    "ink": "#e6edf3",             # primary text
    "muted": "#8896a4",           # secondary text
    "dim": "#5f6d7a",             # tertiary / disabled

    # ── accent (interaction, not status) ──
    "primary": "#19b8a6",
    "primary_hover": "#25d0bc",
    "primary_dim": "#0e6e64",
    "accent": "#19b8a6",
    "teal": "#19b8a6",

    # ── semantic verdicts ──
    "green": "#3fbf6f",
    "green_wash": "#0f2318",
    "amber": "#e0a63c",
    "amber_wash": "#2b2211",
    "red": "#ef6d63",
    "red_wash": "#2e1614",
    "blue": "#5b9cf8",
    "blue_wash": "#101b2b",
    "purple": "#9b7ef0",
    "purple_wash": "#191430",

    # ── ITCD phase tints ──
    "identify": "#3fbf6f",
    "track": "#5b9cf8",
    "contain": "#9b7ef0",
    "decide": "#ef6d63",

    "console_bg": "#080b0f",
    "console_fg": "#c3d0dc",
}

MONO = "'JetBrains Mono','DejaVu Sans Mono','SF Mono',Menlo,monospace"

# (objectName, accent, fill, border) for the four ITCD phase cards.
PHASES = [
    ("phaseIdentify", "#3fbf6f", "#0f2318", "#1e4a31"),
    ("phaseTrack",    "#5b9cf8", "#101b2b", "#22406b"),
    ("phaseContain",  "#9b7ef0", "#191430", "#3a2e63"),
    ("phaseDecide",   "#ef6d63", "#2a1412", "#5a2a26"),
]

STYLESHEET = """
#root, QMainWindow, QStackedWidget { background: #0b0f14; }
QStackedWidget > QWidget { background: #0b0f14; }
QScrollArea { background: #0b0f14; border: none; }
QScrollArea > QWidget > QWidget { background: transparent; }
QWidget { color: #e6edf3; }
QToolTip {
  background: #18202a; color: #e6edf3; border: 1px solid #232d38;
  padding: 5px 8px; border-radius: 4px;
}

/* ── sidebar ─────────────────────────────────────────────────── */
#sidebar { background: #070a0e; border-right: 1px solid #1b242e; }
QLabel#logoText { color: #e6edf3; font-size: 14px; font-weight: 700; letter-spacing: .2px; }
QLabel#logoSub {
  color: #5f6d7a; font-size: 9px; font-weight: 600; letter-spacing: 1.4px;
}
QPushButton#nav {
  color: #8896a4; text-align: left; padding: 9px 12px 9px 13px;
  border: none; border-left: 2px solid transparent;
  background: transparent; font-size: 13px; font-weight: 500;
}
QPushButton#nav:hover { background: #101720; color: #e6edf3; }
QPushButton#nav:checked {
  background: #101720; color: #19b8a6;
  border-left: 2px solid #19b8a6; font-weight: 600;
}
QLabel#connDot { font-size: 11px; color: #8896a4; font-family: 'JetBrains Mono', monospace; }
QLabel#railMeta {
  font-size: 10px; color: #5f6d7a; font-family: 'JetBrains Mono', monospace;
}

/* ── content ─────────────────────────────────────────────────── */
QLabel#pageTitle { font-size: 19px; font-weight: 700; color: #e6edf3; letter-spacing: -.2px; }
QLabel#pageSub { font-size: 13px; color: #8896a4; }
QLabel#sectionTitle {
  font-size: 10px; font-weight: 700; color: #8896a4;
  letter-spacing: 1.2px; text-transform: uppercase;
}
QLabel#statValue {
  font-size: 25px; font-weight: 700; color: #e6edf3;
  font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace;
}
QLabel#statLabel {
  font-size: 10px; color: #8896a4; letter-spacing: .8px; text-transform: uppercase;
}
QLabel#fieldLabel { font-size: 13px; color: #a9b6c2; font-weight: 500; }
QLabel#bannerTitle { font-size: 21px; font-weight: 700; color: #e6edf3; }

#card { background: #121820; border: 1px solid #232d38; border-radius: 10px; }

/* ── ITCD phase cards ────────────────────────────────────────── */
QFrame#phaseIdentify { background: #0f2318; border: 1px solid #1e4a31; border-radius: 10px; }
QFrame#phaseTrack    { background: #101b2b; border: 1px solid #22406b; border-radius: 10px; }
QFrame#phaseContain  { background: #191430; border: 1px solid #3a2e63; border-radius: 10px; }
QFrame#phaseDecide   { background: #2a1412; border: 1px solid #5a2a26; border-radius: 10px; }
QLabel#phaseTitle { font-size: 10px; font-weight: 700; letter-spacing: 1.4px; }
QLabel#phaseStat {
  font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace;
  font-size: 11px; color: #a9b6c2;
}

/* ── buttons ─────────────────────────────────────────────────── */
QPushButton#primary {
  background: #19b8a6; color: #04120f; border: none; border-radius: 7px;
  padding: 11px 18px; font-weight: 700; font-size: 13px; letter-spacing: .3px;
}
QPushButton#primary:hover { background: #25d0bc; }
QPushButton#primary:pressed { background: #0e6e64; color: #d9fbf6; }
QPushButton#primary:disabled { background: #14332f; color: #5f6d7a; }
QPushButton#danger {
  background: #ef6d63; color: #1a0806; border: none; border-radius: 7px;
  padding: 9px 16px; font-weight: 700; font-size: 12px;
}
QPushButton#danger:hover { background: #f7867d; }
QPushButton#ghost {
  background: transparent; color: #c3d0dc; border: 1px solid #2d3945;
  border-radius: 7px; padding: 10px 16px; font-weight: 600; font-size: 13px;
}
QPushButton#ghost:hover { background: #18202a; border-color: #19b8a6; color: #e6edf3; }

/* ── inputs ──────────────────────────────────────────────────── */
QLineEdit, QComboBox {
  border: 1px solid #2d3945; border-radius: 7px; padding: 9px 12px;
  background: #0e141b; color: #e6edf3; font-size: 13px;
  selection-background-color: #0e6e64;
}
QLineEdit:focus, QComboBox:focus { border-color: #19b8a6; background: #101720; }
QLineEdit::placeholder { color: #5f6d7a; }
QComboBox::drop-down { border: none; width: 18px; }
QComboBox QAbstractItemView {
  background: #121820; color: #e6edf3; border: 1px solid #232d38;
  selection-background-color: #18202a; selection-color: #19b8a6; outline: none;
}

/* ── tables ──────────────────────────────────────────────────── */
QTableWidget {
  background: #121820; border: 1px solid #232d38; border-radius: 8px;
  gridline-color: #1b242e; color: #c3d0dc;
  alternate-background-color: #141b23;
  selection-background-color: #18202a; selection-color: #19b8a6;
  font-size: 12px;
}
QHeaderView::section {
  background: #0e141b; color: #8896a4; padding: 8px 10px; border: none;
  border-bottom: 1px solid #232d38; font-weight: 700; font-size: 9px;
  letter-spacing: 1px; text-transform: uppercase;
}
QTableWidget::item { padding: 5px 6px; border: none; }
QTableWidget::item:selected { background: #18202a; color: #19b8a6; }
QTableCornerButton::section { background: #0e141b; border: none; }

/* ── console ─────────────────────────────────────────────────── */
QPlainTextEdit#console {
  background: #080b0f; color: #c3d0dc; border: 1px solid #232d38;
  border-radius: 8px; font-family: 'JetBrains Mono', 'DejaVu Sans Mono', monospace;
  font-size: 13px; line-height: 20px; padding: 14px;
  selection-background-color: #0e6e64;
}
QLineEdit#consoleInput {
  background: #080b0f; color: #19b8a6; border: 1px solid #2d3945; border-radius: 8px;
  font-family: 'JetBrains Mono', monospace; font-size: 14px; padding: 11px 14px;
}
QLineEdit#consoleInput:focus { border-color: #19b8a6; }

/* ── scrollbars ──────────────────────────────────────────────── */
QScrollBar:vertical { background: transparent; width: 9px; margin: 2px; }
QScrollBar::handle:vertical { background: #2d3945; border-radius: 4px; min-height: 28px; }
QScrollBar::handle:vertical:hover { background: #3d4c5a; }
QScrollBar:horizontal { background: transparent; height: 9px; margin: 2px; }
QScrollBar::handle:horizontal { background: #2d3945; border-radius: 4px; min-width: 28px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; border: none; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }

/* ── misc ────────────────────────────────────────────────────── */
QSplitter::handle:vertical {
  background: #1b242e; height: 4px; margin: 3px 0; border-radius: 2px;
}
QSplitter::handle:vertical:hover { background: #19b8a6; }
QCheckBox { color: #c3d0dc; font-size: 12px; }
QCheckBox::indicator {
  width: 14px; height: 14px; border: 1px solid #2d3945;
  border-radius: 3px; background: #0e141b;
}
QCheckBox::indicator:checked { background: #19b8a6; border-color: #19b8a6; }
"""
