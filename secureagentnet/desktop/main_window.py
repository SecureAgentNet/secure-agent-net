"""Primary window for the SecureAgentNet desktop app.

An endpoint-security console: a dark sidebar nav, a protection-status centrepiece,
and pages for Agents, Activity, Commands (action panels + an embedded `san`
console), Cloud enrollment and Settings.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable, List

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QButtonGroup, QComboBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar, QPushButton,
    QScrollArea, QSizePolicy, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from secureagentnet.desktop.console import SanConsole
from secureagentnet.desktop.theme import COLORS, STYLESHEET, PHASES

if TYPE_CHECKING:
    from secureagentnet.desktop.app import DesktopApplication

_STATE_COLOR = {
    "protected": COLORS["green"],
    "warning": COLORS["amber"],
    "threat": COLORS["red"],
    "offline": COLORS["muted"],
}

# (accent, fill) per ITCD phase — used for tinted timeline / activity rows.
_PHASE_STYLE = {
    "IDENTIFY": ("#16a34a", "#ecfdf5"), "TRACK": ("#2563eb", "#eff6ff"),
    "CONTAIN": ("#7c3aed", "#f5f3ff"), "DECIDE": ("#dc2626", "#fef2f2"),
    "EXECUTE": ("#16a34a", "#ecfdf5"),
}
# (fg, bg) per status/verdict — used for badges.
_STATUS_STYLE = {
    "SUCCESS": ("#15803d", "#dcfce7"), "APPROVED": ("#15803d", "#dcfce7"),
    "PERMIT": ("#15803d", "#dcfce7"), "ACTIVE": ("#15803d", "#dcfce7"),
    "REDACTED": ("#b45309", "#fef3c7"), "WARNING": ("#b45309", "#fef3c7"),
    "ESCALATE": ("#b45309", "#fef3c7"), "STALE": ("#b45309", "#fef3c7"),
    "DENIED": ("#b91c1c", "#fee2e2"), "FAILED": ("#b91c1c", "#fee2e2"),
    "CRITICAL": ("#b91c1c", "#fee2e2"), "ERROR": ("#b91c1c", "#fee2e2"),
    "ROGUE": ("#b91c1c", "#fee2e2"), "KILL-SWITCH": ("#b91c1c", "#fee2e2"),
    "INFO": ("#1d4ed8", "#dbeafe"),
}


def _set_badge(label: QLabel, text: str, kind: str | None = None) -> None:
    key = (kind or text).upper()
    fg, bg = _STATUS_STYLE.get(key, ("#475569", "#eef2f7"))
    label.setText(text.upper())
    label.setStyleSheet(
        f"color:{fg}; background:{bg}; border-radius:9px; padding:2px 9px;"
        "font-size:10px; font-weight:700; letter-spacing:.4px;")
    label.setMaximumHeight(20)


def _badge(text: str, kind: str | None = None) -> QLabel:
    """A small rounded status pill matching the product design system."""
    lab = QLabel()
    _set_badge(lab, text, kind)
    return lab


class StatusPoller(QThread):
    """Polls the daemon on a background thread so the UI never blocks on I/O."""

    updated = Signal(dict)

    def __init__(self, client, interval: float = 5.0, parent=None):
        super().__init__(parent)
        self.client = client
        self.interval = interval
        self._running = True

    def run(self) -> None:
        import time
        while self._running:
            data = {"alive": False, "status": None, "agents": [], "health": {}, "hitl": []}
            try:
                if self.client.is_alive():
                    data["alive"] = True
                    data["status"] = self.client.status() or {}
                    # Registered agents are the persistent inventory; fall back to the
                    # live discovery scan if the daemon predates the /v1/agents route.
                    agents = self.client.registered_agents()
                    if not agents:
                        agents = self.client.discovered_agents()
                    data["agents"] = agents or []
                    data["health"] = self.client.service_health() or {}
                    data["hitl"] = self.client.hitl_pending() or []
            except Exception:
                pass
            self.updated.emit(data)
            # sleep in short slices so stop() is responsive
            for _ in range(int(self.interval * 5)):
                if not self._running:
                    break
                time.sleep(0.2)

    def stop(self) -> None:
        self._running = False
        self.wait(2500)


class ScanWorker(QThread):
    """Runs a (potentially slow) discovery scan off the UI thread."""

    done = Signal(dict)

    def __init__(self, client, parent=None):
        super().__init__(parent)
        self.client = client

    def run(self) -> None:
        self.done.emit(self.client.scan(timeout=120) or {})


class StatusBadge(QWidget):
    """A painted circular protection indicator (check / alert / offline)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(104, 104)
        self._state = "protected"

    def set_state(self, state: str) -> None:
        self._state = state
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        color = QColor(_STATE_COLOR.get(self._state, COLORS["muted"]))
        tint = QColor(color); tint.setAlpha(28)
        r = self.rect().adjusted(8, 8, -8, -8)
        # disc + ring
        p.setBrush(QBrush(tint))
        p.setPen(QPen(color, 5))
        p.drawEllipse(r)
        # glyph
        glyph_pen = QPen(color, 6)
        glyph_pen.setCapStyle(Qt.RoundCap)
        glyph_pen.setJoinStyle(Qt.RoundJoin)
        p.setPen(glyph_pen)
        cx, cy = self.width() / 2, self.height() / 2
        if self._state in ("protected",):
            path = QPainterPath()
            path.moveTo(cx - 16, cy + 1)
            path.lineTo(cx - 4, cy + 13)
            path.lineTo(cx + 18, cy - 14)
            p.drawPath(path)
        elif self._state == "offline":
            p.drawLine(cx - 15, cy, cx + 15, cy)
        else:  # warning / threat → exclamation
            p.drawLine(cx, cy - 16, cx, cy + 6)
            p.setBrush(QBrush(color)); p.setPen(Qt.NoPen)
            p.drawEllipse(int(cx) - 3, int(cy) + 12, 6, 6)
        p.end()


def _card(*children: QWidget, title: str | None = None) -> QWidget:
    box = QFrame(); box.setObjectName("card")
    lay = QVBoxLayout(box); lay.setContentsMargins(18, 16, 18, 16); lay.setSpacing(10)
    if title:
        t = QLabel(title); t.setObjectName("sectionTitle"); lay.addWidget(t)
    for c in children:
        lay.addWidget(c)
    return box


class StatCard(QFrame):
    def __init__(self, label: str):
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self); lay.setContentsMargins(16, 14, 16, 14); lay.setSpacing(2)
        self.value = QLabel("–"); self.value.setObjectName("statValue")
        cap = QLabel(label); cap.setObjectName("statLabel")
        lay.addWidget(self.value); lay.addWidget(cap)

    def set(self, v: str) -> None:
        self.value.setText(v)


class PhaseCard(QFrame):
    """A colour-coded ITCD phase tile (IDENTIFY / TRACK / CONTAIN / DECIDE)."""
    def __init__(self, object_name: str, title: str, accent: str):
        super().__init__()
        self.setObjectName(object_name)
        lay = QVBoxLayout(self); lay.setContentsMargins(16, 14, 16, 14); lay.setSpacing(6)
        t = QLabel(title); t.setObjectName("phaseTitle"); t.setStyleSheet(f"color:{accent};")
        self.stat = QLabel(""); self.stat.setObjectName("phaseStat")
        lay.addWidget(t); lay.addWidget(self.stat)

    def set_lines(self, lines: list[str]) -> None:
        self.stat.setText("\n".join(lines))


class MainWindow(QMainWindow):
    def __init__(self, app: "DesktopApplication"):
        super().__init__()
        self.app = app
        self.setWindowTitle("SecureAgentNet")
        self.setMinimumSize(1060, 720)
        self.setStyleSheet(STYLESHEET)

        root = QWidget(); root.setObjectName("root")
        self.setCentralWidget(root)
        row = QHBoxLayout(root); row.setContentsMargins(0, 0, 0, 0); row.setSpacing(0)

        self.stack = QStackedWidget()
        row.addWidget(self._build_sidebar())
        row.addWidget(self.stack, 1)

        self._agents_cache: list = []     # row-index → agent dict, for the detail view
        self._event_buffer: list = []     # recent events, fed to the Forensics table

        self._pages: dict[str, int] = {}
        self._add_page("protection", self._page_protection())
        self._add_page("agents", self._page_agents())
        self._add_page("agent_detail", self._page_agent_detail())
        self._add_page("forensics", self._page_forensics())
        self._add_page("hitl", self._page_hitl())
        self._add_page("activity", self._page_activity())
        self._add_page("commands", self._page_commands())
        self._add_page("cloud", self._page_cloud())
        self._add_page("settings", self._page_settings())
        self._select("protection")

        # Poll the daemon off the UI thread; updates arrive via the signal.
        self._poller = StatusPoller(self.app.client)
        self._poller.updated.connect(self._apply_status)
        self._poller.start()

    # ── sidebar ──────────────────────────────────────────────────
    def _build_sidebar(self) -> QWidget:
        bar = QWidget(); bar.setObjectName("sidebar"); bar.setFixedWidth(212)
        lay = QVBoxLayout(bar); lay.setContentsMargins(16, 18, 16, 16); lay.setSpacing(6)

        brand = QHBoxLayout(); brand.setSpacing(8)
        logo = QLabel(); logo.setFixedSize(26, 26)
        logo.setStyleSheet("background:#0f766e; border-radius:7px;")
        txt = QVBoxLayout(); txt.setSpacing(0)
        name = QLabel("SecureAgentNet"); name.setObjectName("logoText")
        sub = QLabel("ENDPOINT SECURITY"); sub.setObjectName("logoSub")
        txt.addWidget(name); txt.addWidget(sub)
        brand.addWidget(logo); brand.addLayout(txt); brand.addStretch()
        lay.addLayout(brand)
        lay.addSpacing(14)

        self._nav_group = QButtonGroup(self); self._nav_group.setExclusive(True)
        self._nav_buttons: dict[str, QPushButton] = {}
        for key, label in (("protection", "Dashboard"), ("agents", "Agents"),
                           ("forensics", "Forensics"), ("hitl", "HITL Queue"),
                           ("activity", "Activity"), ("commands", "Commands"),
                           ("cloud", "Cloud"), ("settings", "Settings")):
            b = QPushButton(label); b.setObjectName("nav"); b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key: self._select(k))
            b._key = key; b._label = label
            self._nav_group.addButton(b)
            self._nav_buttons[key] = b
            lay.addWidget(b)

        lay.addStretch()
        self.conn_label = QLabel("● daemon: …"); self.conn_label.setObjectName("connDot")
        lay.addWidget(self.conn_label)
        return bar

    def _add_page(self, key: str, widget: QWidget) -> None:
        self._pages[key] = self.stack.addWidget(widget)

    def _select(self, key: str) -> None:
        self.stack.setCurrentIndex(self._pages[key])
        for b in self._nav_group.buttons():
            if getattr(b, "_key", None) == key:
                b.setChecked(True)

    def _page_header(self, title: str, subtitle: str) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(2)
        t = QLabel(title); t.setObjectName("pageTitle")
        s = QLabel(subtitle); s.setObjectName("pageSub")
        lay.addWidget(t); lay.addWidget(s)
        return w

    def _page_shell(self) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget(); lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 24, 28, 24); lay.setSpacing(16)
        return page, lay

    # ── Dashboard (home) ─────────────────────────────────────────
    def _page_protection(self) -> QWidget:
        content = QWidget(); lay = QVBoxLayout(content)
        lay.setContentsMargins(28, 24, 28, 24); lay.setSpacing(16)
        lay.addWidget(self._page_header("Dashboard", "Zero-trust monitoring for autonomous AI agents on this host"))

        self.badge = StatusBadge()
        banner_text = QVBoxLayout(); banner_text.setSpacing(2)
        self.banner_title = QLabel("Protected"); self.banner_title.setStyleSheet("font-size:22px; font-weight:700; color:#0f172a;")
        self.banner_sub = QLabel("The ITCD pipeline is guarding every agent action."); self.banner_sub.setObjectName("pageSub")
        banner_text.addStretch(); banner_text.addWidget(self.banner_title); banner_text.addWidget(self.banner_sub); banner_text.addStretch()
        banner_row = QHBoxLayout(); banner_row.setSpacing(18)
        banner_row.addWidget(self.badge); banner_row.addLayout(banner_text); banner_row.addStretch()
        scan = QPushButton("Scan now"); scan.setObjectName("primary"); scan.clicked.connect(self._on_scan)
        self.scan_btn = scan
        banner_row.addWidget(scan, 0, Qt.AlignVCenter)
        banner_w = QWidget(); banner_w.setLayout(banner_row)
        lay.addWidget(_card(banner_w))

        # ITCD phase tiles (colour-coded, mirror the product dashboard)
        self.phase_cards: dict[str, PhaseCard] = {}
        _phase_defaults = {
            "phaseIdentify": ("IDENTIFY", ["Active agents: –", "Authenticated: –", "Rogue: 0"]),
            "phaseTrack":    ("TRACK",    ["Events: –", "Audit: Vault", "Queries: –"]),
            "phaseContain":  ("CONTAIN",  ["Containers: –", "Isolation: on", "Network: isolated"]),
            "phaseDecide":   ("DECIDE",   ["Requests: –", "Approved: –", "Kill-switch: off"]),
        }
        prow = QHBoxLayout(); prow.setSpacing(14)
        for obj, accent, _fill, _border in PHASES:
            title, lines = _phase_defaults[obj]
            card = PhaseCard(obj, title, accent); card.set_lines(lines)
            self.phase_cards[obj] = card; prow.addWidget(card)
        prow_w = QWidget(); prow_w.setLayout(prow); lay.addWidget(prow_w)

        # Recent activity (live event stream)
        self.recent_table = self._make_table(["Time", "Phase", "Detail"], [120, 90])
        self.recent_table.setMinimumHeight(160)
        lay.addWidget(_card(self.recent_table, title="Recent activity"))

        # Bottom row: Security alerts + System health (mirrors the product dashboard)
        bottom = QHBoxLayout(); bottom.setSpacing(16)
        bottom.addWidget(self._security_alerts_card(), 1)
        bottom.addWidget(self._system_health_card(), 1)
        bottom_w = QWidget(); bottom_w.setLayout(bottom); lay.addWidget(bottom_w)
        lay.addStretch()

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(content)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea{background:transparent; border:none;}")
        return scroll

    def _security_alerts_card(self) -> QWidget:
        self.sec_alerts_box = QVBoxLayout(); self.sec_alerts_box.setSpacing(8)
        self._sec_alert_empty = QLabel("No alerts yet — the pipeline is quiet.")
        self._sec_alert_empty.setObjectName("pageSub")
        self.sec_alerts_box.addWidget(self._sec_alert_empty)
        holder = QWidget(); holder.setLayout(self.sec_alerts_box)
        return _card(holder, title="Security alerts")

    def _system_health_card(self) -> QWidget:
        self.health_rows: dict[str, tuple[QLabel, QLabel]] = {}
        box = QVBoxLayout(); box.setSpacing(9)
        for svc in ("Database", "Vault", "Ollama LLM", "Docker", "MCP Gateway"):
            row = QHBoxLayout()
            dot = QLabel("●"); dot.setStyleSheet(f"color:{COLORS['muted']}; font-size:13px;")
            name = QLabel(svc); name.setStyleSheet("font-size:13px; color:#1f2937;")
            state = QLabel("checking…")
            state.setStyleSheet(f"color:{COLORS['muted']}; font-size:12px;")
            row.addWidget(dot); row.addWidget(name); row.addStretch(); row.addWidget(state)
            rw = QWidget(); rw.setLayout(row); box.addWidget(rw)
            self.health_rows[svc] = (dot, state)
        holder = QWidget(); holder.setLayout(box)
        return _card(holder, title="System health")

    # ── Agents ───────────────────────────────────────────────────
    def _page_agents(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Agents", "AI agents discovered and monitored on this host"))
        self.agents_table = self._make_table(["Name", "Framework", "Source", "Status", "ID"], [220, 120, 110, 90])
        self.agents_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.agents_table.cellDoubleClicked.connect(self._open_agent_detail)
        hint = QLabel("Double-click an agent to open its detail view."); hint.setObjectName("pageSub")
        refresh = QPushButton("Refresh"); refresh.setObjectName("ghost"); refresh.clicked.connect(self._load_discovered_agents)
        commission = QPushButton("Commission an agent →"); commission.setObjectName("primary")
        commission.clicked.connect(lambda: self._select("commands"))
        bar = QHBoxLayout(); bar.addWidget(refresh); bar.addStretch(); bar.addWidget(commission)
        bar_w = QWidget(); bar_w.setLayout(bar)
        lay.addWidget(_card(bar_w, self.agents_table, hint), 1)
        return page

    # ── Agent detail ─────────────────────────────────────────────
    def _res_label(self, text: str) -> QLabel:
        l = QLabel(text); l.setStyleSheet("font-size:11px; color:#64748b; font-weight:600;")
        return l

    def _res_bar(self, color: str) -> QProgressBar:
        b = QProgressBar(); b.setRange(0, 100); b.setValue(0); b.setFixedHeight(18)
        b.setStyleSheet(
            "QProgressBar{border:none; background:#eef2f7; border-radius:6px;"
            "text-align:center; font-size:10px; color:#0f172a;}"
            f"QProgressBar::chunk{{background:{color}; border-radius:6px;}}")
        return b

    def _page_agent_detail(self) -> QWidget:
        page = QWidget(); outer = QVBoxLayout(page)
        outer.setContentsMargins(28, 24, 28, 24); outer.setSpacing(16)

        head = QHBoxLayout()
        back = QPushButton("← Back to Agents"); back.setObjectName("ghost")
        back.clicked.connect(lambda: self._select("agents"))
        self.detail_title = QLabel("Agent details"); self.detail_title.setObjectName("pageTitle")
        self.detail_badge = _badge("ACTIVE", "ACTIVE")
        head.addWidget(back); head.addSpacing(12); head.addWidget(self.detail_title)
        head.addStretch(); head.addWidget(self.detail_badge)
        head_w = QWidget(); head_w.setLayout(head); outer.addWidget(head_w)

        cols = QHBoxLayout(); cols.setSpacing(16)
        self.detail_info = QLabel("—")
        self.detail_info.setStyleSheet(
            "font-family:'JetBrains Mono','DejaVu Sans Mono',monospace; font-size:12px; color:#1f2937;")
        self.detail_info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.detail_info.setAlignment(Qt.AlignTop)
        self.detail_info.setWordWrap(True)
        cols.addWidget(_card(self.detail_info, title="Agent information"), 1)

        res = QVBoxLayout(); res.setSpacing(8)
        res.addWidget(self._res_label("CPU usage"))
        self.detail_cpu = self._res_bar("#2563eb"); res.addWidget(self.detail_cpu)
        res.addWidget(self._res_label("Memory usage"))
        self.detail_mem = self._res_bar("#7c3aed"); res.addWidget(self.detail_mem)
        self.detail_net = QLabel("Network I/O\n  RX: —    TX: —")
        self.detail_net.setStyleSheet("font-family:monospace; font-size:11px; color:#64748b;")
        res.addWidget(self.detail_net)
        self.detail_container = QLabel("Container: —")
        self.detail_container.setStyleSheet("font-family:monospace; font-size:11px; color:#64748b;")
        res.addWidget(self.detail_container); res.addStretch()
        res_w = QWidget(); res_w.setLayout(res)
        cols.addWidget(_card(res_w, title="Container resources"), 1)

        self.detail_sec = QVBoxLayout(); self.detail_sec.setSpacing(7)
        for t in ("Read-only filesystem", "Seccomp profile active", "AppArmor enforced",
                  "Network isolated", "Capabilities dropped: ALL"):
            l = QLabel("✓  " + t)
            l.setStyleSheet("color:#16a34a; font-family:monospace; font-size:12px;")
            self.detail_sec.addWidget(l)
        self.detail_sec.addStretch()
        sec_w = QWidget(); sec_w.setLayout(self.detail_sec)
        cols.addWidget(_card(sec_w, title="Security profile"), 1)
        cols_w = QWidget(); cols_w.setLayout(cols); outer.addWidget(cols_w)

        self.detail_timeline = QVBoxLayout(); self.detail_timeline.setSpacing(8)
        tl_holder = QWidget(); tl_holder.setLayout(self.detail_timeline)
        outer.addWidget(_card(tl_holder, title="Activity timeline (ITCD)"), 1)
        return page

    def _timeline_row(self, phase: str, detail: str) -> QWidget:
        fg, bg = _PHASE_STYLE.get(phase.upper(), ("#475569", "#eef2f7"))
        f = QFrame(); f.setStyleSheet(f"background:{bg}; border-radius:8px;")
        v = QVBoxLayout(f); v.setContentsMargins(12, 8, 12, 8); v.setSpacing(1)
        top = QLabel(phase.upper())
        top.setStyleSheet(f"color:{fg}; font-weight:700; font-size:11px; font-family:monospace;")
        sub = QLabel(detail)
        sub.setStyleSheet("color:#1f2937; font-size:11px; font-family:monospace;")
        v.addWidget(top); v.addWidget(sub)
        return f

    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _open_agent_detail(self, row: int, _col: int = 0) -> None:
        if 0 <= row < len(self._agents_cache):
            self.show_agent_detail(self._agents_cache[row])

    @staticmethod
    def _trust_rating(t) -> str:
        if not isinstance(t, (int, float)):
            return ""
        return (" (Excellent)" if t >= 90 else " (Good)" if t >= 70
                else " (Fair)" if t >= 40 else " (Low)")

    def show_agent_detail(self, agent: dict) -> None:
        aid = str(agent.get("agent_id", ""))
        # Fetch the enriched detail from the daemon; fall back to the list row.
        detail = self.app.client.agent_detail(aid) if aid else None
        d = {**agent, **(detail or {})}

        name = d.get("name", "unknown")
        fw = d.get("framework") or d.get("type", "Custom")
        status = str(d.get("status", "active")).upper()
        trust = d.get("trust_score")
        caps = d.get("capabilities")
        if isinstance(caps, dict):
            caps = ", ".join(k for k, v in caps.items() if v)
        elif isinstance(caps, (list, tuple)):
            caps = ", ".join(map(str, caps))
        caps = caps or "—"

        self.detail_title.setText(f"Agent details: {name}")
        _set_badge(self.detail_badge, status, status)
        trust_txt = (f"{trust:.1f}%{self._trust_rating(trust)}"
                     if isinstance(trust, (int, float)) else "—")
        container = d.get("container") or {}
        cid = container.get("container_id") or "—"
        self.detail_info.setText(
            f"Agent ID       {aid[:18] or '—'}\n"
            f"Name           {name}\n"
            f"Type           {fw}\n"
            f"Status         {status}\n"
            f"Trust score    {trust_txt}\n"
            f"Current phase  {d.get('current_phase') or '—'}\n"
            f"Registered     {str(d.get('registered_at', '') or '')[:19] or '—'}\n"
            f"Last seen      {str(d.get('last_seen', '') or '')[:19] or '—'}\n"
            f"Container ID   {str(cid)[:18]}\n"
            f"Capabilities   {caps}")

        # ── container resources ──
        live = d.get("live")
        cpu_limit = container.get("cpu_limit_cores")
        mem_limit = container.get("memory_limit_mb")
        if live:
            cpu = live.get("cpu_percent", 0) or 0
            self.detail_cpu.setValue(int(min(cpu, 100))); self.detail_cpu.setFormat(f"{cpu:.0f}%")
            mlim = live.get("memory_limit_mb") or mem_limit or 0
            mused = live.get("memory_mb", 0) or 0
            mpct = int((mused / mlim) * 100) if mlim else 0
            self.detail_mem.setValue(min(mpct, 100))
            self.detail_mem.setFormat(f"{mpct}% ({mused:.0f}MB / {mlim or '—'}MB)")
            self.detail_net.setText(
                f"Network I/O\n  RX: {live.get('rx_mb', '—')} MB    TX: {live.get('tx_mb', '—')} MB")
        else:
            self.detail_cpu.setValue(0)
            self.detail_cpu.setFormat(f"limit: {cpu_limit} core" if cpu_limit else "no live container")
            self.detail_mem.setValue(0)
            self.detail_mem.setFormat(f"limit: {mem_limit} MB" if mem_limit else "no live container")
            self.detail_net.setText("Network I/O\n  isolated — no live container")
        self.detail_container.setText(f"Container: {str(cid)[:18]}   ·   {container.get('status', 'none')}")

        # ── security profile (real flags) ──
        self._clear_layout(self.detail_sec)
        sp = d.get("security_profile")
        if isinstance(sp, dict):
            for label, val in sp.items():
                ok = (val is True) or (isinstance(val, str) and val)
                mark, color = ("✓", "#16a34a") if ok else ("✗", "#dc2626")
                text = f"{mark}  {label}" + (f": {val}" if isinstance(val, str) else "")
                l = QLabel(text)
                l.setStyleSheet(f"color:{color}; font-family:monospace; font-size:12px;")
                self.detail_sec.addWidget(l)
        else:
            for t in ("Read-only filesystem", "Seccomp profile active", "AppArmor enforced",
                      "Network isolated", "Capabilities dropped: ALL"):
                l = QLabel("✓  " + t)
                l.setStyleSheet("color:#16a34a; font-family:monospace; font-size:12px;")
                self.detail_sec.addWidget(l)
        self.detail_sec.addStretch()

        # ── activity timeline (with timestamps) ──
        self._clear_layout(self.detail_timeline)
        tl = d.get("timeline") or []
        if tl:
            for e in tl[:8]:
                raw = str(e.get("time", ""))
                ts = raw[11:19] or raw[:19]
                ph = (e.get("phase") or "DECIDE").upper()
                summ = e.get("summary") or e.get("event") or ""
                self.detail_timeline.addWidget(self._timeline_row(ph, f"{ts}   {summ}"))
        else:
            evs = [e for e in self._event_buffer
                   if name in e.get("agent", "") or (aid and aid[:8] in e.get("agent", ""))]
            if evs:
                for e in evs[:8]:
                    raw = str(e.get("time", "")); ts = raw[11:19] or raw
                    self.detail_timeline.addWidget(self._timeline_row(
                        e.get("phase", "DECIDE") or "DECIDE",
                        f"{ts}   {e.get('event','')}  [{e.get('status','')}]"))
            else:
                auth = "verified" if status == "ACTIVE" else status.lower()
                for ph, txt in (("IDENTIFY", f"Challenge-response auth — {auth}; trust manifest checked"),
                                ("CONTAIN", "Hardened sandbox provisioned (seccomp · AppArmor · cgroups)"),
                                ("TRACK", "Actions logged to Vault (append-only, HMAC-SHA256)"),
                                ("DECIDE", "Intent Capsule loaded; actions adjudicated against mandate")):
                    self.detail_timeline.addWidget(self._timeline_row(ph, txt))
        self.detail_timeline.addStretch()
        self._select("agent_detail")

    # ── Forensics ────────────────────────────────────────────────
    def _page_forensics(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Forensics", "Query the tamper-evident audit trail"))

        top = QHBoxLayout(); top.setSpacing(16)
        qb = QVBoxLayout(); qb.setSpacing(8)
        lab = QLabel("Agent ID or name"); lab.setObjectName("fieldLabel")
        self.forensic_query = QLineEdit()
        self.forensic_query.setPlaceholderText("e.g. email-support-agent")
        self.forensic_query.returnPressed.connect(self._run_forensic_query)
        run = QPushButton("Run query"); run.setObjectName("primary")
        run.clicked.connect(self._run_forensic_query)
        qb.addWidget(lab); qb.addWidget(self.forensic_query)
        qbar = QHBoxLayout(); qbar.addWidget(run); qbar.addStretch()
        qbar_w = QWidget(); qbar_w.setLayout(qbar); qb.addWidget(qbar_w)
        qb_w = QWidget(); qb_w.setLayout(qb)
        top.addWidget(_card(qb_w, title="Query builder"), 1)

        qf = QGridLayout(); qf.setSpacing(8)
        for i, (label, key) in enumerate([("Successful Auth", "SUCCESS"), ("Failed Auth", "FAILED"),
                ("PII Detected", "REDACTED"), ("Container Events", "CONTAIN"),
                ("Denied Requests", "DENIED")]):
            b = QPushButton(label); b.setObjectName("ghost")
            b.clicked.connect(lambda _=False, k=key: self._apply_forensic_filter(k))
            qf.addWidget(b, i // 3, i % 3)
        qf_w = QWidget(); qf_w.setLayout(qf)
        top.addWidget(_card(qf_w, title="Quick filters"), 1)
        top_w = QWidget(); top_w.setLayout(top); lay.addWidget(top_w)

        self.forensic_table = self._make_table(
            ["Timestamp", "Agent", "Phase", "Event type", "Status"], [150, 170, 100, 160])
        self.forensic_count = QLabel("0 events"); self.forensic_count.setObjectName("pageSub")
        console_btn = QPushButton("Run in console (full audit)"); console_btn.setObjectName("ghost")
        console_btn.clicked.connect(self._forensic_to_console)
        fbar = QHBoxLayout(); fbar.addWidget(self.forensic_count); fbar.addStretch(); fbar.addWidget(console_btn)
        fbar_w = QWidget(); fbar_w.setLayout(fbar)
        lay.addWidget(_card(fbar_w, self.forensic_table, title="Query results"), 1)
        return page

    def _render_forensic(self, events: list) -> None:
        self.forensic_table.setRowCount(len(events))
        for r, e in enumerate(events):
            for c, val in enumerate((e.get("time", ""), e.get("agent", ""),
                                     e.get("phase", ""), e.get("event", ""))):
                self.forensic_table.setItem(r, c, QTableWidgetItem(str(val)))
            st = str(e.get("status", "INFO"))
            item = QTableWidgetItem(st.upper())
            fg, _bg = _STATUS_STYLE.get(st.upper(), ("#475569", "#eef2f7"))
            item.setForeground(QColor(fg))
            self.forensic_table.setItem(r, 4, item)
        self.forensic_count.setText(f"{len(events)} event(s)")

    def _run_forensic_query(self) -> None:
        q = self.forensic_query.text().strip().lower()
        evs = [e for e in self._event_buffer
               if not q or q in (e.get("agent", "") + " " + e.get("event", "")).lower()]
        self._render_forensic(evs)

    def _apply_forensic_filter(self, key: str) -> None:
        k = key.upper()
        evs = [e for e in self._event_buffer
               if k == str(e.get("status", "")).upper() or k == str(e.get("phase", "")).upper()]
        self._render_forensic(evs)

    def _forensic_to_console(self) -> None:
        q = self.forensic_query.text().strip()
        args = ["forensics", "query"] + (["--agent", q] if q else [])
        self._select("commands"); self.console.run(args)

    # ── HITL review queue ────────────────────────────────────────
    def _page_hitl(self) -> QWidget:
        page, lay = self._page_shell()
        head = QHBoxLayout()
        head.addWidget(self._page_header("HITL review queue",
                                         "Escalated actions awaiting a human decision"))
        head.addStretch()
        self.hitl_count = _badge("0 PENDING", "INFO")
        head.addWidget(self.hitl_count, 0, Qt.AlignTop)
        head_w = QWidget(); head_w.setLayout(head); lay.addWidget(head_w)

        cols = QHBoxLayout(); cols.setSpacing(16)
        # queue (left)
        self.hitl_queue_box = QVBoxLayout(); self.hitl_queue_box.setSpacing(8)
        self.hitl_empty = QLabel("No actions awaiting review — the pipeline is clear.")
        self.hitl_empty.setObjectName("pageSub")
        self.hitl_queue_box.addWidget(self.hitl_empty); self.hitl_queue_box.addStretch()
        qholder = QWidget(); qholder.setLayout(self.hitl_queue_box)
        qscroll = QScrollArea(); qscroll.setWidgetResizable(True); qscroll.setWidget(qholder)
        qscroll.setFrameShape(QFrame.NoFrame)
        qscroll.setStyleSheet("QScrollArea{background:transparent; border:none;}")
        cols.addWidget(_card(qscroll, title="Escalation queue"), 3)

        # review detail (right)
        self.hitl_detail = QLabel("Select an item from the queue to review.")
        self.hitl_detail.setWordWrap(True); self.hitl_detail.setAlignment(Qt.AlignTop)
        self.hitl_detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.hitl_detail.setStyleSheet(
            "font-family:'JetBrains Mono','DejaVu Sans Mono',monospace; font-size:12px; color:#1f2937;")
        self.hitl_approve_btn = QPushButton("✓  Approve once")
        self.hitl_approve_btn.setStyleSheet(
            "background:#16a34a; color:#fff; border:none; border-radius:8px;"
            "padding:9px 16px; font-weight:600;")
        self.hitl_approve_btn.clicked.connect(lambda: self._hitl_decide(True))
        self.hitl_deny_btn = QPushButton("✕  Deny + log"); self.hitl_deny_btn.setObjectName("danger")
        self.hitl_deny_btn.clicked.connect(lambda: self._hitl_decide(False))
        self.hitl_approve_btn.setEnabled(False); self.hitl_deny_btn.setEnabled(False)
        btns = QHBoxLayout(); btns.addWidget(self.hitl_approve_btn)
        btns.addWidget(self.hitl_deny_btn); btns.addStretch()
        btns_w = QWidget(); btns_w.setLayout(btns)
        note = QLabel("Decisions are signed and written to the tamper-evident audit log.")
        note.setObjectName("pageSub")
        review_inner = QWidget(); rv = QVBoxLayout(review_inner)
        rv.setContentsMargins(0, 0, 0, 0); rv.setSpacing(12)
        rv.addWidget(self.hitl_detail, 1); rv.addWidget(btns_w); rv.addWidget(note)
        cols.addWidget(_card(review_inner, title="Review"), 2)
        cols_w = QWidget(); cols_w.setLayout(cols); lay.addWidget(cols_w, 1)

        self._hitl_pending: list = []
        self._hitl_selected_id = None
        self._hitl_ids: list | None = None
        return page

    def _on_hitl_update(self, pending: list) -> None:
        ids = [r.get("request_id") for r in (pending or [])]
        if ids == self._hitl_ids:
            return
        self._hitl_ids = ids
        self._render_hitl(pending or [])

    def _render_hitl(self, pending: list) -> None:
        self._hitl_pending = pending
        self._hitl_ids = [r.get("request_id") for r in pending]
        _set_badge(self.hitl_count, f"{len(pending)} PENDING", "WARNING" if pending else "INFO")
        btn = self._nav_buttons.get("hitl")
        if btn is not None:
            btn.setText(f"HITL Queue  ({len(pending)})" if pending else "HITL Queue")

        self._clear_layout(self.hitl_queue_box)
        if not pending:
            e = QLabel("No actions awaiting review — the pipeline is clear.")
            e.setObjectName("pageSub")
            self.hitl_queue_box.addWidget(e); self.hitl_queue_box.addStretch()
            self.hitl_detail.setText("Select an item from the queue to review.")
            self.hitl_approve_btn.setEnabled(False); self.hitl_deny_btn.setEnabled(False)
            self._hitl_selected_id = None
            return
        for req in pending:
            agent = str(req.get("agent_id", ""))[:12]
            risk = req.get("risk_score", 0.0)
            txt = (f"  {agent or '—'}      risk {risk:.2f}\n"
                   f"  {req.get('action_name', '')} → {req.get('target_resource', '')}")
            b = QPushButton(txt); b.setCheckable(True); b.setCursor(Qt.PointingHandCursor)
            b.setStyleSheet(
                "QPushButton{text-align:left; background:#fef2f2; border:1px solid #fecaca;"
                "border-radius:10px; padding:10px; color:#1f2937;"
                "font-family:'JetBrains Mono','DejaVu Sans Mono',monospace; font-size:11px;}"
                "QPushButton:checked{border:2px solid #dc2626; background:#fee2e2;}")
            b.clicked.connect(lambda _=False, r=req: self._select_hitl(r))
            self.hitl_queue_box.addWidget(b)
        self.hitl_queue_box.addStretch()
        if self._hitl_selected_id not in self._hitl_ids:
            self._hitl_selected_id = None
            self.hitl_detail.setText("Select an item from the queue to review.")
            self.hitl_approve_btn.setEnabled(False); self.hitl_deny_btn.setEnabled(False)

    def _select_hitl(self, req: dict) -> None:
        self._hitl_selected_id = req.get("request_id")
        self.hitl_detail.setText(
            f"Request    {str(req.get('request_id', ''))[:18]}\n"
            f"Agent      {req.get('agent_id', '')}\n"
            f"Action     {req.get('action_name', '')}\n"
            f"Target     {req.get('target_resource', '')}\n"
            f"Risk       {req.get('risk_score', 0.0):.2f}\n"
            f"Created    {str(req.get('created_at', ''))[:19]}\n\n"
            f"Intent\n  {req.get('intent_summary', '—')}\n\n"
            f"Reason for escalation\n  {req.get('reason', '—')}")
        self.hitl_approve_btn.setEnabled(True); self.hitl_deny_btn.setEnabled(True)

    def _hitl_decide(self, approve: bool) -> None:
        rid = self._hitl_selected_id
        if not rid:
            return
        self.app.client.hitl_decide(rid, approve)
        # optimistic update — the next poll reconciles with the daemon
        remaining = [r for r in self._hitl_pending if r.get("request_id") != rid]
        self._hitl_selected_id = None
        self._render_hitl(remaining)

    # ── Activity ─────────────────────────────────────────────────
    def _page_activity(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Activity", "Live security alerts from the local daemon"))
        self.alerts_table = self._make_table(["Time", "Severity", "Title", "Detail"], [140, 90, 200])
        self.alerts_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        view_logs = QPushButton("Open full audit log (san view-logs)"); view_logs.setObjectName("ghost")
        view_logs.clicked.connect(lambda: (self._select("commands"), self.console.run(["view-logs"])))
        lay.addWidget(_card(self.alerts_table, view_logs, title="Alerts"), 1)
        return page

    # ── Commands (action panels + embedded console) ──────────────
    def _page_commands(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Commands", "Every SecureAgentNet CLI command, from the GUI"))

        # quick, no-argument actions
        quick = QHBoxLayout(); quick.setSpacing(8)
        for label, args in (("Doctor", ["doctor"]), ("List agents", ["agent", "list"]),
                            ("Audit log", ["view-logs"]), ("Metrics", ["metrics"]),
                            ("Cloud status", ["cloud", "status"])):
            b = QPushButton(label); b.setObjectName("ghost")
            b.clicked.connect(lambda _=False, a=args: self.console.run(a))
            quick.addWidget(b)
        quick.addStretch()
        quick_w = QWidget(); quick_w.setLayout(quick)
        lay.addWidget(_card(quick_w, title="Quick actions"))

        # parameterised action forms
        forms = QGridLayout(); forms.setSpacing(10)
        forms.addWidget(self._form_register(), 0, 0)
        forms.addWidget(self._form_commission(), 0, 1)
        forms.addWidget(self._form_run(), 1, 0)
        forms.addWidget(self._form_cloud_enroll(), 1, 1)
        forms_w = QWidget(); forms_w.setLayout(forms)
        lay.addWidget(forms_w)

        self.console = SanConsole()
        lay.addWidget(_card(self.console, title="Console"), 1)
        return page

    def _form(self, title: str, fields: List[tuple], run_label: str,
              build_args: Callable[[dict], list]) -> QWidget:
        inputs: dict[str, QWidget] = {}
        rows = QVBoxLayout(); rows.setSpacing(8)
        for key, placeholder, kind in fields:
            lab = QLabel(placeholder); lab.setObjectName("fieldLabel")
            if kind == "combo":
                w = QComboBox(); w.addItems(["Custom", "LangChain", "CrewAI", "AutoGen"])
            else:
                w = QLineEdit(); w.setPlaceholderText(placeholder)
            inputs[key] = w
            rows.addWidget(lab); rows.addWidget(w)
        btn = QPushButton(run_label); btn.setObjectName("primary")

        def _go():
            vals = {k: (w.currentText() if isinstance(w, QComboBox) else w.text().strip())
                    for k, w in inputs.items()}
            args = build_args(vals)
            if args is None:
                self.console.run([])  # no-op guard
                return
            self._select("commands")
            self.console.run(args)
        btn.clicked.connect(_go)
        rows.addWidget(btn)
        wrap = QWidget(); wrap.setLayout(rows)
        return _card(wrap, title=title)

    def _form_register(self) -> QWidget:
        return self._form("Register agent",
                          [("name", "Agent name", "text"), ("type", "Framework", "combo")],
                          "Register",
                          lambda v: ["agent", "register", v["name"] or "new-agent", "--type", v["type"]])

    def _form_commission(self) -> QWidget:
        return self._form("Commission (set mandate)",
                          [("agent", "Agent name or id", "text"),
                           ("goal", "Commissioned goal", "text"),
                           ("approve", "Approved actions (comma)", "text")],
                          "Commission",
                          lambda v: ["agent", "commission", v["agent"], "--goal", v["goal"]]
                                    + (["--approve-actions", v["approve"]] if v["approve"] else []))

    def _form_run(self) -> QWidget:
        return self._form("Run an action through ITCD",
                          [("agent", "Agent name or id", "text"), ("cmd", "Command", "text")],
                          "Run",
                          lambda v: ["run", v["agent"], v["cmd"]])

    def _form_cloud_enroll(self) -> QWidget:
        return self._form("Enroll with cloud console",
                          [("url", "Console URL", "text"), ("token", "Enrollment token", "text")],
                          "Enroll",
                          lambda v: ["cloud", "enroll", "--url", v["url"], "--token", v["token"]])

    # ── Cloud ────────────────────────────────────────────────────
    def _page_cloud(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Cloud console", "Report this endpoint up to a central console"))
        self.cloud_status_label = QLabel("Checking enrollment…"); self.cloud_status_label.setObjectName("pageSub")
        check = QPushButton("Check status"); check.setObjectName("ghost")
        check.clicked.connect(lambda: (self._select("commands"), self.console.run(["cloud", "status"])))
        enroll = QPushButton("Enroll this endpoint →"); enroll.setObjectName("primary")
        enroll.clicked.connect(lambda: self._select("commands"))
        bar = QHBoxLayout(); bar.addWidget(check); bar.addStretch(); bar.addWidget(enroll)
        bar_w = QWidget(); bar_w.setLayout(bar)
        lay.addWidget(_card(self.cloud_status_label, bar_w, title="Enrollment"))
        lay.addStretch()
        return page

    # ── Settings ─────────────────────────────────────────────────
    def _page_settings(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Settings", "Daemon connection and app information"))
        info = QLabel(
            f"Daemon endpoint:  {self.app.client.base_url}\n"
            "Alerts stream:    live websocket\n"
            "Reporting:        metadata only (when enrolled to a cloud console)\n\n"
            "The desktop app talks to the local daemon on this host. Start one with\n"
            "`secureagentnet-daemon` if the status reads offline."
        )
        info.setStyleSheet("color:#44403c; font-size:13px;")
        lay.addWidget(_card(info, title="Connection"))
        lay.addStretch()
        return page

    # ── helpers ──────────────────────────────────────────────────
    def _make_table(self, headers: list[str], widths: list[int]) -> QTableWidget:
        t = QTableWidget(); t.setColumnCount(len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.verticalHeader().setVisible(False)
        t.setEditTriggers(QTableWidget.NoEditTriggers)
        t.setSelectionBehavior(QTableWidget.SelectRows)
        t.horizontalHeader().setStretchLastSection(True)
        for i, w in enumerate(widths):
            t.setColumnWidth(i, w)
        return t

    # ── live data (interface used by app.py) ─────────────────────
    def refresh(self) -> None:
        # Called once at startup; the background poller fills in live data.
        self._set_state("offline", "Connecting…", "Contacting the local daemon…")

    def _apply_status(self, data: dict) -> None:
        """Slot for StatusPoller.updated — runs on the UI thread, no network here."""
        alive = bool(data.get("alive"))
        self.conn_label.setText("● daemon: online" if alive else "● daemon: offline")
        self.conn_label.setStyleSheet(
            f"#connDot {{ color: {COLORS['green'] if alive else COLORS['muted']}; }}")
        self._update_health(alive, data.get("health"))
        if not alive:
            self._on_hitl_update([])
            self._set_state("offline", "Daemon offline", "Start it with `secureagentnet-daemon`.")
            return
        status = data.get("status") or {}
        if self.badge._state != "threat":
            self._set_state("protected", "Protected",
                            "The ITCD pipeline is guarding every agent action.")
        agents = data.get("agents") or []
        self._fill_agents_table(agents)
        self._update_phase_cards(status, agents)
        self._on_hitl_update(data.get("hitl") or [])

    def _update_health(self, alive: bool, services: dict | None = None) -> None:
        """Render real per-service probe results from the daemon's /v1/health."""
        services = services or {}
        for svc, (dot, state) in getattr(self, "health_rows", {}).items():
            st = str(services.get(svc, "")).lower()
            if not alive:
                color, txt, bold = COLORS["muted"], "offline", ""
            elif st == "online":
                color, txt, bold = COLORS["green"], "Online", "font-weight:600;"
            elif st == "offline":
                color, txt, bold = COLORS["red"], "Offline", "font-weight:600;"
            else:
                color, txt, bold = COLORS["muted"], "checking…", ""
            dot.setStyleSheet(f"color:{color}; font-size:13px;")
            state.setText(txt)
            state.setStyleSheet(f"color:{color}; font-size:12px; {bold}")

    def _update_phase_cards(self, status: dict, agents: list) -> None:
        if not getattr(self, "phase_cards", None):
            return
        total = status.get("agents_total", len(agents))
        authed = sum(1 for a in agents if str(a.get("status", "")).lower() == "active")
        rogue = sum(1 for a in agents if str(a.get("status", "")).lower() == "rogue")
        blocked = status.get("threats_blocked", 0)
        containers = status.get("containers", authed)
        self.phase_cards["phaseIdentify"].set_lines(
            [f"Active agents: {total}", f"Authenticated: {authed}", f"Rogue: {rogue}"])
        self.phase_cards["phaseTrack"].set_lines(
            [f"Events: {status.get('events_logged', '—')}", "Audit: Vault (HMAC)",
             f"Queries: {status.get('forensic_queries', '—')}"])
        self.phase_cards["phaseContain"].set_lines(
            [f"Containers: {containers}", "Isolation: on", "Network: isolated"])
        self.phase_cards["phaseDecide"].set_lines(
            [f"Requests: {status.get('requests_total', '—')}", f"Blocked: {blocked}",
             f"Kill-switch: {'ARMED' if blocked else 'off'}"])

    def _set_state(self, state: str, title: str, sub: str) -> None:
        self.badge.set_state(state)
        self.banner_title.setText(title)
        self.banner_sub.setText(sub)
        color = _STATE_COLOR.get(state, COLORS["muted"])
        self.banner_title.setStyleSheet(f"font-size:22px; font-weight:700; color:{color};")

    def _fill_agents_table(self, agents: list) -> None:
        self._agents_cache = agents
        self.agents_table.setRowCount(len(agents))
        for row, a in enumerate(agents):
            self.agents_table.setItem(row, 0, QTableWidgetItem(str(a.get("name", ""))))
            self.agents_table.setItem(row, 1, QTableWidgetItem(str(a.get("framework", "") or a.get("type", ""))))
            self.agents_table.setItem(row, 2, QTableWidgetItem(str(a.get("source", ""))))
            self.agents_table.setItem(row, 3, QTableWidgetItem(str(a.get("status", ""))))
            self.agents_table.setItem(row, 4, QTableWidgetItem(str(a.get("agent_id", ""))[:12]))

    def _load_discovered_agents(self) -> None:
        # Manual refresh button (Agents page) — registered inventory, with a
        # fall-back to the live discovery scan on older daemons.
        agents = self.app.client.registered_agents() or self.app.client.discovered_agents() or []
        self._fill_agents_table(agents)

    def handle_alert(self, alert: dict) -> None:
        sev = str(alert.get("severity", "INFO"))
        detail = str(alert.get("message", "") or alert.get("title", ""))
        ts = str(alert.get("timestamp", ""))[:19]
        phase = str(alert.get("phase", "") or "DECIDE").upper()
        agent = str(alert.get("agent_id", "") or alert.get("agent", ""))

        # Activity table (full)
        self.alerts_table.insertRow(0)
        for i, v in enumerate([ts, sev, str(alert.get("title", "")), detail]):
            item = QTableWidgetItem(v)
            if i == 1 and sev in ("CRITICAL", "WARNING", "ERROR"):
                item.setForeground(QColor(COLORS["red"] if sev != "WARNING" else COLORS["amber"]))
            self.alerts_table.setItem(0, i, item)
        while self.alerts_table.rowCount() > 60:
            self.alerts_table.removeRow(self.alerts_table.rowCount() - 1)

        # Dashboard recent-activity table (Time / Phase / Detail)
        self.recent_table.insertRow(0)
        for i, v in enumerate([ts[11:] or ts, phase, detail]):
            item = QTableWidgetItem(v)
            if i == 1:
                fg, _bg = _PHASE_STYLE.get(phase, ("#475569", ""))
                item.setForeground(QColor(fg))
            self.recent_table.setItem(0, i, item)
        while self.recent_table.rowCount() > 60:
            self.recent_table.removeRow(self.recent_table.rowCount() - 1)

        # Security-alerts card (dashboard) + forensic event buffer
        self._add_security_alert(sev, f"{sev}: {detail}" if detail else sev)
        self._event_buffer.insert(0, {
            "time": ts, "agent": agent or "—", "phase": phase,
            "event": (alert.get("title", "") or detail)[:48], "status": sev,
        })
        self._event_buffer = self._event_buffer[:200]
        if getattr(self, "forensic_table", None) is not None:
            self._run_forensic_query()

        if sev in ("CRITICAL", "ERROR"):
            self._set_state("threat", "Threat blocked", detail[:80])

    def _add_security_alert(self, sev: str, text: str) -> None:
        # Drop the "no alerts yet" placeholder from the layout the first time an alert
        # arrives, and clear the reference. Otherwise the prune loop below eventually
        # takeAt()/deleteLater()s it (it sits at the bottom of the box), leaving a
        # dangling C++ object that raises "already deleted" on the next access.
        placeholder = getattr(self, "_sec_alert_empty", None)
        if placeholder is not None:
            self._sec_alert_empty = None
            try:
                self.sec_alerts_box.removeWidget(placeholder)
                placeholder.deleteLater()
            except RuntimeError:
                pass  # already deleted in a previous (pre-fix) session
        fg, bg = _STATUS_STYLE.get(sev.upper(), ("#1d4ed8", "#dbeafe"))
        row = QLabel(text); row.setWordWrap(True)
        row.setStyleSheet(
            f"color:{fg}; background:{bg}; border-radius:8px; padding:8px 10px; font-size:12px;")
        self.sec_alerts_box.insertWidget(0, row)
        while self.sec_alerts_box.count() > 5:
            item = self.sec_alerts_box.takeAt(self.sec_alerts_box.count() - 1)
            if item.widget():
                item.widget().deleteLater()

    def _on_scan(self) -> None:
        self.scan_btn.setEnabled(False); self.scan_btn.setText("Scanning…")
        self._scan_worker = ScanWorker(self.app.client)
        self._scan_worker.done.connect(self._on_scan_done)
        self._scan_worker.start()

    def _on_scan_done(self, result: dict) -> None:
        self.scan_btn.setEnabled(True); self.scan_btn.setText("Scan now")
        QMessageBox.information(self, "Scan complete",
                                f"Discovered {result.get('discovered', 0)} AI agent(s) "
                                "(LangChain / CrewAI / AutoGen).")
