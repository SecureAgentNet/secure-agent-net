"""Primary window for the SecureAgentNet desktop app.

An endpoint-security console with pages for host protection, agents, forensics,
HITL review, activity, commands and settings.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Callable, List

from collections import deque

from PySide6.QtCore import (
    QSettings, Qt, QThread, Signal, QPropertyAnimation, QEasingCurve, Property, QRectF,
)
from PySide6.QtGui import (
    QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen,
)
from PySide6.QtWidgets import (
    QButtonGroup, QCheckBox, QComboBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QScrollArea, QSizePolicy, QSplitter, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from secureagentnet.desktop.console import SanConsole
from secureagentnet.desktop.theme import COLORS, STYLESHEET, PHASES, MONO


# Vocabularies the forms offer instead of asking the operator to remember them.
# An agent's own capabilities always come first; these are the fallback for an
# agent that has not declared any yet.
def _common_actions() -> list[str]:
    """The action names an operator can tick when registering or commissioning.

    Derived from the capability library rather than written out again, so the
    two cannot drift: an action this build can actually perform should always be
    offerable, and one it cannot should not be silently suggested. The extras
    are actions the wider system understands even though the desktop has no
    tool for them.
    """
    try:
        from secureagentnet.agents.capabilities import supported

        known = set(supported())
    except Exception:  # pragma: no cover - agents package unavailable
        known = set()
    known.update({"http_request", "run_query"})
    return sorted(known)


COMMON_ACTIONS = _common_actions()
COMMON_RESOURCES = ["shell", "local filesystem", "support-inbox", "smtp",
                    "database", "http", "workspace"]


def capability_actions(agent: dict | None) -> list[str]:
    """The action names an agent actually holds, from either capability shape.

    The registry stores capabilities two ways — ``{"search_files": true}`` for a
    normal agent and ``{"level": "admin", "actions": ["*"]}`` for a privileged
    one — so a form that reads only the first shape silently offers nothing for
    the second.
    """
    caps = (agent or {}).get("capabilities") or {}
    if not isinstance(caps, dict):
        return []
    if "actions" in caps and isinstance(caps["actions"], list):
        actions = [a for a in caps["actions"] if isinstance(a, str) and a != "*"]
    else:
        actions = [k for k, v in caps.items()
                   if v is True and k not in ("level", "actions")]
    return sorted(actions)

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
    "IDENTIFY": (COLORS["identify"], "#0f2318"), "TRACK": (COLORS["track"], "#101b2b"),
    "CONTAIN": (COLORS["contain"], "#191430"), "DECIDE": (COLORS["decide"], "#2a1412"),
    "EXECUTE": (COLORS["identify"], "#0f2318"),
}
# (fg, bg) per status/verdict — used for badges.
_OK = (COLORS["green"], COLORS["green_wash"])
_WARN = (COLORS["amber"], COLORS["amber_wash"])
_BAD = (COLORS["red"], COLORS["red_wash"])
_STATUS_STYLE = {
    "SUCCESS": _OK, "APPROVED": _OK, "PERMIT": _OK, "ACTIVE": _OK,
    "REDACTED": _WARN, "WARNING": _WARN, "ESCALATE": _WARN, "STALE": _WARN,
    "DENIED": _BAD, "FAILED": _BAD, "CRITICAL": _BAD, "ERROR": _BAD,
    "ROGUE": _BAD, "KILL-SWITCH": _BAD,
    "INFO": (COLORS["blue"], COLORS["blue_wash"]),
}


class MandateDrafter(QThread):
    """Draft a mandate off the UI thread — the local model takes seconds."""

    drafted = Signal(object)     # DraftMandate
    failed = Signal(str)

    def __init__(self, brief: str, known_actions: list):
        super().__init__()
        self._brief = brief
        self._known = known_actions

    def run(self) -> None:
        try:
            from secureagentnet.decide.mandate_author import draft_from_brief
            self.drafted.emit(draft_from_brief(self._brief, known_actions=self._known))
        except Exception as exc:
            self.failed.emit(str(exc))


class ActionPicker(QWidget):
    """Tick the actions you mean, instead of typing a comma-separated list.

    The comma syntax was the single most error-prone field on the page: a stray
    space or a misremembered action name produced a mandate that silently did not
    cover the work. Here the choices are the agent's own capabilities, and the
    widget renders the comma string the CLI wants.
    """

    def __init__(self, placeholder: str = "add another…", parent=None):
        super().__init__(parent)
        self._boxes: list[QCheckBox] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(6)

        self._host = QWidget()
        self._host_lay = QVBoxLayout(self._host)
        self._host_lay.setContentsMargins(8, 6, 8, 6)
        self._host_lay.setSpacing(2)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setWidget(self._host)
        self._scroll.setFrameShape(QFrame.NoFrame)
        self._scroll.setFixedHeight(96)
        self._scroll.setStyleSheet(
            f"QScrollArea{{background:{COLORS['surface_2']};"
            f"border:1px solid {COLORS['line']}; border-radius:6px;}}")
        lay.addWidget(self._scroll)

        self._extra = QLineEdit()
        self._extra.setPlaceholderText(placeholder)
        self._extra.setMinimumHeight(32)
        lay.addWidget(self._extra)

        self._empty = QLabel("Select an agent to list its actions")
        self._empty.setObjectName("fieldLabel")
        self._host_lay.addWidget(self._empty)
        self._host_lay.addStretch()

    def set_options(self, options: list[str]) -> None:
        keep = set(self.selected())
        for box in self._boxes:
            box.setParent(None)
        self._boxes.clear()
        self._empty.setVisible(not options)
        for name in options:
            box = QCheckBox(name)
            box.setChecked(name in keep)
            self._host_lay.insertWidget(self._host_lay.count() - 1, box)
            self._boxes.append(box)

    def selected(self) -> list[str]:
        picked = [b.text() for b in self._boxes if b.isChecked()]
        typed = [t.strip() for t in self._extra.text().split(",") if t.strip()]
        seen, out = set(), []
        for name in picked + typed:
            if name not in seen:
                seen.add(name)
                out.append(name)
        return out

    def value(self) -> str:
        return ",".join(self.selected())

    def set_value(self, csv: str) -> None:
        """Tick what this agent offers; anything else falls to the free-text box."""
        wanted = [t.strip() for t in (csv or "").split(",") if t.strip()]
        offered = {b.text() for b in self._boxes}
        for box in self._boxes:
            box.setChecked(box.text() in wanted)
        self._extra.setText(",".join(w for w in wanted if w not in offered))

    def changed_signals(self) -> list:
        return [self._extra.textChanged]



def _set_badge(label: QLabel, text: str, kind: str | None = None) -> None:
    key = (kind or text).upper()
    fg, bg = _STATUS_STYLE.get(key, (COLORS["muted"], COLORS["surface_2"]))
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
    """Polls the daemon on a background thread so the UI never blocks on I/O.

    Endpoints are polled on three cadences rather than one, because they do not
    cost the same and do not change at the same rate:

      * live   (1.5s) — /v1/status and the HITL queue: in-memory on the daemon,
                        and the numbers a watching operator expects to move.
      * agents (4s)   — the inventory; touches Docker per container, so it is not
                        worth re-fetching several times a second.
      * health (15s)  — dependency probes. Genuinely expensive when something is
                        down, and a service does not flap second-to-second.

    Each cycle emits a *complete* snapshot by merging fresh values over the last
    known ones, so the slower lanes never blank the panels they feed.
    """

    updated = Signal(dict)

    # (seconds) per-lane intervals
    LIVE_INTERVAL = 1.5
    AGENTS_INTERVAL = 4.0
    HEALTH_INTERVAL = 15.0

    def __init__(self, client, interval: float = LIVE_INTERVAL, parent=None):
        super().__init__(parent)
        self.client = client
        self.interval = interval
        self._running = True
        self._snapshot = {"alive": False, "status": None, "agents": [], "health": {}, "hitl": []}
        self._seeded = False

    def _fetch_agents(self) -> list:
        # Registered agents are the persistent inventory; fall back to the live
        # discovery scan if the daemon predates the /v1/agents route.
        agents = self.client.registered_agents() or self.client.discovered_agents() or []
        contracts = {c.get("agent_id"): c for c in self.client.agent_contracts()}
        return [{**a, "agent_contract": contracts.get(a.get("agent_id"))} for a in agents]

    def run(self) -> None:
        import time
        last_agents = 0.0
        last_health = 0.0

        while self._running:
            cycle_started = time.monotonic()
            try:
                # status() doubles as the liveness check — a separate /health
                # round-trip first only added latency to every single cycle.
                status = self.client.status()
                if status is None:
                    self._snapshot = {"alive": False, "status": None,
                                      "agents": [], "health": {}, "hitl": []}
                else:
                    self._snapshot["alive"] = True
                    self._snapshot["status"] = status
                    self._snapshot["hitl"] = self.client.hitl_pending() or []

                    if not self._seeded:
                        # One-shot backfill so Activity and Forensics open with the
                        # history that predates this launch, not an empty table.
                        self._snapshot["events_seed"] = self.client.recent_events(200)
                        self._seeded = True
                    else:
                        self._snapshot.pop("events_seed", None)

                    now = time.monotonic()
                    if now - last_agents >= self.AGENTS_INTERVAL or not self._snapshot["agents"]:
                        self._snapshot["agents"] = self._fetch_agents()
                        last_agents = now
                    if now - last_health >= self.HEALTH_INTERVAL or not self._snapshot["health"]:
                        self._snapshot["health"] = self.client.service_health() or {}
                        last_health = now
            except Exception:
                pass

            self.updated.emit(dict(self._snapshot))

            # Sleep only the remainder of the interval, in slices, so a slow cycle
            # does not compound into drift and stop() stays responsive.
            deadline = cycle_started + self.interval
            while self._running and time.monotonic() < deadline:
                time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))

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
        t = QLabel(title); t.setObjectName("sectionTitle")
        # Pin the title to the top. With a Preferred vertical policy QVBoxLayout
        # hands the label a share of any spare height and centres it inside that,
        # so in a card taller than its content the heading drifted downward.
        t.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        lay.addWidget(t)
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


class HostMonitorPoller(QThread):
    """Samples real host telemetry (psutil) off the UI thread, ~1/second, so the
    Host Monitor updates live without ever blocking the interface."""

    sampled = Signal(dict)

    def __init__(self, interval: float = 1.0, parent=None):
        super().__init__(parent)
        self.interval = interval
        self._running = True

    def run(self) -> None:
        import time
        from secureagentnet.monitoring import HostSampler
        from secureagentnet.monitoring.host_telemetry import HostTelemetryMonitor
        sampler = HostSampler(top_n=6)
        telemetry = HostTelemetryMonitor()  # same spike logic DECIDE uses
        sampler.sample()  # prime rates (first read has no delta)
        while self._running:
            time.sleep(self.interval)
            if not self._running:
                break
            try:
                m = sampler.sample()
                if m.get("available"):
                    # Flag an outbound-network spike so the UI can show the same
                    # anomaly state that makes the gateway escalate exfil actions.
                    m["egress_anomaly"] = telemetry.observe_egress(
                        m["network"]["up_bps"])
                self.sampled.emit(m)
            except Exception:
                pass

    def stop(self) -> None:
        self._running = False
        self.wait(2500)


class Sparkline(QWidget):
    """A live, filled mini line-chart of the last N samples. This is the moving,
    'alive' element — CPU and network history stream across it in real time."""

    def __init__(self, color: str, maxlen: int = 60, y_max: float = 100.0, parent=None):
        super().__init__(parent)
        self._color = QColor(color)
        self._data: deque = deque([0.0] * maxlen, maxlen=maxlen)
        self._y_max = y_max
        self.setMinimumHeight(56)
        # Expand vertically too: pinned to a fixed 56px the trace sat on the floor
        # of a taller card with dead space above it.
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def push(self, value: float, y_max: float | None = None) -> None:
        if y_max is not None and y_max > 0:
            self._y_max = y_max
        self._data.append(max(0.0, float(value)))
        self.update()

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        n = len(self._data)
        if n < 2 or self._y_max <= 0:
            return
        step = w / (n - 1)
        top = 4.0
        usable = h - top - 2

        def pt(i, v):
            y = top + usable * (1.0 - min(v / self._y_max, 1.0))
            return i * step, y

        line = QPainterPath()
        line.moveTo(*pt(0, self._data[0]))
        for i in range(1, n):
            line.lineTo(*pt(i, self._data[i]))

        fill = QPainterPath(line)
        fill.lineTo((n - 1) * step, h)
        fill.lineTo(0, h)
        fill.closeSubpath()
        grad = QLinearGradient(0, 0, 0, h)
        c0 = QColor(self._color); c0.setAlpha(70)
        c1 = QColor(self._color); c1.setAlpha(0)
        grad.setColorAt(0, c0); grad.setColorAt(1, c1)
        p.fillPath(fill, QBrush(grad))

        base = QColor(self._color); base.setAlpha(38)
        p.setPen(QPen(base, 1))
        p.drawLine(0, int(h - 1), int(w), int(h - 1))

        p.setPen(QPen(self._color, 2))
        p.drawPath(line)

        # "Now" marker: the newest sample, so the eye lands on the current value.
        ex, ey = pt(n - 1, self._data[-1])
        halo = QColor(self._color); halo.setAlpha(60)
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(halo)); p.drawEllipse(QRectF(ex - 4.5, ey - 4.5, 9, 9))
        p.setBrush(QBrush(self._color)); p.drawEllipse(QRectF(ex - 2, ey - 2, 4, 4))
        p.end()


class MetricGauge(QFrame):
    """A stat card with a big live value and a smoothly-animated bar that turns
    amber/red as the metric climbs — the endpoint 'vital sign' at a glance."""

    def __init__(self, title: str, unit: str = "%"):
        super().__init__()
        self.setObjectName("card")
        self._value = 0.0
        lay = QVBoxLayout(self); lay.setContentsMargins(16, 14, 16, 14); lay.setSpacing(8)
        top = QHBoxLayout()
        t = QLabel(title); t.setObjectName("statLabel")
        self.value_lbl = QLabel(f"0{unit}"); self.value_lbl.setObjectName("statValue")
        top.addWidget(t); top.addStretch(); top.addWidget(self.value_lbl)
        lay.addLayout(top)
        self.bar = QProgressBar(); self.bar.setTextVisible(False)
        self.bar.setFixedHeight(8); self.bar.setRange(0, 1000)
        lay.addWidget(self.bar)
        self.sub = QLabel(""); self.sub.setObjectName("pageSub"); lay.addWidget(self.sub)
        self._unit = unit
        self._anim = QPropertyAnimation(self, b"barValue", self)
        self._anim.setDuration(450)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def get_bar_value(self) -> int:
        return self.bar.value()

    def set_bar_value(self, v: int) -> None:
        self.bar.setValue(int(v))

    barValue = Property(int, get_bar_value, set_bar_value)

    def _bar_color(self, pct: float) -> str:
        if pct >= 90:
            return COLORS["red"]
        if pct >= 70:
            return COLORS["amber"]
        return COLORS["green"]

    def update_value(self, percent: float, value_text: str | None = None,
                     sub_text: str = "") -> None:
        pct = max(0.0, min(percent, 100.0))
        self.value_lbl.setText(value_text if value_text is not None else f"{pct:.0f}{self._unit}")
        self.sub.setText(sub_text)
        color = self._bar_color(pct)
        self.bar.setStyleSheet(
            f"QProgressBar{{background:{COLORS['surface_2']}; border:none; border-radius:4px;}}"
            f"QProgressBar::chunk{{background:{color}; border-radius:4px;}}"
        )
        self._anim.stop()
        self._anim.setStartValue(self.bar.value())
        self._anim.setEndValue(int(pct * 10))
        self._anim.start()


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
        self._agent_selectors: list[QComboBox] = []
        # form title → its agent dropdown / its card, so the agent detail page can
        # send the operator straight into the right form with the agent chosen.
        self._form_agent_selectors: dict[str, QComboBox] = {}
        self._form_cards: dict[str, QWidget] = {}
        self._detail_agent_id: str = ""
        self._event_buffer: list = []     # recent events, fed to the Forensics table

        self._pages: dict[str, int] = {}
        self._add_page("prompt", self._page_prompt())
        self._add_page("protection", self._page_protection())
        self._add_page("host", self._page_host())
        self._add_page("agents", self._page_agents())
        self._add_page("agent_detail", self._page_agent_detail())
        self._add_page("forensics", self._page_forensics())
        self._add_page("hitl", self._page_hitl())
        self._add_page("activity", self._page_activity())
        self._add_page("commands", self._page_commands())
        self._add_page("runs", self._page_runs())
        self._add_page("settings", self._page_settings())
        # Prompting is now the way work starts, so it is where the app opens.
        self._select("prompt")

        # Poll the daemon off the UI thread; updates arrive via the signal.
        self._poller = StatusPoller(self.app.client)
        self._poller.updated.connect(self._apply_status)
        self._poller.start()

        # Live host telemetry (psutil) — the endpoint's own vital signs, ~1/sec.
        self._host_poller = HostMonitorPoller(interval=1.0)
        self._host_poller.sampled.connect(self._apply_host)
        self._host_poller.start()

    # ── sidebar ──────────────────────────────────────────────────
    def _build_sidebar(self) -> QWidget:
        bar = QWidget(); bar.setObjectName("sidebar"); bar.setFixedWidth(212)
        lay = QVBoxLayout(bar); lay.setContentsMargins(16, 18, 16, 16); lay.setSpacing(6)

        brand = QHBoxLayout(); brand.setSpacing(8)
        logo = QLabel(); logo.setFixedSize(26, 26)
        logo.setStyleSheet(f"background:{COLORS['primary']}; border-radius:7px;")
        txt = QVBoxLayout(); txt.setSpacing(0)
        name = QLabel("SecureAgentNet"); name.setObjectName("logoText")
        sub = QLabel("ENDPOINT SECURITY"); sub.setObjectName("logoSub")
        txt.addWidget(name); txt.addWidget(sub)
        brand.addWidget(logo); brand.addLayout(txt); brand.addStretch()
        lay.addLayout(brand)
        lay.addSpacing(14)

        self._nav_group = QButtonGroup(self); self._nav_group.setExclusive(True)
        self._nav_buttons: dict[str, QPushButton] = {}
        for key, label in (("prompt", "Prompt"), ("protection", "Dashboard"),
                           ("host", "Host Monitor"), ("agents", "Agents"),
                           ("runs", "Agent Runs"),
                           ("forensics", "Forensics"), ("hitl", "HITL Queue"),
                           ("activity", "Activity"), ("commands", "Commands"),
                           ("settings", "Settings")):
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
        if key == "runs" and getattr(self, "runs_page", None) is not None:
            self.runs_page.reload()
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

    # ── Prompt & runs ────────────────────────────────────────────
    def _page_prompt(self) -> QWidget:
        from secureagentnet.desktop.prompt_page import PromptPage

        self.prompt_page = PromptPage(self._operator_name)
        self.prompt_page.review_requested.connect(lambda: self._select("hitl"))
        return self.prompt_page

    def _page_runs(self) -> QWidget:
        from secureagentnet.desktop.prompt_page import RunsPage

        self.runs_page = RunsPage()
        return self.runs_page

    # ── Dashboard (home) ─────────────────────────────────────────
    def _page_protection(self) -> QWidget:
        content = QWidget(); lay = QVBoxLayout(content)
        lay.setContentsMargins(28, 24, 28, 24); lay.setSpacing(16)
        lay.addWidget(self._page_header("Dashboard", "Zero-trust monitoring for autonomous AI agents on this host"))

        self.badge = StatusBadge()
        banner_text = QVBoxLayout(); banner_text.setSpacing(2)
        self.banner_title = QLabel("Protected"); self.banner_title.setObjectName("bannerTitle")
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
        self.sec_alerts_box.addStretch()
        holder = QWidget(); holder.setLayout(self.sec_alerts_box)
        return _card(holder, title="Security alerts")

    def _system_health_card(self) -> QWidget:
        self.health_rows: dict[str, tuple[QLabel, QLabel]] = {}
        box = QVBoxLayout(); box.setSpacing(9)
        for svc in ("Database", "Vault", "Ollama LLM", "Docker", "MCP Gateway"):
            row = QHBoxLayout()
            dot = QLabel("●"); dot.setStyleSheet(f"color:{COLORS['muted']}; font-size:13px;")
            name = QLabel(svc); name.setStyleSheet(f"font-size:13px; color:{COLORS['ink']};")
            state = QLabel("checking…")
            state.setStyleSheet(f"color:{COLORS['muted']}; font-size:12px;")
            row.addWidget(dot); row.addWidget(name); row.addStretch(); row.addWidget(state)
            rw = QWidget(); rw.setLayout(row); box.addWidget(rw)
            self.health_rows[svc] = (dot, state)
        holder = QWidget(); holder.setLayout(box)
        return _card(holder, title="System health")

    # ── Host Monitor (live endpoint telemetry) ───────────────────
    def _page_host(self) -> QWidget:
        content = QWidget(); lay = QVBoxLayout(content)
        lay.setContentsMargins(28, 24, 28, 24); lay.setSpacing(16)
        lay.addWidget(self._page_header(
            "Host Monitor",
            "Live telemetry from this endpoint — the machine SecureAgentNet is protecting"))

        # Anomaly banner — lights up on a live outbound-network spike (the same
        # condition that makes DECIDE escalate exfiltration-shaped actions).
        self.host_anomaly_banner = QLabel()
        self.host_anomaly_banner.setWordWrap(True)
        self.host_anomaly_banner.setVisible(False)
        self.host_anomaly_banner.setStyleSheet(
            f"QLabel{{background:{COLORS['red_wash']}; color:{COLORS['red']};"
            f"border:1px solid #5a2a26; border-radius:8px; padding:10px 14px;"
            f"font-weight:600;}}")
        lay.addWidget(self.host_anomaly_banner)

        # System info strip
        self.host_sys = {}
        info_row = QHBoxLayout(); info_row.setSpacing(24)
        for key, label in (("hostname", "Host"), ("uptime", "Uptime"),
                           ("cores", "CPU cores"), ("procs", "Processes"),
                           ("conns", "Connections")):
            col = QVBoxLayout(); col.setSpacing(1)
            v = QLabel("–"); v.setObjectName("statValue"); v.setStyleSheet("font-size:16px;")
            cap = QLabel(label); cap.setObjectName("statLabel")
            col.addWidget(v); col.addWidget(cap)
            self.host_sys[key] = v
            info_row.addLayout(col)
        info_row.addStretch()
        info_w = QWidget(); info_w.setLayout(info_row)
        lay.addWidget(_card(info_w, title="System"))

        # Vital-sign gauges
        self.gauge_cpu = MetricGauge("CPU")
        self.gauge_mem = MetricGauge("Memory")
        self.gauge_disk = MetricGauge("Disk (/)")
        self.gauge_net = MetricGauge("Network", unit="")
        grow = QHBoxLayout(); grow.setSpacing(14)
        for g in (self.gauge_cpu, self.gauge_mem, self.gauge_disk, self.gauge_net):
            grow.addWidget(g, 1)
        grow_w = QWidget(); grow_w.setLayout(grow); lay.addWidget(grow_w)

        # Live sparklines
        self.spark_cpu = Sparkline(COLORS["blue"], y_max=100.0)
        self.spark_net = Sparkline(COLORS["purple"], y_max=1.0)
        srow = QHBoxLayout(); srow.setSpacing(14)
        srow.addWidget(_card(self.spark_cpu, title="CPU history (last 60s)"), 1)
        srow.addWidget(_card(self.spark_net, title="Network throughput (last 60s)"), 1)
        srow_w = QWidget(); srow_w.setLayout(srow); lay.addWidget(srow_w)

        # Top processes
        self.host_proc_table = self._make_table(["PID", "Process", "CPU %", "MEM %"], [70, 260, 90])
        self.host_proc_table.setMinimumHeight(200)
        lay.addWidget(_card(self.host_proc_table, title="Top processes"))
        lay.addStretch()

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(content)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea{background:transparent; border:none;}")
        return scroll

    def _apply_host(self, m: dict) -> None:
        """Render a host telemetry sample onto the live gauges/sparklines/table."""
        if not m.get("available"):
            self.host_sys["hostname"].setText("psutil unavailable")
            return
        cpu, mem, disk, net, sysd = (m["cpu"], m["memory"], m["disk"],
                                     m["network"], m["system"])

        self.host_sys["hostname"].setText(sysd["hostname"])
        self.host_sys["uptime"].setText(sysd["uptime"])
        self.host_sys["cores"].setText(str(cpu["count"]))
        self.host_sys["procs"].setText(str(sysd["process_count"]))
        conns = net["connections"]
        self.host_sys["conns"].setText(str(conns) if conns >= 0 else "n/a")

        self.gauge_cpu.update_value(
            cpu["percent"], f"{cpu['percent']:.0f}%",
            f"load {cpu['load_avg'][0]} · {cpu['count']} cores")
        self.gauge_mem.update_value(
            mem["percent"], f"{mem['percent']:.0f}%",
            f"{mem['used_h']} / {mem['total_h']}")
        self.gauge_disk.update_value(
            disk["percent"], f"{disk['percent']:.0f}%",
            f"{disk['used_h']} / {disk['total_h']}")

        # Network has no fixed ceiling; scale the bar against a rolling reference.
        down, up = net["down_bps"], net["up_bps"]
        self._net_peak = max(getattr(self, "_net_peak", 1.0), down, up, 1.0)
        net_pct = min(down / self._net_peak * 100.0, 100.0)
        anomaly = bool(m.get("egress_anomaly"))
        # On an outbound spike, force the network gauge into the alarm band so it
        # reads red — matching the escalation the gateway would raise.
        self.gauge_net.update_value(
            95.0 if anomaly else net_pct, f"↑{net['up_h']}",
            f"↓{net['down_h']} · {net['recv_total_h']} rx")

        if anomaly:
            self.host_anomaly_banner.setText(
                f"⚠  Outbound-network spike detected ({net['up_h']}). "
                "DECIDE will escalate exfiltration-shaped agent actions to human "
                "review while this persists.")
            self.host_anomaly_banner.setVisible(True)
        else:
            self.host_anomaly_banner.setVisible(False)

        # Sparklines: CPU on a fixed 0–100 scale; network auto-scaled to its peak.
        self.spark_cpu.push(cpu["percent"], y_max=100.0)
        self.spark_net.push(down, y_max=self._net_peak)

        rows = m["processes"]
        self.host_proc_table.setRowCount(len(rows))
        for i, pr in enumerate(rows):
            for c, val in enumerate((str(pr["pid"]), pr["name"],
                                     f"{pr['cpu']:.1f}", f"{pr['mem']:.1f}")):
                self.host_proc_table.setItem(i, c, QTableWidgetItem(val))

    # ── Agents ───────────────────────────────────────────────────
    def _page_agents(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Agents", "AI agents discovered and monitored on this host"))
        self.agents_table = self._make_table(
            ["Name", "Framework", "Project", "CPU", "Memory", "Container", "Status", "ID"],
            [150, 95, 135, 60, 90, 90, 70],
        )
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
        l = QLabel(text); l.setStyleSheet(f"font-size:11px; color:{COLORS['muted']}; font-weight:600;")
        return l

    def _res_bar(self, color: str) -> QProgressBar:
        b = QProgressBar(); b.setRange(0, 100); b.setValue(0); b.setFixedHeight(18)
        b.setStyleSheet(
            f"QProgressBar{{border:none; background:{COLORS['surface_2']}; border-radius:6px;"
            f"text-align:center; font-size:10px; color:{COLORS['ink']};}}"
            f"QProgressBar::chunk{{background:{color}; border-radius:6px;}}")
        return b

    # ── operator identity ────────────────────────────────────────
    def _settings_store(self) -> QSettings:
        return QSettings("SecureAgentNet", "Desktop")

    def _operator_name(self) -> str:
        """Who is accountable for decisions made from this app.

        Defaults to the OS login rather than a generic label: an audit row saying
        an action was released by "desktop" names an application, not a person,
        which is the one thing a review trail has to record.
        """
        saved = str(self._settings_store().value("operator", "") or "").strip()
        if saved:
            return saved
        try:
            import getpass
            return getpass.getuser()
        except Exception:
            return "desktop"

    def _set_operator_name(self, name: str) -> None:
        self._settings_store().setValue("operator", name.strip())

    def _act_on_current_agent(self, form_title: str) -> None:
        """Jump to Commands with this agent already chosen in the named form."""
        agent_id = getattr(self, "_detail_agent_id", "") or ""
        self._select("commands")
        target = self._form_agent_selectors.get(form_title)
        if target is not None and agent_id:
            idx = target.findData(agent_id)
            if idx >= 0:
                target.setCurrentIndex(idx)
        card = self._form_cards.get(form_title)
        if card is not None:
            # Bring the form into view inside the scrolling upper pane.
            scroll = getattr(self, "_commands_scroll", None)
            if scroll is not None:
                scroll.ensureWidgetVisible(card, 0, 40)
        if target is not None:
            target.setFocus()

    def _page_agent_detail(self) -> QWidget:
        page = QWidget(); outer = QVBoxLayout(page)
        outer.setContentsMargins(28, 24, 28, 24); outer.setSpacing(16)

        head = QHBoxLayout()
        back = QPushButton("← Back to Agents"); back.setObjectName("ghost")
        back.clicked.connect(lambda: self._select("agents"))
        self.detail_title = QLabel("Agent details"); self.detail_title.setObjectName("pageTitle")
        self.detail_badge = _badge("ACTIVE", "ACTIVE")
        head.addWidget(back); head.addSpacing(12); head.addWidget(self.detail_title)
        head.addStretch()

        # Act on the agent you are already looking at. Without these the operator
        # had to remember the agent, cross to Commands and find it again in a
        # dropdown — the commonest reason to touch the console by hand.
        for label, form_title in (("Commission…", "Commission (set mandate)"),
                                  ("Run action…", "Run an action through ITCD"),
                                  ("Grant capability…", "Grant a capability")):
            b = QPushButton(label); b.setObjectName("ghost")
            b.clicked.connect(lambda _=False, t=form_title: self._act_on_current_agent(t))
            head.addWidget(b)
            head.addSpacing(6)

        head.addWidget(self.detail_badge)
        head_w = QWidget(); head_w.setLayout(head); outer.addWidget(head_w)

        cols = QHBoxLayout(); cols.setSpacing(16)
        self.detail_info = QLabel("—")
        self.detail_info.setStyleSheet(
            f"font-family:{MONO}; font-size:12px; color:{COLORS['ink']};")
        self.detail_info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.detail_info.setAlignment(Qt.AlignTop)
        self.detail_info.setWordWrap(True)
        cols.addWidget(_card(self.detail_info, title="Agent information"), 1)

        res = QVBoxLayout(); res.setSpacing(8)
        res.addWidget(self._res_label("CPU usage"))
        self.detail_cpu = self._res_bar(COLORS["track"]); res.addWidget(self.detail_cpu)
        res.addWidget(self._res_label("Memory usage"))
        self.detail_mem = self._res_bar(COLORS["contain"]); res.addWidget(self.detail_mem)
        self.detail_net = QLabel("Network I/O\n  RX: —    TX: —")
        self.detail_net.setStyleSheet(f"font-family:{MONO}; font-size:11px; color:{COLORS['muted']};")
        res.addWidget(self.detail_net)
        self.detail_container = QLabel("Container: —")
        self.detail_container.setStyleSheet(f"font-family:{MONO}; font-size:11px; color:{COLORS['muted']};")
        res.addWidget(self.detail_container); res.addStretch()
        res_w = QWidget(); res_w.setLayout(res)
        cols.addWidget(_card(res_w, title="Container resources"), 1)

        self.detail_sec = QVBoxLayout(); self.detail_sec.setSpacing(7)
        for t in ("Read-only filesystem", "Seccomp profile active", "AppArmor enforced",
                  "Network isolated", "Capabilities dropped: ALL"):
            l = QLabel("✓  " + t)
            l.setStyleSheet(f"color:{COLORS['green']}; font-family:{MONO}; font-size:12px;")
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
        fg, bg = _PHASE_STYLE.get(phase.upper(), (COLORS["muted"], COLORS["surface_2"]))
        f = QFrame(); f.setStyleSheet(f"background:{bg}; border-radius:8px;")
        v = QVBoxLayout(f); v.setContentsMargins(12, 8, 12, 8); v.setSpacing(1)
        top = QLabel(phase.upper())
        top.setStyleSheet(f"color:{fg}; font-weight:700; font-size:11px; font-family:{MONO};")
        sub = QLabel(detail)
        sub.setStyleSheet(f"color:{COLORS['ink']}; font-size:11px; font-family:{MONO};")
        v.addWidget(top); v.addWidget(sub)
        return f

    def _clear_layout(self, layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                # takeAt() only detaches from the layout; the widget stays a child
                # with its old geometry and keeps painting until deleteLater() is
                # serviced. Reparenting first stops it drawing this frame, which is
                # what left old rows ghosting under the new ones on re-open.
                w.setParent(None)
                w.deleteLater()

    def _open_agent_detail(self, row: int, _col: int = 0) -> None:
        if 0 <= row < len(self._agents_cache):
            self.show_agent_detail(self._agents_cache[row])

    @staticmethod
    def _trust_rating(t) -> str:
        if not isinstance(t, (int, float)):
            return ""
        return (" (Excellent)" if t >= 90 else " (Good)" if t >= 70
                else " (Fair)" if t >= 40 else " (Low)")

    @staticmethod
    def _mandate_lines(mandate: dict | None, contract: dict) -> str:
        """Render the commissioned mandate — the goal DECIDE judges actions against.

        Falls back to the framework contract's mandate string when the agent has no
        commissioned mandate of its own.
        """
        if not mandate:
            return f"Mandate        {contract.get('mandate') or '— (not commissioned)'}"
        def fit(value: str, width: int = 26) -> str:
            # The info card is a narrow monospace column; anything longer wraps and
            # breaks the label/value alignment, so elide rather than let it reflow.
            return value if len(value) <= width else value[:width - 1] + "…"

        goal = fit(str(mandate.get("goal") or "—"))
        approved = fit(", ".join(mandate.get("approved_actions") or []) or "—")
        forbidden = fit(", ".join(mandate.get("forbidden_actions") or []) or "—")
        expires = str(mandate.get("expires_at") or "")[:16] or "—"
        return (f"Mandate        {goal}\n"
                f"  approved     {approved}\n"
                f"  forbidden    {forbidden}\n"
                f"  expires      {expires}")

    def show_agent_detail(self, agent: dict) -> None:
        aid = str(agent.get("agent_id", ""))
        self._detail_agent_id = aid
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
        contract = d.get("agent_contract") or {}
        if contract:
            fw = contract.get("framework") or fw

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
            f"Project        {contract.get('project_name') or '—'}\n"
            f"Agent role     {contract.get('role') or '—'}\n"
            f"Status         {status}\n"
            f"Trust score    {trust_txt}\n"
            f"Current phase  {d.get('current_phase') or '—'}\n"
            f"Registered     {str(d.get('registered_at', '') or '')[:19] or '—'}\n"
            f"Last seen      {str(d.get('last_seen', '') or '')[:19] or '—'}\n"
            f"Container ID   {str(cid)[:18]}\n"
            f"Capabilities   {', '.join(contract.get('capabilities') or []) or caps}\n"
            f"{self._mandate_lines(d.get('mandate'), contract)}")

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
                mark, color = ("✓", COLORS["green"]) if ok else ("✗", COLORS["red"])
                text = f"{mark}  {label}" + (f": {val}" if isinstance(val, str) else "")
                l = QLabel(text)
                l.setStyleSheet(f"color:{color}; font-family:monospace; font-size:12px;")
                self.detail_sec.addWidget(l)
        else:
            for t in ("Read-only filesystem", "Seccomp profile active", "AppArmor enforced",
                      "Network isolated", "Capabilities dropped: ALL"):
                l = QLabel("✓  " + t)
                l.setStyleSheet(f"color:{COLORS['green']}; font-family:{MONO}; font-size:12px;")
                self.detail_sec.addWidget(l)
        self.detail_sec.addStretch()

        # ── activity timeline (with timestamps) ──
        self._clear_layout(self.detail_timeline)
        tl = d.get("timeline") or []
        if tl:
            for e in tl[:8]:
                raw = str(e.get("time", ""))
                ts = raw[11:19] or raw[:19]
                ph = (e.get("phase") or "SYSTEM").upper()
                summ = e.get("summary") or e.get("event") or ""
                self.detail_timeline.addWidget(self._timeline_row(ph, f"{ts}   {summ}"))
        else:
            evs = [e for e in self._event_buffer
                   if name in e.get("agent", "") or (aid and aid[:8] in e.get("agent", ""))]
            if evs:
                for e in evs[:8]:
                    raw = str(e.get("time", "")); ts = raw[11:19] or raw
                    self.detail_timeline.addWidget(self._timeline_row(
                        e.get("phase") or "SYSTEM",
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
            fg, _bg = _STATUS_STYLE.get(st.upper(), (COLORS["muted"], COLORS["surface_2"]))
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
            f"font-family:{MONO}; font-size:12px; color:{COLORS['ink']};")
        self.hitl_approve_btn = QPushButton("✓  Approve once")
        self.hitl_approve_btn.setStyleSheet(
            f"background:{COLORS['green']}; color:#06180d; border:none; border-radius:8px;"
            "padding:9px 16px; font-weight:600;")
        self.hitl_approve_btn.clicked.connect(lambda: self._hitl_decide(True))
        self.hitl_deny_btn = QPushButton("✕  Deny + log"); self.hitl_deny_btn.setObjectName("danger")
        self.hitl_deny_btn.clicked.connect(lambda: self._hitl_decide(False))
        self.hitl_approve_btn.setEnabled(False); self.hitl_deny_btn.setEnabled(False)
        btns = QHBoxLayout(); btns.addWidget(self.hitl_approve_btn)
        btns.addWidget(self.hitl_deny_btn); btns.addStretch()
        btns_w = QWidget(); btns_w.setLayout(btns)
        # A decision is redeemed by the *next* attempt, because the process that
        # escalated has already exited. Saying so here is the difference between
        # "I approved it and nothing happened" and knowing to re-run the action.
        self.hitl_outcome = QLabel("")
        self.hitl_outcome.setWordWrap(True)
        self.hitl_outcome.setVisible(False)
        self.hitl_outcome.setStyleSheet(
            f"background:{COLORS['green_wash']}; color:{COLORS['ink']};"
            "border-radius:8px; padding:10px 12px; font-size:12px;")
        note = QLabel("Decisions are signed and written to the tamper-evident audit log.")
        note.setObjectName("pageSub")
        review_inner = QWidget(); rv = QVBoxLayout(review_inner)
        rv.setContentsMargins(0, 0, 0, 0); rv.setSpacing(12)
        rv.addWidget(self.hitl_detail, 1); rv.addWidget(btns_w)
        rv.addWidget(self.hitl_outcome); rv.addWidget(note)
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
            # Amber, not red: these are actions held for a decision, not blocked
            # ones. Colouring a queue of pending reviews as alarms trains the
            # operator to ignore the colour that should mean "something was denied".
            b.setStyleSheet(
                f"QPushButton{{text-align:left; background:{COLORS['amber_wash']};"
                f"border:1px solid #5a4522;"
                f"border-radius:10px; padding:10px; color:{COLORS['ink']};"
                "font-family:'JetBrains Mono','DejaVu Sans Mono',monospace; font-size:11px;}"
                f"QPushButton:checked{{border:2px solid {COLORS['amber']}; background:#3a2f16;}}")
            b.clicked.connect(lambda _=False, r=req: self._select_hitl(r))
            self.hitl_queue_box.addWidget(b)
        self.hitl_queue_box.addStretch()
        if self._hitl_selected_id not in self._hitl_ids:
            self._hitl_selected_id = None
            self.hitl_detail.setText("Select an item from the queue to review.")
            self.hitl_approve_btn.setEnabled(False); self.hitl_deny_btn.setEnabled(False)

    def _select_hitl(self, req: dict) -> None:
        self._hitl_selected_id = req.get("request_id")
        self.hitl_outcome.setVisible(False)
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
        operator = self._operator_name()
        self.app.client.hitl_decide(rid, approve, operator=operator)
        wash = COLORS["green_wash"] if approve else COLORS["amber_wash"]
        self.hitl_outcome.setStyleSheet(
            f"background:{wash}; color:{COLORS['ink']};"
            "border-radius:8px; padding:10px 12px; font-size:12px;")
        self.hitl_outcome.setText(
            f"Approved by {operator}  ·  {str(rid)[:8]}\nRe-issue the same action within 15 "
            "minutes and it will execute under this approval — once. A later attempt "
            "escalates again."
            if approve else
            f"Denied by {operator}  ·  {str(rid)[:8]}\nRe-issuing the same action within 15 "
            "minutes will be blocked under this decision rather than escalating again.")
        self.hitl_outcome.setVisible(True)
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
        # This page holds more than fits: nine quick actions, four parameterised
        # forms and a console. Laid out flat it overflowed the window, and a
        # QVBoxLayout with nowhere to go compresses its children *past* their
        # minimum — which is why the form labels and inputs were drawing on top of
        # each other and the run buttons were slivers. The forms scroll, and a
        # splitter lets the console be dragged as large as the operator wants.
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 24, 28, 24); lay.setSpacing(16)
        lay.addWidget(self._page_header("Commands", "Every SecureAgentNet CLI command, from the GUI"))

        upper = QWidget()
        upper_lay = QVBoxLayout(upper)
        upper_lay.setContentsMargins(0, 0, 0, 0); upper_lay.setSpacing(16)

        # Quick, no-argument actions. A single QHBoxLayout of nine buttons cannot
        # wrap, so its minimum width (~900px) became the minimum width of the whole
        # page — which is what pushed the second form column off the right edge on
        # a narrower window. A grid wraps instead.
        quick = QGridLayout(); quick.setSpacing(8)
        quick_actions = (("Doctor", ["doctor"]), ("List agents", ["agent", "list"]),
                         ("Contracts", ["agent", "contracts"]),
                         ("Audit log", ["view-logs"]), ("Metrics", ["metrics"]),
                         ("Security status", ["security", "status"]),
                         ("Containers", ["contain", "list"]),
                         ("MCP tools", ["mcp", "list"]),
                         ("Trust root", ["trust", "root"]))
        per_row = 5
        for i, (label, args) in enumerate(quick_actions):
            b = QPushButton(label); b.setObjectName("ghost")
            b.setMinimumHeight(38)
            b.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            b.clicked.connect(lambda _=False, a=args: self.console.run(a))
            quick.addWidget(b, i // per_row, i % per_row)
        for col in range(per_row):
            quick.setColumnStretch(col, 1)
        quick_w = QWidget(); quick_w.setLayout(quick)
        upper_lay.addWidget(_card(quick_w, title="Quick actions"))

        # parameterised action forms
        forms = QGridLayout(); forms.setSpacing(16)
        forms.setColumnStretch(0, 1); forms.setColumnStretch(1, 1)
        forms.addWidget(self._form_register(), 0, 0)
        forms.addWidget(self._form_commission(), 0, 1)
        forms.addWidget(self._form_run(), 1, 0)
        forms.addWidget(self._form_agent_controls(), 1, 1)
        forms_w = QWidget(); forms_w.setLayout(forms)
        upper_lay.addWidget(forms_w)
        upper_lay.addStretch()

        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setWidget(upper)
        self._commands_scroll = scroll
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setStyleSheet("QScrollArea{background:transparent; border:none;}")
        upper_lay.setContentsMargins(0, 0, 10, 0)   # room for the scrollbar

        self.console = SanConsole()
        console_card = _card(self.console, title="Console  ·  for anything the forms above don't cover")
        console_card.setMinimumHeight(170)

        split = QSplitter(Qt.Vertical)
        split.setChildrenCollapsible(False)
        split.setHandleWidth(10)
        split.addWidget(scroll)
        split.addWidget(console_card)
        # The forms are the page; the console is the escape hatch. It used to open
        # at nearly half the height, which made the page read as a terminal with
        # some forms attached rather than the other way round.
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 1)
        split.setSizes([680, 200])
        lay.addWidget(split, 1)
        return page

    def _form(self, title: str, fields: List[tuple], run_label: str,
              build_args: Callable[[dict], list],
              templates: List[tuple] | None = None,
              describe_field: bool = False) -> QWidget:
        inputs: dict[str, QWidget] = {}
        agent_combo: QComboBox | None = None
        dependents: list[QWidget] = []      # fields whose options follow the chosen agent
        rows = QVBoxLayout(); rows.setSpacing(9)
        for key, placeholder, kind in fields:
            lab = QLabel(placeholder); lab.setObjectName("fieldLabel")
            if kind == "combo":
                w = QComboBox(); w.addItems(["Custom", "LangChain", "CrewAI", "AutoGen"])
            elif kind == "action":
                # Editable so an action the agent does not hold yet can still be
                # typed, but the agent's own capabilities are offered first.
                w = QComboBox(); w.setEditable(True)
                w.lineEdit().setPlaceholderText(placeholder)
                w.setMinimumWidth(240)
                w.setProperty("action_field", True)
                dependents.append(w)
            elif kind == "resource":
                w = QComboBox(); w.setEditable(True)
                w.addItems(COMMON_RESOURCES)
                w.setCurrentText("")
                w.lineEdit().setPlaceholderText(placeholder)
                w.setMinimumWidth(240)
            elif kind == "actionlist":
                w = ActionPicker()
                w.setProperty("action_list", True)
                dependents.append(w)
            elif kind == "agent":
                w = QComboBox(); w.addItem("Select registered agent", "")
                for agent in self._agents_cache:
                    w.addItem(f"{agent.get('name', 'Unnamed')} · {str(agent.get('agent_id', ''))[:12]}", agent.get('agent_id', ''))
                w.setMinimumWidth(240)
                w.setProperty("agent_selector", True)
                self._agent_selectors.append(w)
                agent_combo = w
            elif kind == "multiline":
                w = QPlainTextEdit(); w.setPlaceholderText(placeholder); w.setMinimumHeight(80)
            else:
                w = QLineEdit(); w.setPlaceholderText(placeholder); w.setMinimumWidth(240)
            # A control with only a *preferred* height gets squeezed to nothing when
            # its parent runs out of room. Pin the floor so a row always renders.
            if not isinstance(w, (QPlainTextEdit, ActionPicker)):
                w.setMinimumHeight(36)
                w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            lab.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            inputs[key] = w
            # Label and field are one unit: grouping them in their own tight layout
            # keeps the caption attached to the control it names.
            field = QWidget()
            fl = QVBoxLayout(field)
            fl.setContentsMargins(0, 0, 0, 0); fl.setSpacing(5)
            fl.addWidget(lab); fl.addWidget(w)
            rows.addWidget(field)
        def _apply_template(values: dict) -> None:
            for key, val in values.items():
                w = inputs.get(key)
                if w is None:
                    continue
                if isinstance(w, ActionPicker):
                    w.set_value(val)
                elif isinstance(w, QComboBox):
                    w.setCurrentText(val)
                elif isinstance(w, QPlainTextEdit):
                    w.setPlainText(val)
                else:
                    w.setText(val)
            _refresh_preview()

        if describe_field:
            # The operator writes the job; the model proposes the structure; the
            # fields stay editable. Nothing is committed until they press the
            # form's own button, so the draft is a starting point, not a decision.
            drow = QVBoxLayout(); drow.setSpacing(6); drow.setContentsMargins(0, 0, 0, 0)
            dlab = QLabel("Describe the job in a sentence and let the local model draft it")
            dlab.setObjectName("fieldLabel")
            brief = QPlainTextEdit()
            brief.setPlaceholderText(
                "e.g. Read our support inbox each morning and reply to customers "
                "using public help articles. Never touch billing or passwords.")
            brief.setMinimumHeight(62); brief.setMaximumHeight(76)
            draft_btn = QPushButton("Draft mandate with local model")
            draft_btn.setObjectName("ghost"); draft_btn.setMinimumHeight(32)
            status = QLabel(""); status.setObjectName("pageSub"); status.setWordWrap(True)

            def _draft() -> None:
                text = brief.toPlainText().strip()
                if len(text.split()) < 4:
                    status.setText("Describe the job in a sentence first.")
                    return
                agent_id = agent_combo.currentData() if agent_combo else ""
                agent = next((a for a in self._agents_cache
                              if str(a.get("agent_id")) == str(agent_id)), None)
                draft_btn.setEnabled(False)
                status.setText("Asking the local model…")

                def _ok(draft) -> None:
                    _apply_template({
                        "goal": draft.goal,
                        "approve": ",".join(draft.approved_actions),
                        "forbid": ",".join(draft.forbidden_actions)})
                    notes = list(draft.warnings)
                    if draft.reasoning:
                        notes.insert(0, draft.reasoning)
                    status.setText("Drafted — review and edit before commissioning."
                                   + ("  ⚠ " + "  ⚠ ".join(notes) if notes else ""))
                    draft_btn.setEnabled(True)

                def _err(msg: str) -> None:
                    status.setText(f"Could not draft: {msg}  Nothing was changed.")
                    draft_btn.setEnabled(True)

                self._drafter = MandateDrafter(text, capability_actions(agent))
                self._drafter.drafted.connect(_ok)
                self._drafter.failed.connect(_err)
                self._drafter.start()

            draft_btn.clicked.connect(_draft)
            drow.addWidget(dlab); drow.addWidget(brief)
            drow.addWidget(draft_btn); drow.addWidget(status)
            dw = QWidget(); dw.setLayout(drow)
            rows.insertWidget(0, dw)

        if templates:
            # A blank form asks the operator to invent a mandate from nothing.
            # These fill one in, to be edited rather than composed.
            trow = QHBoxLayout(); trow.setSpacing(6); trow.setContentsMargins(0, 0, 0, 0)
            tlab = QLabel("Start from"); tlab.setObjectName("fieldLabel")
            trow.addWidget(tlab)
            for label, values in templates:
                tb = QPushButton(label); tb.setObjectName("ghost")
                tb.setMinimumHeight(28)
                tb.setCursor(Qt.PointingHandCursor)
                tb.clicked.connect(lambda _=False, v=values: _apply_template(v))
                trow.addWidget(tb)
            trow.addStretch()
            tw = QWidget(); tw.setLayout(trow)
            rows.insertWidget(0, tw)

        btn = QPushButton(run_label); btn.setObjectName("primary")
        btn.setMinimumHeight(38)
        btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # The exact command this form will run, shown before it runs. The GUI is a
        # view over the CLI, so showing the command keeps the two legible to each
        # other — and an operator can copy it into a terminal or a report.
        preview = QLabel(); preview.setObjectName("cmdPreview")
        preview.setWordWrap(True)
        preview.setTextInteractionFlags(Qt.TextSelectableByMouse)
        preview.setStyleSheet(
            f"color:{COLORS['dim']}; font-family:{MONO}; font-size:11px; "
            f"background:{COLORS['surface_2']}; border-radius:5px; padding:7px 9px;")

        def _values() -> dict:
            out = {}
            for k, w in inputs.items():
                if isinstance(w, ActionPicker):
                    out[k] = w.value()
                elif isinstance(w, QComboBox):
                    out[k] = w.currentData() if w.property("agent_selector") else w.currentText().strip()
                elif isinstance(w, QPlainTextEdit):
                    out[k] = w.toPlainText().strip()
                else:
                    out[k] = w.text().strip()
            return out

        def _refresh_preview():
            try:
                args = build_args(_values())
            except Exception:
                args = None
            if not args:
                preview.setText("san …   (fill the required fields)")
                return
            preview.setText("san " + " ".join(
                a if (a and " " not in a) else f'"{a}"' for a in args))

        def _sync_dependents():
            """Offer the selected agent's own actions in this form's action fields."""
            if agent_combo is None:
                # A form with no agent field (registering a new one) has no
                # capabilities to read, so offer the standard vocabulary.
                options = COMMON_ACTIONS
            else:
                agent_id = agent_combo.currentData()
                agent = next((a for a in self._agents_cache
                              if str(a.get("agent_id")) == str(agent_id)), None)
                options = capability_actions(agent) or (COMMON_ACTIONS if agent else [])
            for w in dependents:
                if isinstance(w, ActionPicker):
                    w.set_options(options)
                else:
                    current = w.currentText()
                    w.blockSignals(True)
                    w.clear(); w.addItems(options)
                    w.setCurrentText(current)
                    w.blockSignals(False)
            _refresh_preview()

        for w in inputs.values():
            if isinstance(w, ActionPicker):
                for sig in w.changed_signals():
                    sig.connect(_refresh_preview)
            elif isinstance(w, QComboBox):
                w.currentTextChanged.connect(_refresh_preview)
            elif isinstance(w, QPlainTextEdit):
                w.textChanged.connect(_refresh_preview)
            else:
                w.textChanged.connect(_refresh_preview)
        if agent_combo is not None:
            agent_combo.currentIndexChanged.connect(lambda _=0: _sync_dependents())
        _sync_dependents()

        def _go():
            args = build_args(_values())
            if args is None:
                self.console.run([])  # no-op guard
                return
            self._select("commands")
            self.console.run(args)
        btn.clicked.connect(_go)
        rows.addSpacing(4)
        rows.addWidget(preview)
        rows.addWidget(btn)
        rows.addStretch()
        wrap = QWidget(); wrap.setLayout(rows); wrap.setMinimumWidth(340)
        wrap.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        card = _card(wrap, title=title)
        if agent_combo is not None:
            self._form_agent_selectors[title] = agent_combo
        self._form_cards[title] = card
        return card

    def _form_register(self) -> QWidget:
        return self._form("Register agent",
                          [("name", "Agent name", "text"), ("type", "Framework", "combo"),
                           ("capabilities", "Actions it may take", "actionlist"),
                           ("description", "Description (optional)", "text")],
                          "Register",
                          lambda v: (["agent", "register", v["name"] or "new-agent", "--type", v["type"]]
                                    + (["--capabilities", v["capabilities"]] if v["capabilities"] else [])
                                    + (["--desc", v["description"]] if v["description"] else [])))

    def _form_commission(self) -> QWidget:
        return self._form("Commission (set mandate)",
                          [("agent", "Registered agent", "agent"),
                           ("goal", "What is this agent for?", "multiline"),
                           ("approve", "Actions it may take", "actionlist"),
                           ("forbid", "Actions it must never take", "actionlist"),
                           ("expires", "Expires in minutes (optional)", "text")],
                          "Commission",
                          lambda v: ["agent", "commission", v["agent"], "--goal", v["goal"]]
                                    + (["--approve-actions", v["approve"]] if v["approve"] else [])
                                    + (["--forbid-actions", v["forbid"]] if v["forbid"] else [])
                                    + (["--expires-minutes", v["expires"]] if v["expires"] else []),
                          templates=[
                              ("Research", {
                                  "goal": "Locate and summarise information for the "
                                          "commissioned research task",
                                  "approve": "search_files,read_file",
                                  "forbid": "send_email,write_file,execute_code"}),
                              ("Support inbox", {
                                  "goal": "Triage the support inbox and reply to customers "
                                          "using public knowledge-base information only",
                                  "approve": "read_email,send_email",
                                  "forbid": "read_credentials,transfer_funds,write_file"}),
                              ("Read-only diagnostics", {
                                  "goal": "Run read-only diagnostic commands and report on "
                                          "system state",
                                  "approve": "execute",
                                  "forbid": "write_file,send_email,delete_file"}),
                          ],
                          describe_field=True)

    def _form_agent_controls(self) -> QWidget:
        return self._form("Grant a capability",
                          [("agent", "Registered agent", "agent"),
                           ("capability", "Capability to grant", "action")],
                          "Add capability",
                          lambda v: ["agent", "add-cap", v["agent"], v["capability"]]
                                    if v["agent"] and v["capability"] else None)

    def _form_run(self) -> QWidget:
        return self._form("Run an action through ITCD",
                          [("agent", "Registered agent", "agent"),
                           ("action", "Action name", "action"),
                           ("resource", "Target resource", "resource"),
                           ("intent", "Why is the agent doing this?", "multiline"),
                           ("cmd", "Command to execute in the sandbox", "multiline")],
                          "Run",
                          lambda v: (["run", v["agent"], "--action", v["action"] or "execute",
                                      "--resource", v["resource"] or "shell",
                                      "--intent", v["intent"] or "Execute command", v["cmd"]]
                                     if v["agent"] and v["cmd"] else None),
                          templates=[
                              ("Read-only check", {
                                  "action": "execute", "resource": "shell",
                                  "intent": "Read-only diagnostic of the sandbox workspace",
                                  "cmd": "echo ok; ls -la /workspace; df -h"}),
                              ("Search workspace", {
                                  "action": "search_files", "resource": "local filesystem",
                                  "intent": "Locate files matching the commissioned search",
                                  "cmd": "grep -ril 'faustina' /workspace || echo 'no matches'"}),
                          ])


    # ── Settings ─────────────────────────────────────────────────
    def _page_settings(self) -> QWidget:
        page, lay = self._page_shell()
        lay.addWidget(self._page_header("Settings", "Operator identity and daemon connection"))

        # Every approval and denial made from this app is written to the audit
        # trail under this name, so it has to be a person.
        op_box = QVBoxLayout(); op_box.setSpacing(7)
        op_lab = QLabel("Your name, as recorded against decisions you make")
        op_lab.setObjectName("fieldLabel")
        self.operator_field = QLineEdit(self._operator_name())
        self.operator_field.setPlaceholderText("e.g. a.owusu")
        self.operator_field.setMinimumHeight(36)
        self.operator_field.setMaximumWidth(360)
        self.operator_saved = QLabel("")
        self.operator_saved.setObjectName("pageSub")

        def _save_operator() -> None:
            name = self.operator_field.text().strip()
            if not name:
                self.operator_field.setText(self._operator_name())
                return
            self._set_operator_name(name)
            self.operator_saved.setText(
                f"Approvals from this app will be recorded as '{name}'.")

        self.operator_field.editingFinished.connect(_save_operator)
        op_box.addWidget(op_lab)
        op_box.addWidget(self.operator_field)
        op_box.addWidget(self.operator_saved)
        hint = QLabel("Approvals released from the CLI carry their own "
                      "--operator value instead.")
        hint.setObjectName("pageSub")
        op_box.addWidget(hint)
        op_w = QWidget(); op_w.setLayout(op_box)
        lay.addWidget(_card(op_w, title="Operator identity"))

        info = QLabel(
            f"Daemon endpoint:  {self.app.client.base_url}\n"
            "Alerts stream:    live websocket\n"
            "The desktop app talks to the local daemon on this host. Start one with\n"
            "`secureagentnet-daemon` if the status reads offline."
        )
        info.setStyleSheet(f"color:{COLORS['muted']}; font-size:13px;")
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
        # A stale daemon is withholding verdicts, so the endpoint is not being
        # guarded — saying "Protected" here would be the reassuring lie the whole
        # fingerprint check exists to prevent.
        if status.get("stale"):
            self._set_state("threat", "Daemon needs restarting",
                            f"{status.get('stale_reason') or 'The enforcement surface changed'}. "
                            "Verdicts are withheld until it restarts — run `san daemon restart`.")
        elif self.badge._state != "threat":
            self._set_state("protected", "Protected",
                            "The ITCD pipeline is guarding every agent action.")
        seed = data.get("events_seed")
        if seed:
            self._seed_activity(seed)
        agents = data.get("agents") or []
        self._fill_agents_table(agents)
        self._update_phase_cards(status, agents)
        self._on_hitl_update(data.get("hitl") or [])

    def _seed_activity(self, events: list) -> None:
        """Backfill Recent Activity and the forensic buffer from the audit trail.

        Live alerts prepend to the same tables afterwards, so this only ever runs
        once per launch and only fills what the WebSocket could not have seen.
        """
        rows = events[:60]
        self.recent_table.setRowCount(0)
        for e in rows:
            ts = str(e.get("timestamp", ""))[:19]
            phase = str(e.get("phase", "")).upper()
            detail = e.get("detail") or e.get("event_type", "")
            r = self.recent_table.rowCount()
            self.recent_table.insertRow(r)
            for i, v in enumerate([ts[11:] or ts, phase, str(detail)]):
                item = QTableWidgetItem(v)
                if i == 1:
                    fg, _bg = _PHASE_STYLE.get(phase, (COLORS["muted"], ""))
                    item.setForeground(QColor(fg))
                self.recent_table.setItem(r, i, item)

        self._event_buffer = [{
            "time": str(e.get("timestamp", ""))[:19],
            "agent": (e.get("agent_id") or "—")[:18],
            "phase": str(e.get("phase", "")).upper(),
            "event": str(e.get("event_type", ""))[:48],
            "status": str(e.get("severity", "INFO")),
        } for e in events[:200]]
        if getattr(self, "forensic_table", None) is not None:
            self._render_forensic(self._event_buffer)

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
        for selector in getattr(self, "_agent_selectors", []):
            selected = selector.currentData()
            selector.blockSignals(True)
            selector.clear(); selector.addItem("Select registered agent", "")
            for agent in agents:
                selector.addItem(f"{agent.get('name', 'Unnamed')} · {str(agent.get('agent_id', ''))[:12]}", agent.get('agent_id', ''))
            if selected:
                idx = selector.findData(selected)
                if idx >= 0: selector.setCurrentIndex(idx)
            selector.blockSignals(False)
        self.agents_table.setRowCount(len(agents))
        for row, a in enumerate(agents):
            contract = a.get("agent_contract") or {}
            container = a.get("container") or {}
            live = container.get("live") or {}
            cpu = live.get("cpu_percent")
            memory = live.get("memory_mb")
            memory_limit = live.get("memory_limit_mb") or container.get("memory_limit_mb")
            cpu_text = f"{cpu:.1f}%" if isinstance(cpu, (int, float)) else "—"
            memory_text = (f"{memory:.0f}/{memory_limit:.0f} MB"
                           if isinstance(memory, (int, float)) and isinstance(memory_limit, (int, float))
                           else "—")
            self.agents_table.setItem(row, 0, QTableWidgetItem(str(a.get("name", ""))))
            self.agents_table.setItem(row, 1, QTableWidgetItem(str(contract.get("framework") or a.get("framework", "") or a.get("type", ""))))
            self.agents_table.setItem(row, 2, QTableWidgetItem(str(contract.get("project_name", "—"))))
            self.agents_table.setItem(row, 3, QTableWidgetItem(cpu_text))
            self.agents_table.setItem(row, 4, QTableWidgetItem(memory_text))
            self.agents_table.setItem(row, 5, QTableWidgetItem(str(container.get("status", "none"))))
            self.agents_table.setItem(row, 6, QTableWidgetItem(str(a.get("status", ""))))
            self.agents_table.setItem(row, 7, QTableWidgetItem(str(a.get("agent_id", ""))[:12]))

    def _load_discovered_agents(self) -> None:
        # Manual refresh button (Agents page) — registered inventory, with a
        # fall-back to the live discovery scan on older daemons.
        agents = self.app.client.registered_agents() or self.app.client.discovered_agents() or []
        contracts = {c.get("agent_id"): c for c in self.app.client.agent_contracts()}
        agents = [{**a, "agent_contract": contracts.get(a.get("agent_id"))}
                  for a in agents]
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
                fg, _bg = _PHASE_STYLE.get(phase, (COLORS["muted"], ""))
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
        fg, bg = _STATUS_STYLE.get(sev.upper(), (COLORS["blue"], COLORS["blue_wash"]))
        row = QLabel(text); row.setWordWrap(True)
        row.setStyleSheet(
            f"color:{fg}; background:{bg}; border-radius:8px; padding:8px 10px; font-size:12px;")
        self.sec_alerts_box.insertWidget(0, row)
        # Prune to the newest five, counting only alert rows. The trailing stretch
        # that keeps them packed to the top of the card is a spacer item, not a
        # widget — a plain count()-based loop would take it first and let the list
        # drift back to centre.
        rows = [i for i in range(self.sec_alerts_box.count())
                if self.sec_alerts_box.itemAt(i).widget() is not None]
        while len(rows) > 5:
            item = self.sec_alerts_box.takeAt(rows.pop())
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
