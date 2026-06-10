import asyncio
import json
import os
import sys
import time
import subprocess
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Any

# Silence noisy loggers in CLI mode
logging.getLogger("SecureAgentNet").setLevel(logging.WARNING)
logging.getLogger("SecureAgentNet.Track.Indexer").setLevel(logging.WARNING)
logging.getLogger("SecureAgentNet.Track").setLevel(logging.WARNING)
logging.getLogger("SecureAgentNet.Identify.Registry").setLevel(logging.WARNING)
logging.getLogger("SecureAgentNet.Identify.Discovery").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from src.core.pipeline import ITCDPipeline
from src.track.models import AgentActionRequest
from src.identify.identity_registry import IdentityRegistry
from src.identify.capability_profiler import CapabilityProfiler
from src.identify.rogue_detector import RogueDetector
from src.track.log_indexer import LogIndexer
from src.track.forensic_query import ForensicQueryEngine
from src.decide.circuit_breaker import CircuitBreaker
from src.contain.resource_manager import ContainerResourceManager
from src.core.config import get_settings
from src.utils.platform import detect_platform, Platform, docker_available, ollama_available, apparmor_available, redis_available

console = Console()

pipeline = ITCDPipeline()
rogue_detector = RogueDetector()
circuit_breaker = CircuitBreaker(failure_threshold=3, time_window_seconds=60, reset_timeout_seconds=120)
IdentityRegistry.initialize()
LogIndexer.initialize()


# ============================================================
#  UTILITY HELPERS
# ============================================================

def _print_table(title: str, columns: List[str], rows: List[List[str]], caption: str = ""):
    table = Table(title=title, box=box.ROUNDED, title_style="bold cyan", caption=caption)
    for col in columns:
        table.add_column(col, style="bold")
    for row in rows:
        table.add_row(*row)
    console.print(table)


def _print_json(data: Any):
    syntax = Syntax(json.dumps(data, indent=2, default=str), "json", theme="monokai")
    console.print(syntax)


def _print_success(msg: str):
    console.print(f"[bold green]✓[/] {msg}")


def _print_error(msg: str):
    console.print(f"[bold red]✗[/] {msg}")


def _print_warning(msg: str):
    console.print(f"[bold yellow]⚠[/] {msg}")


def _print_info(msg: str):
    console.print(f"[bold blue]ℹ[/] {msg}")


def _status_icon(status: str) -> str:
    icons = {"active": "[green]●[/]", "suspended": "[yellow]●[/]", "rogue": "[red]●[/]",
             "revoked": "[red]●[/]", "pending": "[dim]●[/]",
             "running": "[green]●[/]", "stopped": "[red]●[/]", "failed": "[red]●[/]",
             "creating": "[yellow]●[/]", "removed": "[dim]●[/]",
             "CLOSED": "[green]●[/]", "OPEN": "[red]●[/]",
             "approve": "[green]✓[/]", "deny": "[red]✗[/]", "escalate": "[yellow]▲[/]"}
    return icons.get(status.lower(), f"[dim]●[/]")


# ============================================================
#  INIT
# ============================================================

@click.command()
@click.option("--seed", is_flag=True, help="Seed with test data")
@click.option("--mode", default=None, type=click.Choice(["docker", "local", "minimal"]),
              help="Deployment mode (default from settings.yaml or docker)")
def init(seed: bool, mode: Optional[str]):
    """Initialize SecureAgentNet system"""
    if mode:
        import os
        env_path = Path.home() / ".secureagentnet" / ".env"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        existing = env_path.read_text() if env_path.exists() else ""
        if "DEPLOY_MODE" not in existing:
            env_path.write_text(existing + f"\nDEPLOY_MODE={mode}\n")
            _print_success(f"Deploy mode set to '{mode}' in {env_path}")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Initializing system...", total=None)
        IdentityRegistry.initialize()
        LogIndexer.initialize()
        time.sleep(0.3)

    console.print(Panel.fit(
        "[bold green]SecureAgentNet initialized successfully[/]\n\n"
        f"[dim]Agents:[/] {IdentityRegistry.get_total_count()} registered\n"
        f"[dim]Log system:[/] LogIndexer ready\n"
        f"[dim]Pipeline:[/] ITCD (Identify → Track → Decide → Contain)",
        title="[bold cyan]SecureAgentNet[/]",
        border_style="cyan"
    ))


# ============================================================
#  AGENT COMMANDS
# ============================================================

@click.group()
def agent():
    """Manage AI agents (register, list, update, revoke)"""
    pass


@agent.command()
@click.argument("name")
@click.option("--type", "agent_type", default="Custom", help="Agent framework type (LangChain, AutoGen, CrewAI)")
@click.option("--desc", "description", default="", help="Agent description")
@click.option("--public-key", "public_key", default="", help="Ed25519 public key")
@click.option("--capabilities", default="", help="Comma-separated capabilities")
def register(name: str, agent_type: str, description: str, public_key: str, capabilities: str):
    """Register a new AI agent"""
    cap_dict = {}
    if capabilities:
        for cap in capabilities.split(","):
            cap_dict[cap.strip()] = True

    agent_data = {
        "name": name, "type": agent_type, "description": description,
        "public_key": public_key, "capabilities": cap_dict,
        "metadata": {}, "created_by": "cli",
    }

    existing = IdentityRegistry.get_agent_by_name(name)
    if existing:
        _print_error(f"Agent '{name}' already exists (ID: {existing['agent_id']})")
        return

    result = IdentityRegistry.register_agent(agent_data)
    for cap in cap_dict:
        CapabilityProfiler.add_capability(result["agent_id"], cap)

    _print_success(f"Agent '{name}' registered with ID: [bold]{result['agent_id']}[/]")
    console.print(f"  Type: {agent_type}  |  Trust Score: 50.0  |  Status: active")


@agent.command()
@click.option("--status", default=None, help="Filter by status (active/suspended/rogue)")
@click.option("--type", "agent_type", default=None, help="Filter by type (LangChain/AutoGen/CrewAI)")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def list(status: Optional[str], agent_type: Optional[str], json_output: bool):
    """List registered agents"""
    agents = IdentityRegistry.list_agents(status=status, agent_type=agent_type)
    if json_output:
        _print_json(agents)
        return

    if not agents:
        _print_warning("No agents found")
        return

    rows = []
    for a in agents:
        anomaly = rogue_detector.compute_anomaly_score(a["agent_id"])
        rows.append([
            _status_icon(a["status"]),
            a["name"], a["type"], a["status"],
            f"{a['trust_score']:.1f}",
            f"{anomaly:.2f}",
            a["agent_id"][:8] + "...",
        ])

    _print_table(
        "Registered Agents",
        ["", "Name", "Type", "Status", "Trust", "Anomaly", "ID"],
        rows,
        caption=f"Total: {len(agents)} agents"
    )


@agent.command()
@click.argument("agent_id")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def get(agent_id: str, json_output: bool):
    """Get detailed agent information"""
    agent = IdentityRegistry.get_agent(agent_id)
    if not agent:
        agent = IdentityRegistry.get_agent_by_name(agent_id)

    if not agent:
        _print_error(f"Agent '{agent_id}' not found")
        return

    if json_output:
        _print_json(agent)
        return

    console.print(Panel.fit(
        f"[bold]Name:[/] {agent['name']}\n"
        f"[bold]ID:[/] {agent['agent_id']}\n"
        f"[bold]Type:[/] {agent['type']}\n"
        f"[bold]Status:[/] {_status_icon(agent['status'])} {agent['status']}\n"
        f"[bold]Trust Score:[/] {agent['trust_score']:.1f}/100\n"
        f"[bold]Anomaly Score:[/] {rogue_detector.compute_anomaly_score(agent['agent_id']):.2f}\n"
        f"[bold]Capabilities:[/] {', '.join(agent.get('capabilities', {}).keys()) or 'none'}\n"
        f"[bold]Registered:[/] {agent['registered_at']}\n"
        f"[bold]Last Seen:[/] {agent.get('last_seen', 'never')}",
        title=f"[bold cyan]Agent: {agent['name']}[/]",
        border_style="cyan"
    ))


@agent.command()
@click.argument("agent_id")
@click.option("--status", help="New status (active/suspended/revoked)")
@click.option("--trust", type=float, help="New trust score (0-100)")
@click.option("--name", help="New name")
def update(agent_id: str, status: Optional[str], trust: Optional[float], name: Optional[str]):
    """Update agent properties"""
    agent = IdentityRegistry.get_agent(agent_id) or IdentityRegistry.get_agent_by_name(agent_id)
    if not agent:
        _print_error(f"Agent '{agent_id}' not found")
        return

    updates = {}
    if status:
        updates["status"] = status
    if trust is not None:
        current = agent["trust_score"]
        delta = trust - current
        IdentityRegistry.update_trust_score(agent["agent_id"], delta)
        _print_success(f"Trust score updated: {current} → {trust}")
    if name:
        updates["name"] = name

    if updates:
        IdentityRegistry.update_agent(agent["agent_id"], updates)
        _print_success(f"Agent updated: {json.dumps(updates)}")
    else:
        _print_info("No changes specified")


@agent.command()
@click.argument("agent_id")
@click.confirmation_option(prompt="Revoke this agent?")
def revoke(agent_id: str):
    """Revoke an agent's access"""
    agent = IdentityRegistry.get_agent(agent_id) or IdentityRegistry.get_agent_by_name(agent_id)
    if not agent:
        _print_error(f"Agent '{agent_id}' not found")
        return
    IdentityRegistry.revoke_agent(agent["agent_id"])
    _print_success(f"Agent '{agent['name']}' revoked")


@agent.command()
@click.argument("agent_id")
@click.argument("capability")
def add_cap(agent_id: str, capability: str):
    """Add a capability to an agent"""
    agent = IdentityRegistry.get_agent(agent_id) or IdentityRegistry.get_agent_by_name(agent_id)
    if not agent:
        _print_error(f"Agent '{agent_id}' not found")
        return
    CapabilityProfiler.add_capability(agent["agent_id"], capability)
    _print_success(f"Capability '{capability}' added to '{agent['name']}'")


@agent.command()
@click.argument("agent_id")
def capabilities(agent_id: str):
    """List agent capabilities"""
    agent = IdentityRegistry.get_agent(agent_id) or IdentityRegistry.get_agent_by_name(agent_id)
    if not agent:
        _print_error(f"Agent '{agent_id}' not found")
        return
    caps = agent.get("capabilities", {})
    if not caps:
        _print_warning("No capabilities registered")
        return
    for cap, enabled in caps.items():
        icon = "[green]✓[/]" if enabled else "[red]✗[/]"
        console.print(f"  {icon} {cap}")


@agent.command()
@click.option("--scanner", "scanner_filter", default=None,
              type=click.Choice(["docker", "mcp", "process", "network", "filesystem"]),
              help="Run only a specific scanner")
@click.option("--register", "auto_register", is_flag=True, help="Auto-register discovered agents")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--no-dedup", "no_dedup", is_flag=True, help="Show all results without deduplication")
def discover(scanner_filter: Optional[str], auto_register: bool, json_output: bool, no_dedup: bool):
    """Scan system-wide for AI agents (Docker, MCP, processes, network, filesystem)

    Runs all 5 scanners in parallel and deduplicates results.
    """
    from src.identify.agent_discovery import AgentDiscoveryOrchestrator

    scanners = [scanner_filter] if scanner_filter else None

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="[bold cyan]Scanning system for AI agents...[/]", total=None)
        agents = AgentDiscoveryOrchestrator.discover_all(scanners=scanners, deduplicate=not no_dedup)

    if json_output:
        _print_json([a.to_dict() for a in agents])
        return

    if not agents:
        _print_warning("No AI agents discovered on this system")
        return

    source_colors = {
        "docker": "[blue]docker[/]", "mcp": "[green]mcp[/]",
        "process": "[yellow]process[/]", "network": "[magenta]network[/]",
        "filesystem": "[dim]filesystem[/]",
    }

    rows = []
    for a in agents:
        src = source_colors.get(a.source, a.source)
        fw = a.framework if a.framework != "unknown" else "—"
        detail = (
            f"port:{a.port}" if a.port else
            f"pid:{a.pid}" if a.pid else
            f"cid:{a.container_id}" if a.container_id else
            f"cfg:{Path(a.config_path).name}" if a.config_path else
            "—"
        )
        rows.append([src, a.name, fw, detail, a.status[:12]])

    _print_table(
        f"Discovered AI Agents ({len(agents)} found)",
        ["Source", "Name", "Framework", "Detail", "Status"],
        rows,
        caption=f"Scanners used: {', '.join(AgentDiscoveryOrchestrator.list_scanners())}"
    )

    if auto_register:
        registered = 0
        for a in agents:
            existing = IdentityRegistry.get_agent_by_name(a.name)
            if existing:
                continue
            try:
                agent_data = {
                    "name": a.name,
                    "type": a.framework,
                    "description": f"Discovered via {a.source} scanner",
                    "capabilities": {c: True for c in (a.capabilities or [])},
                    "metadata": {"discovered_by": a.source, "discovered_at": a.discovered_at},
                    "created_by": "auto-discover",
                }
                result = IdentityRegistry.register_agent(agent_data)
                for cap in a.capabilities or []:
                    CapabilityProfiler.add_capability(result["agent_id"], cap)
                registered += 1
                _print_success(f"Registered: {a.name} ({result['agent_id'][:8]}...)")
            except Exception as exc:
                _print_error(f"Failed to register {a.name}: {exc}")
        if registered:
            _print_success(f"Auto-registered {registered} new agent(s)")

        if registered:
            console.print(f"\n[dim]Use [bold]san agent list[/] to see all agents.[/]")


# ============================================================
#  RUN COMMAND
# ============================================================

@click.command()
@click.argument("agent_id")
@click.argument("command_str")
@click.option("--action", default="execute", help="Action name for the pipeline")
@click.option("--resource", default="shell", help="Target resource")
@click.option("--intent", default="Execute command", help="Intent summary")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def run(agent_id: str, command_str: str, action: str, resource: str, intent: str, json_output: bool):
    """Execute a command through the ITCD security pipeline

    AGENT_ID: Agent name or ID to run as
    COMMAND_STR: The command to execute in the sandbox
    """
    agent = IdentityRegistry.get_agent(agent_id) or IdentityRegistry.get_agent_by_name(agent_id)
    if agent:
        agent_id = agent["agent_id"]

    request = AgentActionRequest(
        action_name=action,
        target_resource=resource,
        intent_summary=intent,
        payload={"command": command_str}
    )

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="[bold cyan]ITCD Pipeline:[/] Identify → Track → Contain → Decide", total=None)
        result = asyncio.run(pipeline.execute_agent_action(agent_id, request, command_str))

    if json_output:
        _print_json(result)
        return

    status = result.get("status", "unknown")
    phase = result.get("phase", "")

    if status == "blocked":
        console.print(Panel.fit(
            f"[bold red]ACTION BLOCKED[/]\n\n"
            f"[bold]Phase:[/] {phase}\n"
            f"[bold]Evaluated By:[/] {result.get('evaluated_by', 'N/A')}\n"
            f"[bold]Risk Score:[/] [red]{result.get('risk_score', 'N/A')}[/]\n"
            f"[bold]Reason:[/] {result.get('reason', 'N/A')}",
            title="[red]🚫 Blocked[/]",
            border_style="red"
        ))

    elif status == "success":
        data = result.get("data", {})
        console.print(Panel.fit(
            f"[bold green]ACTION ALLOWED & EXECUTED[/]\n\n"
            f"[bold]Sandbox:[/] {data.get('sandbox_id', 'N/A')}\n"
            f"[bold]Exit Code:[/] {data.get('exit_code', 'N/A')}\n"
            f"[bold]Execution Time:[/] {data.get('execution_time_ms', 'N/A')}ms\n"
            f"[bold]Vault Receipt:[/] [dim]{result.get('vault_receipt', 'N/A')}[/]\n"
            f"[bold]Correlation ID:[/] [dim]{result.get('correlation_id', 'N/A')}[/]",
            title="[green]✅ Allowed[/]",
            border_style="green"
        ))

        stdout = data.get("stdout", "").strip()
        stderr = data.get("stderr", "").strip()
        if stdout:
            console.print("\n[bold]STDOUT:[/]")
            console.print(Syntax(stdout, "bash", theme="monokai"))
        if stderr:
            console.print("\n[bold red]STDERR:[/]")
            console.print(Syntax(stderr, "bash", theme="monokai"))

    elif status == "error":
        console.print(Panel.fit(
            f"[bold magenta]SYSTEM ERROR[/]\n\n{result.get('error_details', 'Unknown error')}",
            title="[magenta]⚠ Error[/]",
            border_style="magenta"
        ))


# ============================================================
#  EVALUATE COMMAND
# ============================================================

@click.command()
@click.argument("action_name")
@click.option("--agent", "agent_id", default="test-agent", help="Agent ID")
@click.option("--resource", default="/tmp/test", help="Target resource")
@click.option("--intent", default="Test evaluation", help="Intent summary")
@click.option("--payload", default="{}", help="JSON payload")
def evaluate(action_name: str, agent_id: str, resource: str, intent: str, payload: str):
    """Test the DECIDE phase evaluation without executing"""
    try:
        payload_dict = json.loads(payload)
    except json.JSONDecodeError:
        _print_error("Invalid JSON payload")
        return

    from src.decide.models import EvaluationRequest
    req = EvaluationRequest(
        agent_id=agent_id,
        action_name=action_name,
        target_resource=resource,
        intent_summary=intent,
        payload=payload_dict,
    )

    from src.decide import DecisionGateway
    gateway = DecisionGateway()
    result = gateway.evaluate_request(req)

    icon = "[green]✓[/]" if result.is_allowed else "[red]✗[/]"
    decision_str = "ALLOWED" if result.is_allowed else "DENIED"

    console.print(Panel.fit(
        f"[bold]Decision:[/] {'[green]' + decision_str + '[/]' if result.is_allowed else '[red]' + decision_str + '[/]'}\n"
        f"[bold]Risk Score:[/] {result.risk_score:.4f}\n"
        f"[bold]Evaluated By:[/] {result.evaluated_by}\n"
        f"[bold]Reason:[/] {result.reason}",
        title=f"{icon} Evaluation Result",
        border_style="green" if result.is_allowed else "red"
    ))


# ============================================================
#  FORENSICS COMMANDS
# ============================================================

@click.group()
def forensics():
    """Query audit logs and forensic data"""
    pass


@forensics.command()
@click.option("--agent", "agent_id", help="Filter by agent ID")
@click.option("--phase", help="Filter by phase (IDENTIFY/TRACK/CONTAIN/DECIDE)")
@click.option("--severity", help="Filter by severity (DEBUG/INFO/WARNING/ERROR/CRITICAL)")
@click.option("--search", "search_query", help="Full-text search")
@click.option("--limit", default=50, help="Max results")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def query(agent_id: Optional[str], phase: Optional[str], severity: Optional[str],
          search_query: Optional[str], limit: int, json_output: bool):
    """Query forensic event logs"""
    events = []
    if search_query:
        events = LogIndexer.search(search_query, limit)
    elif agent_id:
        events = LogIndexer.query_by_agent(agent_id)
    elif phase:
        from src.core.constants import PipelinePhase
        try:
            events = LogIndexer.query_by_phase(PipelinePhase(phase.upper()), limit)
        except ValueError:
            _print_error(f"Invalid phase: {phase}")
            return
    elif severity:
        from src.core.constants import EventSeverity
        try:
            events = LogIndexer.query_by_severity(EventSeverity(severity.upper()), limit)
        except ValueError:
            _print_error(f"Invalid severity: {severity}")
            return
    else:
        events = LogIndexer.get_recent(limit)

    if json_output:
        _print_json(events)
        return

    if not events:
        _print_warning("No events found")
        return

    rows = []
    for e in events:
        rows.append([
            e.get("timestamp", "")[11:19],
            e.get("agent_id", "?")[:8],
            e.get("event_type", ""),
            e.get("phase", ""),
            e.get("severity", ""),
            str(e.get("summary", ""))[:60],
        ])

    _print_table(
        "Forensic Events",
        ["Time", "Agent", "Event", "Phase", "Severity", "Summary"],
        rows,
        caption=f"Showing {len(events)} events"
    )


@forensics.command()
@click.argument("receipt")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def verify(receipt: str, json_output: bool):
    """Verify a Vault audit log entry using Transit HMAC

    RECEIPT: Vault receipt ID from a previous operation (e.g., vault-audit/agents/...-v1)
    """
    from src.track.vault_client import VaultAuditClient
    vault = VaultAuditClient()
    if not vault.client:
        _print_error("Vault client not available")
        return

    result = vault.verify_receipt(receipt)
    if json_output:
        _print_json(result)
        return

    if not result.get("valid"):
        _print_error("Log VERIFICATION FAILED — entry may have been tampered with")
        _print_info(f"Reason: {result.get('error', 'HMAC mismatch')}")
        return

    log = result.get("log", {})
    summary = log.get("summary", log.get("event_type", "unknown"))
    agent_id = log.get("agent_id", "?")
    ts = log.get("timestamp", "")
    console.print(Panel.fit(
        f"[bold green]✓ Log verified — HMAC matches[/]\n\n"
        f"[bold]Agent:[/] {agent_id}\n"
        f"[bold]Event:[/] {summary}\n"
        f"[bold]Time:[/] {ts}",
        title="[bold cyan]Log Integrity Verified[/]",
        border_style="green"
    ))


@forensics.command()
@click.option("--format", "fmt", default="json", type=click.Choice(["json", "csv"]))
def export(fmt: str):
    """Export forensic data"""
    data = ForensicQueryEngine.export_events(fmt)
    if fmt == "json":
        console.print(Syntax(data, "json", theme="monokai"))
    else:
        console.print(data)


@forensics.command()
@click.argument("agent_id")
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def timeline(agent_id: str, json_output: bool):
    """Show agent action timeline"""
    agent = IdentityRegistry.get_agent(agent_id) or IdentityRegistry.get_agent_by_name(agent_id)
    if agent:
        agent_id = agent["agent_id"]

    events = LogIndexer.query_by_agent(agent_id)
    if json_output:
        _print_json(events)
        return

    if not events:
        _print_warning(f"No events for agent '{agent_id}'")
        return

    rows = []
    for e in reversed(events[-30:]):
        rows.append([
            e.get("timestamp", "")[11:19],
            e.get("event_type", ""),
            e.get("phase", ""),
            e.get("severity", ""),
        ])

    _print_table(
        f"Timeline: {agent_id}",
        ["Time", "Event", "Phase", "Severity"],
        rows,
        caption=f"Last {len(rows)} of {len(events)} events"
    )


@forensics.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def summary(json_output: bool):
    """Show forensics system summary"""
    summary_data = ForensicQueryEngine.get_system_summary()
    if json_output:
        _print_json(summary_data)
        return

    phase_counts = LogIndexer.count_by_phase()
    severity_counts = LogIndexer.count_by_severity()

    console.print(Panel.fit(
        f"[bold]Total Events:[/] {summary_data['total_events']}\n"
        f"[bold]Active Agents:[/] {summary_data['active_agents']}\n"
        f"[bold]Blocked Actions:[/] [red]{summary_data['blocked_actions']}[/]\n"
        f"[bold]Approved Actions:[/] [green]{summary_data['approved_actions']}[/]\n"
        f"\n[bold]By Phase:[/]\n" +
        "\n".join(f"  {p}: {c}" for p, c in phase_counts.items()) +
        f"\n\n[bold]By Severity:[/]\n" +
        "\n".join(f"  {s}: {c}" for s, c in severity_counts.items()),
        title="[bold cyan]Forensics Summary[/]",
        border_style="cyan"
    ))


# ============================================================
#  SECURITY COMMANDS
# ============================================================

@click.group()
def security():
    """Security controls (kill-switch, circuit breaker, alerts)"""
    pass


@security.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def status(json_output: bool):
    """Show overall security status"""
    ks_status = pipeline.kill_switch.get_status()
    anomaly_scores = rogue_detector.get_all_anomaly_scores()

    if json_output:
        _print_json({"kill_switch": ks_status, "anomaly_scores": anomaly_scores})
        return

    ks_icon = "[red]ACTIVE[/]" if ks_status["active"] else "[green]ARMED[/]" if ks_status["armed"] else "[yellow]DISARMED[/]"
    console.print(Panel.fit(
        f"[bold]Kill-Switch:[/] {ks_icon}\n"
        f"[bold]Trigger Count:[/] {ks_status['trigger_count']}\n"
        f"[bold]Agent Denial Threshold:[/] {ks_status['denial_threshold']}\n"
        f"\n[bold]Suspicious Agents:[/]\n" +
        "\n".join(f"  {a}: {s:.2f}" for a, s in anomaly_scores.items() if s > 0.5) +
        f"\n\n[bold]Agents Tracked:[/] {len(anomaly_scores)}",
        title="[bold cyan]Security Status[/]",
        border_style="cyan"
    ))


@security.group()
def kill_switch():
    """Manage the kill-switch"""
    pass


@kill_switch.command()
def active():
    """Check if kill-switch is active"""
    if pipeline.kill_switch.is_active:
        _print_error("Kill-switch is ACTIVE — all operations halted")
    else:
        _print_success("Kill-switch is inactive")


@kill_switch.command()
@click.confirmation_option(prompt="Activate kill-switch? This halts ALL agent operations")
def activate():
    """Activate the kill-switch (halts all agents)"""
    pipeline.kill_switch.record_denial("cli-manual")
    _print_error("Kill-switch ACTIVATED — all agent operations halted")


@kill_switch.command()
@click.confirmation_option(prompt="Deactivate kill-switch?")
def deactivate():
    """Deactivate the kill-switch"""
    pipeline.kill_switch.deactivate("cli")
    _print_success("Kill-switch deactivated — operations may resume")


@security.group()
def circuit_breaker():
    """View circuit breaker status"""
    pass


@circuit_breaker.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def status(json_output: bool):
    """Show circuit breaker states"""
    if json_output:
        _print_json(circuit_breaker._state_store)
        return
    states = circuit_breaker._state_store
    if not states:
        _print_info("No agents tracked by circuit breaker")
        return
    rows = []
    for aid, state in states.items():
        rows.append([
            _status_icon(state["state"]),
            aid[:12],
            state["state"],
            str(len(state["failures"])),
        ])
    _print_table("Circuit Breaker States", ["", "Agent", "State", "Failures"], rows)


@security.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def alerts(json_output: bool):
    """Show recent security alerts"""
    events = LogIndexer.get_recent(100)
    alerts_list = [e for e in events if e.get("severity") in ("WARNING", "ERROR", "CRITICAL")]

    if json_output:
        _print_json(alerts_list)
        return

    if not alerts_list:
        _print_success("No security alerts")
        return

    rows = []
    for a in alerts_list[:30]:
        rows.append([
            a.get("timestamp", "")[11:19],
            _status_icon(a.get("severity", "")),
            a.get("severity", ""),
            a.get("event_type", ""),
            a.get("agent_id", "?")[:8],
        ])
    _print_table("Security Alerts", ["Time", "", "Severity", "Event", "Agent"], rows)


# ============================================================
#  CONTAIN COMMANDS
# ============================================================

@click.group()
def contain():
    """Manage execution containers"""
    pass


@contain.command()
@click.argument("agent_id")
@click.option("--image", default="python:3.11-slim", help="Docker image")
@click.option("--cpu", default=1.0, help="CPU limit")
@click.option("--memory", default=512, help="Memory limit in MB")
def provision(agent_id: str, image: str, cpu: float, memory: int):
    """Provision a sandbox container for an agent"""
    agent = IdentityRegistry.get_agent(agent_id) or IdentityRegistry.get_agent_by_name(agent_id)
    if agent:
        agent_id = agent["agent_id"]

    from src.contain.resource_manager import ContainerResourceManager, ResourceQuota
    import uuid
    container_id = f"sandbox-{uuid.uuid4().hex[:8]}"
    quota = ResourceQuota(cpu_limit=cpu, memory_limit_mb=memory)
    ContainerResourceManager.register_container(container_id, agent_id, quota)
    ContainerResourceManager.update_status(container_id, "running")

    console.print(Panel.fit(
        f"[bold]Container ID:[/] {container_id}\n"
        f"[bold]Agent:[/] {agent_id}\n"
        f"[bold]Image:[/] {image}\n"
        f"[bold]CPU:[/] {cpu} core(s)\n"
        f"[bold]Memory:[/] {memory}MB\n"
        f"[bold]Status:[/] [green]running[/]",
        title="[bold cyan]Container Provisioned[/]",
        border_style="cyan"
    ))


@contain.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def list(json_output: bool):
    """List active containers"""
    from src.contain.resource_manager import ContainerResourceManager
    containers = ContainerResourceManager._containers

    if json_output:
        _print_json(containers)
        return

    if not containers:
        _print_info("No containers running")
        return

    rows = []
    for cid, c in containers.items():
        rows.append([
            _status_icon(c.get("status", "unknown")),
            cid[:16],
            c.get("agent_id", "?")[:8],
            c.get("status", "unknown"),
            f"{c.get('quota', {}).get('cpu_limit', 0)}",
            f"{c.get('quota', {}).get('memory_limit_mb', 0)}MB",
        ])
    _print_table("Containers", ["", "ID", "Agent", "Status", "CPU", "Memory"], rows)


@contain.command()
@click.argument("container_id")
@click.confirmation_option(prompt="Stop and remove this container?")
def stop(container_id: str):
    """Stop and remove a container"""
    from src.contain.resource_manager import ContainerResourceManager
    ContainerResourceManager.update_status(container_id, "stopped")
    ContainerResourceManager.remove_container(container_id)
    _print_success(f"Container {container_id} stopped and removed")


# ============================================================
#  DOCTOR COMMAND
# ============================================================

@click.command()
@click.option("--deploy-mode", default=None, help="Override deployment mode: docker|local|minimal")
def doctor(deploy_mode: Optional[str]):
    """System health check and diagnostics"""
    checks = []
    all_pass = True
    platform = detect_platform()

    settings = get_settings()
    mode = deploy_mode or settings.deploy_mode

    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    checks.append(("[green]✓[/]" if sys.version_info >= (3, 10) else "[red]✗[/]", f"Python {py_ver} (3.10+ required)", sys.version_info >= (3, 10)))
    if sys.version_info < (3, 10): all_pass = False

    checks.append(("[green]✓[/]", f"Platform: {platform.value.capitalize()}", True))
    checks.append(("[green]✓[/]", f"Deploy Mode: {mode}", True))

    try:
        ir_count = IdentityRegistry.get_total_count()
        ir_ok = ir_count >= 0
        checks.append(("[green]✓[/]" if ir_ok else "[red]✗[/]", f"Identity Registry: {ir_count} agents registered", ir_ok))
    except Exception:
        ir_ok = False
        checks.append(("[red]✗[/]", "Identity Registry: failed to load", False))
    if not ir_ok: all_pass = False

    try:
        li_count = len(LogIndexer._events)
        li_ok = li_count >= 0
        checks.append(("[green]✓[/]" if li_ok else "[red]✗[/]", f"Log Indexer: {li_count} events indexed", li_ok))
    except Exception:
        li_ok = False
        checks.append(("[red]✗[/]", "Log Indexer: failed to load", False))
    if not li_ok: all_pass = False

    docker_ok = docker_available()
    docker_ver = "not found"
    if docker_ok:
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5)
            docker_ver = result.stdout.strip() if result.returncode == 0 else "not found"
        except Exception:
            docker_ver = "not found"
    icon = "[green]✓[/]" if docker_ok else "[yellow]⚠[/]" if mode != "docker" else "[red]✗[/]"
    checks.append((icon, f"Docker: {docker_ver}", docker_ok or mode != "docker"))
    if mode == "docker" and not docker_ok:
        all_pass = False
        _print_warning(f"Docker required in '{mode}' mode — container sandboxing disabled")
    elif not docker_ok:
        _print_info(f"Docker not available — container sandboxing disabled ({mode} mode)")

    ollama_ok = ollama_available()
    ollama_ver = "not found"
    if ollama_ok:
        try:
            result = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=5)
            ollama_ver = result.stdout.strip() if result.returncode == 0 else "not found"
        except Exception:
            ollama_ver = "not found"
    icon = "[green]✓[/]" if ollama_ok else "[yellow]⚠[/]" if mode != "docker" else "[red]✗[/]"
    checks.append((icon, f"Ollama: {ollama_ver}", ollama_ok or mode != "docker"))
    if mode == "docker" and not ollama_ok:
        all_pass = False
        _print_warning("Ollama required in 'docker' mode — LLM evaluation disabled")
    elif not ollama_ok:
        _print_info("Ollama not available — semantic LLM evaluation disabled")

    redis_ok = False
    try:
        from src.utils.redis_client import get_redis
        r = get_redis()
        redis_ok = r is not None
    except Exception:
        pass
    icon = "[green]✓[/]" if redis_ok else "[yellow]⚠[/]" if mode != "docker" else "[red]✗[/]"
    checks.append((icon, f"Redis: {'connected' if redis_ok else 'not available'}", redis_ok or mode != "docker"))
    if mode == "docker" and not redis_ok:
        all_pass = False
        _print_warning("Redis required in 'docker' mode")
    elif not redis_ok:
        _print_info("Redis not available — rate limiting uses in-memory fallback")

    if platform == Platform.LINUX:
        aa_ok = apparmor_available()
        icon = "[green]✓[/]" if aa_ok else "[dim]—[/]"
        checks.append((icon, f"AppArmor: {'available' if aa_ok else 'not detected (optional)'}", True))

    checks.append(("[green]✓[/]", f"Environment: {settings.environment}", True))

    console.print("\n[bold cyan]SecureAgentNet System Health[/]")
    console.print("=" * 50)

    for icon, msg, _ in checks:
        console.print(f"  {icon} {msg}")

    console.print("")
    if all_pass:
        console.print(Panel.fit("[bold green]All checks passed![/]", border_style="green"))
    else:
        console.print(Panel.fit(
            "[bold yellow]Some issues detected — system may have limited functionality[/]",
            border_style="yellow"
        ))

    console.print(f"\n[dim]CLI version: 2.0.0 | Pipeline: ITCD | PID: {os.getpid()} | Mode: {mode}[/]")


# ============================================================
#  AUDIT COMMAND
# ============================================================

@click.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def audit(json_output: bool):
    """Run a full system security audit"""
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="Running security audit...", total=None)
        time.sleep(0.5)

    summary = ForensicQueryEngine.get_system_summary()
    anomaly_scores = rogue_detector.get_all_anomaly_scores()
    phase_counts = LogIndexer.count_by_phase()
    severity_counts = LogIndexer.count_by_severity()
    agents = IdentityRegistry.list_agents()

    suspicious_agents = [a for a in agents if a.get("status") in ("rogue", "suspended")]
    high_anomaly = [aid for aid, score in anomaly_scores.items() if score > 0.5]

    audit_result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "system": summary,
        "security": {
            "kill_switch_active": pipeline.kill_switch.is_active,
            "kill_switch_armed": pipeline.kill_switch.is_armed,
            "suspicious_agents": len(suspicious_agents),
            "high_anomaly_agents": len(high_anomaly),
        },
        "agents": {
            "total": len(agents),
            "suspicious": [
                {"id": a["agent_id"], "name": a["name"], "status": a["status"]}
                for a in suspicious_agents
            ],
            "high_anomaly_ids": high_anomaly[:10],
        },
        "events": {
            "phases": phase_counts,
            "severities": severity_counts,
        },
    }

    if json_output:
        _print_json(audit_result)
        return

    console.print(Panel.fit(
        f"[bold cyan]SecureAgentNet Audit Report[/]\n"
        f"[dim]{audit_result['timestamp']}[/]\n\n"
        f"[bold]System Health:[/]\n"
        f"  Total Events: {summary['total_events']}\n"
        f"  Active Agents: {summary['active_agents']} / {summary['total_agents']}\n"
        f"  Blocked/Actions: {summary['blocked_actions']} denied, {summary['approved_actions']} approved\n\n"
        f"[bold]Security:[/]\n"
        f"  Kill-Switch: {'[red]ACTIVE[/]' if audit_result['security']['kill_switch_active'] else '[green]INACTIVE[/]'}\n"
        f"  Suspicious Agents: {audit_result['security']['suspicious_agents']}\n"
        f"  High Anomaly Agents: {audit_result['security']['high_anomaly_agents']}\n\n"
        f"[bold]Events by Phase:[/]\n" +
        "\n".join(f"  {p}: {c}" for p, c in phase_counts.items()) +
        f"\n\n[bold]Events by Severity:[/]\n" +
        "\n".join(f"  {s}: {c}" for s, c in severity_counts.items()),
        title="[bold cyan]Audit Report[/]",
        border_style="cyan"
    ))

    if suspicious_agents:
        _print_warning(f"Suspicious agents detected: {len(suspicious_agents)}")
        for a in suspicious_agents:
            console.print(f"  [red]●[/] {a['name']} ({a['agent_id'][:8]}...) — status: {a['status']}")


# ============================================================
#  CONFIG COMMANDS
# ============================================================

@click.group()
def config_cmd():
    """View and manage configuration"""
    pass


@config_cmd.command()
def show():
    """Show current configuration"""
    settings = get_settings()
    config_dict = {
        "environment": settings.environment,
        "deploy_mode": settings.deploy_mode,
        "database_url": settings.database_url.split("@")[-1] if "@" in settings.database_url else settings.database_url,
        "vault_addr": settings.vault_addr,
        "ollama_model": settings.ollama_model,
        "ollama_api_url": settings.ollama_api_url,
        "container_cpu_limit": settings.container_cpu_limit,
        "container_memory_limit": settings.container_memory_limit,
        "jwt_expiration": settings.jwt_expiration,
        "kill_switch_threshold": settings.kill_switch_threshold,
        "circuit_breaker_timeout": settings.circuit_breaker_timeout,
        "mcp_port": settings.mcp_port,
    }
    rows = [[k, str(v)] for k, v in config_dict.items()]
    _print_table("Configuration", ["Key", "Value"], rows)


@config_cmd.command()
@click.argument("key")
@click.argument("value")
def set(key: str, value: str):
    """Set a configuration value (requires restart)"""
    _print_info(f"Configuration changes require editing .env or restarting the server")
    _print_info(f"Would set: {key} = {value}")


# ============================================================
#  METRICS COMMAND
# ============================================================

@click.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
@click.option("--watch", is_flag=True, help="Watch mode (refresh every 2s)")
def metrics(json_output: bool, watch: bool):
    """Display real-time system metrics"""
    if watch:
        try:
            while True:
                os.system("clear")
                _display_metrics(json_output)
                time.sleep(2)
        except KeyboardInterrupt:
            pass
    else:
        _display_metrics(json_output)


def _display_metrics(json_output: bool):
    summary = ForensicQueryEngine.get_system_summary()
    containers_info = ContainerResourceManager.get_resource_usage_summary()
    anomaly_scores = rogue_detector.get_all_anomaly_scores()

    if json_output:
        _print_json({
            "summary": summary,
            "containers": containers_info,
            "anomaly_scores": anomaly_scores,
        })
        return

    phase_counts = LogIndexer.count_by_phase()

    console.print("[bold cyan]SecureAgentNet — Live Metrics[/]")
    console.print(f"[dim]{datetime.now(timezone.utc).isoformat()}[/]")
    console.print("")

    # Summary panel
    console.print(Panel.fit(
        f"[bold]Active Agents:[/] [green]{summary['active_agents']}[/]  "
        f"[bold]Total Events:[/] {summary['total_events']}  "
        f"[bold]Blocked:[/] [red]{summary['blocked_actions']}[/]  "
        f"[bold]Approved:[/] [green]{summary['approved_actions']}[/]",
        border_style="cyan"
    ))

    # Pipeline phase table
    rows = [[p, str(c)] for p, c in sorted(phase_counts.items())]
    if rows:
        _print_table("Pipeline Activity", ["Phase", "Events"], rows)

    # Container summary
    console.print(f"\n[bold]Containers:[/] {containers_info['total_containers']} running  "
                  f"Memory: {containers_info['total_memory_mb']}MB  "
                  f"CPU: {containers_info['total_cpu_cores']} cores")

    # Top anomalies
    suspicious = [(a, s) for a, s in anomaly_scores.items() if s > 0.3]
    if suspicious:
        suspicious.sort(key=lambda x: x[1], reverse=True)
        console.print("\n[bold yellow]Top Anomalies:[/]")
        for aid, score in suspicious[:5]:
            console.print(f"  {aid[:12]}... — score: {score:.2f}")


# ============================================================
#  VERSION COMMAND
# ============================================================

@click.command()
@click.option("--json", "json_output", is_flag=True, help="Output as JSON")
def version(json_output: bool):
    """Show version information"""
    info = {
        "name": "SecureAgentNet",
        "version": "2.0.0",
        "phases": ["IDENTIFY", "TRACK", "CONTAIN", "DECIDE"],
        "python": sys.version,
        "platform": sys.platform,
    }
    if json_output:
        _print_json(info)
        return

    console.print(Panel.fit(
        f"[bold cyan]SecureAgentNet[/] [white]v{info['version']}[/]\n\n"
        f"[bold]Pipeline:[/] {' → '.join(info['phases'])}\n"
        f"[bold]Python:[/] {sys.version.split()[0]}\n"
        f"[bold]Platform:[/] {sys.platform}\n"
        f"[dim]Zero-Trust Security Orchestration for Autonomous AI Agents[/]",
        title="[bold cyan]📋 Version Info[/]",
        border_style="cyan"
    ))


# ============================================================
#  SERVER COMMANDS
# ============================================================

@click.group()
def server():
    """Manage the optional web dashboard server"""
    pass


@server.command()
@click.option("--port", default=5000, help="Server port")
@click.option("--host", default="0.0.0.0", help="Server host")
@click.option("--daemon", is_flag=True, help="Run in background")
def start(port: int, host: str, daemon: bool):
    """Start the web dashboard server"""
    from pathlib import Path

    _print_info(f"Starting server on {host}:{port}...")
    if daemon:
        _print_info("Running in background (use 'server stop' to terminate)")
    console.print(f"  Dashboard: [bold]http://{host}:{port}/dashboard[/]")
    console.print(f"  API:       [bold]http://{host}:{port}/health[/]")

    cmd = [
        sys.executable, "-m", "uvicorn",
        "src.main:app",
        "--host", host,
        "--port", str(port),
        "--log-level", "info",
    ]

    if daemon:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pid_dir = Path.home() / ".secureagentnet"
        pid_dir.mkdir(parents=True, exist_ok=True)
        (pid_dir / "server.pid").write_text(str(proc.pid))
    else:
        os.execvp(sys.executable, [sys.executable, "-m", "uvicorn",
            "src.main:app",
            "--host", host,
            "--port", str(port),
            "--log-level", "info",
        ])


@server.command()
def stop():
    """Stop the web dashboard server"""
    from pathlib import Path
    pid_file = Path.home() / ".secureagentnet" / "server.pid"
    if not pid_file.exists():
        _print_info("No server PID file found")
        return
    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, 15)  # SIGTERM
        pid_file.unlink(missing_ok=True)
        _print_success(f"Server stopped (PID: {pid})")
    except ProcessLookupError:
        _print_info("Server not running (stale PID file)")
        pid_file.unlink(missing_ok=True)


@server.command()
def status():
    """Check if server is running"""
    from pathlib import Path
    pid_file = Path.home() / ".secureagentnet" / "server.pid"
    if not pid_file.exists():
        _print_info("Server not running (no PID file)")
        return
    pid = int(pid_file.read_text().strip())
    try:
        os.kill(pid, 0)  # Test if process exists
        _print_success(f"Server running (PID: {pid})")
    except ProcessLookupError:
        _print_info("Server not running (stale PID file)")
        pid_file.unlink(missing_ok=True)
