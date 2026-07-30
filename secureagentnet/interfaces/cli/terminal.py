import sys
import os
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.text import Text
from secureagentnet.interfaces.cli.commands import (
    agent, run, forensics, security, contain,
    server, doctor, audit, config_cmd, metrics,
    version, init, evaluate, mcp, daemon, desktop,
    view_logs, cloud, trust, host,
)

console = Console()

BANNER = r"""
   ██████╗  █████╗ ███╗   ██╗
  ██╔════╝ ██╔══██╗████╗  ██║
  ╚█████╗  ███████║██╔██╗ ██║
   ╚═══██╗ ██╔══██║██║╚██╗██║
  ██████╔╝ ██║  ██║██║ ╚████║
  ╚═════╝  ╚═╝  ╚═╝╚═╝  ╚═══╝
"""

TAGLINE = "[bold cyan]Zero-Trust Security Gateway for Autonomous AI Agents[/]"
PIPELINE = "[dim]Pipeline:[/] [cyan]IDENTIFY[/] → [yellow]TRACK[/] → [green]CONTAIN[/] → [magenta]DECIDE[/]"


@click.group(invoke_without_command=True)
@click.version_option(version="2.0.0", prog_name="secureagentnet", message="%(prog)s v%(version)s")
@click.pass_context
def cli(ctx):
    """SecureAgentNet — Zero-Trust Security Orchestration for Autonomous AI Agents

    A four-phase ITCD (Identify, Track, Contain, Decide) pipeline that provides
    cryptographic identity verification, containerized sandboxing, semantic
    security evaluation, and tamper-proof forensic auditing for multi-agent AI systems.
    """
    if ctx.invoked_subcommand is None:
        _show_banner()

        console.print(Align.center(TAGLINE))
        console.print(Align.center(PIPELINE))
        console.print()

        _show_quick_status()
        console.print()

        console.print(ctx.get_help())

        # Show start command hint separately after help so it doesn't get lost
        console.print(
            "\n[dim]Tip:[/] [cyan]san[/] is also available as a shortcut. "
            "Get started: [bold]secureagentnet agent register[/][dim] <name> --capabilities execute_code,read_file[/]"
        )

        ctx.exit()


def _show_banner():
    banner = Text(BANNER, style="bold cyan")
    console.print(Align.center(banner))


def _show_quick_status():
    try:
        from secureagentnet.core.config import get_settings
        from secureagentnet.identify.identity_registry import IdentityRegistry
        from secureagentnet.track.log_indexer import LogIndexer
        from secureagentnet.utils.platform import docker_available, ollama_available

        settings = get_settings()
        IdentityRegistry.initialize()
        LogIndexer.initialize()

        agent_count = IdentityRegistry.get_total_count()
        active_count = IdentityRegistry.get_active_count()
        event_count = len(LogIndexer._events)
        docker_ok = docker_available()
        ollama_ok = ollama_available()

        table = Table.grid(padding=(0, 2))
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")
        table.add_column(justify="center")

        table.add_row(
            f"[bold cyan]{agent_count}[/] agents",
            f"[bold green]{active_count}[/] active",
            f"[bold yellow]{event_count}[/] events",
            f"[bold]{'[green]Docker[/]' if docker_ok else '[dim]Docker[/]'}[/]",
            f"[bold]{'[green]Ollama[/]' if ollama_ok else '[dim]Ollama[/]'}[/]",
        )

        console.print(Align.center(table))
    except Exception:
        pass


cli.add_command(init)
cli.add_command(agent)
cli.add_command(run)
cli.add_command(evaluate)
cli.add_command(forensics)
cli.add_command(security)
cli.add_command(contain)
cli.add_command(server)
cli.add_command(doctor)
cli.add_command(audit)
cli.add_command(config_cmd)
cli.add_command(metrics)
cli.add_command(version)
cli.add_command(mcp)
cli.add_command(trust)
cli.add_command(daemon)
cli.add_command(desktop)
cli.add_command(view_logs)
cli.add_command(cloud)
cli.add_command(host)


if __name__ == "__main__":
    cli()
