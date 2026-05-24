import click
from src.interfaces.cli.commands import (
    agent, run, forensics, security, contain,
    server, doctor, audit, config_cmd, metrics,
    version, init, evaluate,
)


@click.group()
@click.version_option(version="2.0.0", prog_name="secureagentnet", message="%(prog)s v%(version)s")
def cli():
    """SecureAgentNet — Zero-Trust Security Orchestration for Autonomous AI Agents

    A four-phase ITCD (Identify, Track, Contain, Decide) pipeline that provides
    cryptographic identity verification, containerized sandboxing, semantic
    security evaluation, and tamper-proof forensic auditing for multi-agent AI systems.
    """
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


if __name__ == "__main__":
    cli()
