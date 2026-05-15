import click
import asyncio
import json
from src.track.models import AgentActionRequest
from src.core.pipeline import ITCDPipeline


@click.group()
def cli():
    """SecureAgentNet: Zero-Trust Management CLI"""
    pass

@cli.command()
@click.option('--agent-id', default="agent-007", help='The ID of the agent.')
@click.option('--action', required=True, help='The abstract action (e.g., read_file).')
@click.option('--resource', required=True, help='The target resource path or ID.')
@click.option('--intent', required=True, help='The agents explanation of why it needs this.')
@click.option('--command', required=True, help='The actual bash command to execute in the sandbox.')
def run(agent_id: str, action: str, resource: str, intent: str, command: str):
    """Simulates an AI Agent attempting to run a command through the ITCD pipeline."""
    click.secho(f"\n🚀 Initiating Pipeline for {agent_id}", fg="blue", bold=True)
    click.secho("-" * 50, fg="blue")
    
    # Construct the tracking request
    request = AgentActionRequest(
        action_name=action,
        target_resource=resource,
        intent_summary=intent,
        payload={"command": command}
    )
    
    pipeline = ITCDPipeline()
    
    # Run pipeline async
    result = asyncio.run(pipeline.execute_agent_action(agent_id, request, command))
    
    click.secho("\n📊 Pipeline Result:", fg="yellow", bold=True)
    
    if result.get("status") == "blocked":
        click.secho(f"🛑 ACTION BLOCKED", fg="red", bold=True)
        click.secho(f"Evaluated By : {result.get('evaluated_by')}", fg="red")
        click.secho(f"Risk Score   : {result.get('risk_score')}", fg="red")
        click.secho(f"Reason       : {result.get('reason')}", fg="red")
    
    elif result.get("status") == "success":
        click.secho(f"✅ ACTION ALLOWED & EXECUTED", fg="green", bold=True)
        click.secho(f"Vault Receipt: {result.get('vault_receipt')}", fg="cyan")
        
        sandbox_data = result.get("data", {})
        click.secho(f"Sandbox ID   : {sandbox_data.get('sandbox_id')}", fg="green")
        click.secho(f"Exit Code    : {sandbox_data.get('exit_code')}", fg="green")
        click.secho(f"Time (ms)    : {sandbox_data.get('execution_time_ms')}", fg="green")
        
        stdout = sandbox_data.get('stdout', '').strip()
        stderr = sandbox_data.get('stderr', '').strip()
        
        if stdout:
            click.secho("\n--- STDOUT ---", fg="bright_white")
            click.echo(stdout)
        if stderr:
            click.secho("\n--- STDERR ---", fg="bright_red")
            click.echo(stderr)
            
    elif result.get("status") == "error":
        click.secho(f"⚠️ SYSTEM ERROR", fg="magenta", bold=True)
        click.secho(f"Details: {result.get('error_details')}", fg="magenta")
        
    click.echo("\n")

if __name__ == '__main__':
    cli()
