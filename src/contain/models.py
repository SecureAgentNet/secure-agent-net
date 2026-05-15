from pydantic import BaseModel, Field
from typing import Optional, List, Dict
import uuid


class SandboxConfig(BaseModel):
    """Configuration for the isolated execution environment."""
    image: str = Field(default="python:3.11-slim", description="The Docker image to use as the base sandbox.")
    mem_limit: str = Field(default="128m", description="Maximum memory the container can use.")
    cpu_quota: int = Field(default=50000, description="CPU quota (50000 = 0.5 CPU core).")
    network_disabled: bool = Field(default=True, description="If True, container has no network access.")
    read_only: bool = Field(default=True, description="Mount the root filesystem as read-only.")
    work_dir: str = Field(default="/workspace", description="The working directory inside the sandbox.")
    drop_capabilities: List[str] = Field(
        default=["ALL"],
        description="Linux capabilities to drop (default: drop all)."
    )


class ExecutionRequest(BaseModel):
    """The request to execute a specific command or script inside the sandbox."""
    command: str = Field(..., description="The command to run (e.g., 'python script.py').")
    environment_vars: Dict[str, str] = Field(default_factory=dict, description="Safe env vars to inject.")
    # In a real scenario, you'd also pass file contents to mount into the workspace.


class ExecutionResult(BaseModel):
    """The result of the sandbox execution."""
    sandbox_id: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: int
    was_killed: bool = Field(default=False, description="True if killed due to timeout or resource exhaustion.")
