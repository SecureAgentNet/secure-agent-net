import base64
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional


class SandboxConfig(BaseModel):
    image: str = Field(default="python:3.11-slim")
    mem_limit: str = Field(default="128m")
    cpu_quota: int = Field(default=50000)
    network_disabled: bool = Field(default=True)
    network_isolation_level: str = Field(default="strict")
    read_only: bool = Field(default=True)
    work_dir: str = Field(default="/workspace")
    tmpfs_size: str = Field(default="64m")
    drop_capabilities: List[str] = Field(default=["ALL"])
    timeout_seconds: int = Field(default=30)
    max_concurrent_containers: int = Field(default=10)
    max_containers_per_agent: int = Field(default=3)


class InjectedFile(BaseModel):
    path: str = Field(..., description="Destination path in the sandbox, e.g. /workspace/script.py")
    content_base64: str = Field(..., description="Base64-encoded file content")
    executable: bool = Field(default=False)

    def write_to(self, parent_dir: Path) -> Path:
        dest = parent_dir / self.path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        decoded = base64.b64decode(self.content_base64)
        dest.write_bytes(decoded)
        if self.executable:
            dest.chmod(0o755)
        return dest


class ExecutionRequest(BaseModel):
    command: str = Field(..., description="The command to run (e.g. 'python script.py')")
    args: List[str] = Field(default_factory=list, description="Command + args for exec form (Docker best practice)")
    environment_vars: Dict[str, str] = Field(default_factory=dict)
    files: List[InjectedFile] = Field(default_factory=list, description="Files to inject into workspace")


class ExecutionResult(BaseModel):
    sandbox_id: str
    exit_code: int
    stdout: str
    stderr: str
    execution_time_ms: int
    was_killed: bool = Field(default=False)
    oom_killed: bool = Field(default=False)
    resource_usage: Dict[str, Optional[float]] = Field(default_factory=dict)