"""SecureAgentNet framework adapters.

Wrap an existing agent framework's tools so every invocation is governed by the
ITCD pipeline. Framework-specific helpers live in submodules and lazily import
their framework:

    from src.integrations.langchain import secure_tool, secure_tools
    from src.integrations.crewai import secure_tool
    from src.integrations.autogen import secure_function, register_secured

The framework-agnostic core is available directly:

    from src.integrations import secure_callable, LocalExecutor, RemoteExecutor
"""
from src.integrations.base import (
    BLOCKED_PREFIX,
    ESCALATED_PREFIX,
    LocalExecutor,
    RemoteExecutor,
    SecureExecutor,
    get_default_executor,
    secure_callable,
)

__all__ = [
    "secure_callable",
    "get_default_executor",
    "SecureExecutor",
    "LocalExecutor",
    "RemoteExecutor",
    "BLOCKED_PREFIX",
    "ESCALATED_PREFIX",
]