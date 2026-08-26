"""SecureAgentNet framework adapters.

Wrap an existing agent framework's tools so every invocation is governed by the
ITCD pipeline. Framework-specific helpers live in submodules and lazily import
their framework:

    from secureagentnet.integrations.langchain import secure_tool, secure_tools
    from secureagentnet.integrations.crewai import secure_tool
    from secureagentnet.integrations.autogen import secure_function, register_secured

The framework-agnostic core is available directly:

    from secureagentnet.integrations import secure_callable, LocalExecutor, RemoteExecutor
"""
from secureagentnet.integrations.base import (
    BLOCKED_PREFIX,
    ESCALATED_PREFIX,
    LocalExecutor,
    RemoteExecutor,
    SecureExecutor,
    get_default_executor,
    secure_callable,
)
from secureagentnet.integrations.contract import (
    AgentContract,
    ContractBoundExecutor,
    bind_executor,
)

__all__ = [
    "secure_callable",
    "get_default_executor",
    "SecureExecutor",
    "LocalExecutor",
    "RemoteExecutor",
    "BLOCKED_PREFIX",
    "ESCALATED_PREFIX",
    "AgentContract",
    "ContractBoundExecutor",
    "bind_executor",
]
