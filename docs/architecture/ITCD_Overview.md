# SecureAgentNet: Architectural Blueprint & Audit Plan

## Overview
The core philosophy of SecureAgentNet is **Zero-Trust for AI Agents**. We assume that any agent (even a friendly one) can be compromised via prompt injection, goal hijacking, or hallucination. 

To mitigate this, the architecture acts as a strict middleware/proxy between the AI Agent and the outside world (APIs, databases, file systems). It implements an **ITCD (Identify, Track, Contain, Decide)** pipeline.

## 1. System Request Lifecycle (The Data Flow)
When an AI agent attempts to execute an action (e.g., "Delete user records" or "Fetch data from URL"), the request flows through the pipeline:

1. **Agent ➡️ Gateway**: The agent sends an action request via the Model Context Protocol (MCP) or REST API.
2. **[I]dentify**: The `mcp_gateway` intercepts the request. The `authentication` module verifies the agent's cryptographic signature. The `capability_profiler` checks if the agent is authorized for this *type* of action.
3. **[T]rack**: Before any action occurs, `reasoning_capture` logs the agent's intent and context. This is pushed asynchronously to HashiCorp Vault (for tamper-proof logging) and PostgreSQL (for forensic indexing).
4. **[D]ecide (Pre-execution)**: The request enters the Semantic Gateway.
    * *Tier 1*: `rule_filter` checks against hardcoded policies (e.g., "Deny all DELETE requests").
    * *Tier 2*: `pii_redactor` scans payloads for sensitive data.
    * *Tier 3*: `semantic_evaluator` uses a local, sandboxed LLM (via Ollama) to analyze the *intent* of the request for malicious behavior (e.g., prompt injection).
5. **[C]ontain (Execution)**: If approved, `container_provisioner` spins up an ephemeral, deeply restricted Docker container (with strict `seccomp`, `AppArmor`, and no default network access) to execute the specific tool or script.
6. **Response ➡️ Agent**: The result is captured, sanitized, and returned to the agent.

## 2. Component Architecture & Tech Stack

### A. Core Infrastructure
* **Language**: Python 3.11+ (FastAPI/Flask for interfaces, Pydantic for data validation).
* **Database**: PostgreSQL (Identity registry, policy rules, log indexing).
* **Secrets & Auditing**: HashiCorp Vault (Tamper-proof storage of agent credentials and forensic logs).
* **Local AI**: Ollama (Runs the Semantic Evaluator offline to prevent data leaks during evaluation).

### B. Security Boundaries (The Audit Perspective)
* **Network Boundary**: The execution environment (`Contain` phase) uses Linux network namespaces. Default is `none`. Only explicitly whitelisted IPs/Domains are allowed.
* **Compute Boundary**: Docker + cgroups limit CPU and Memory. If an agent tries a denial-of-service, the `resource_manager` kills it.
* **Kernel Boundary**: `seccomp_profile.json` drops all dangerous Linux capabilities, preventing container escape.
* **Data Boundary**: The `circuit_breaker` monitors anomaly rates (e.g., too many denied requests) and trips the `kill_switch`, revoking the agent's token.

## 3. Development Phases

1. **Phase 1: Foundation & Data Layer** (Config, Database Schema, Pydantic Models)
2. **Phase 2: The Identity & Gateway (Identify)** (MCP Server, Agent Auth)
3. **Phase 3: The Execution Sandbox (Contain)** (Docker Wrappers, Security Profiles)
4. **Phase 4: The Brains (Decide & Track)** (Semantic Evaluator, Vault Integration)
5. **Phase 5: The Glass Pane (Interfaces)** (Web Dashboard, CLI, Console)
