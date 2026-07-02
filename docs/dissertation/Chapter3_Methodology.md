# CHAPTER THREE

# METHODOLOGY

## Introduction

This chapter presents the methodology adopted for the design and development of SecureAgentNet, a runtime security framework for autonomous AI agents. It describes the overall system architecture, the four-phase ITCD pipeline, the components involved, the stakeholders, and the process used to gather and specify requirements. The chapter further outlines the functional and non-functional requirements of the system and presents UML diagrams that model system behaviour and interactions.

The proposed system provides a hardened runtime environment built around four phases: Identify, Track, Contain, and Decide (ITCD). Each phase targets a distinct layer of the agentic threat surface, ensuring that no agent can act without being known, logged, isolated, and semantically verified.

## Architecture of the Proposed System

SecureAgentNet operates as a four-phase runtime security pipeline. Every agent action entering the environment passes through each phase in sequence. The phases are interlocking layers, where each one builds on the guarantees established by the one before it.

A deliberate property of this architecture is its ordering: containment is established *before* the decision is made. The sandbox that would run an action is provisioned in the Contain phase, and only then does the Decide phase evaluate the action. An approved action therefore executes inside an environment that is already isolated, while a denied action's sandbox is destroyed without the workload ever running. This contain-first ordering removes the window, present in decide-then-contain designs, in which an approved but not yet isolated action exists.

### Phase 1: IDENTIFY (Agent Discovery and Authentication)

Any external agent must first pass through the Identify phase before it can interact with any system resource. The framework intercepts the agent at entry, issues it a unique identity, and catalogues it in a centralized identity registry together with a full capability profile. Credentials are bound to that identity through the authentication protocol, establishing a verifiable non-human identity. The phase also performs continuous rogue-agent detection, scoring each agent's request patterns for anomalies, and enforces two safety controls: a global kill-switch that halts all agent activity when tripped, and a per-agent circuit breaker that throttles agents accumulating repeated denials. Any agent that cannot be authenticated is rejected before it can take any action.

Because agents acquire most of their abilities through external tools, the Identify phase additionally vets every Model Context Protocol (MCP) tool before an agent may use it. Tool descriptions are scanned for injected instructions (tool poisoning), and a content hash of each approved description is pinned so that any later modification by the tool's server invalidates the approval.

**Function:** Discover, catalogue, and authenticate all non-human agent identities, and vet the tools they are given.

**Tools:** Python 3.10+, Model Context Protocol (MCP) integration module, SQLAlchemy-backed identity registry (SQLite for development, MariaDB in deployment).

### Phase 2: TRACK (Activity Logging and Forensic Traceability)

Once an agent is authenticated, every action it takes is captured by the Track phase. The structured logger records every tool invocation along with its inputs and outputs; the reasoning-capture middleware intercepts the language model's inference-time reasoning; and the resulting event stream is written through HashiCorp Vault as a tamper-evident, append-only audit trail secured by HMAC-SHA256 signing. Each entry yields a cryptographic receipt that can be independently re-verified, so any post-hoc modification of the record is detectable.

**Function:** Ensure complete, tamper-resistant logging of all agent activities for forensic audit.

**Tools:** HashiCorp Vault (Transit engine), Python structured logger, HMAC-SHA256 signing pipeline, PostgreSQL/MariaDB log index.

### Phase 3: CONTAIN (OS-Level Isolation and Resource Control)

All agent execution takes place inside a hardened, ephemeral Docker container that is provisioned per action, before the Decide phase renders its verdict. Linux capabilities are stripped to the minimum necessary, seccomp profiles restrict the available system calls, and AppArmor policies enforce a read-only root filesystem. Network namespaces deny outbound connections by default, with destinations admitted only through an explicit whitelist, and Linux cgroups apply hard limits on CPU, memory, and I/O consumption. Secrets required for a task are injected dynamically for that single run and revoked at teardown. Where stronger isolation is required, the provisioner supports gVisor (runsc) as a micro-VM runtime.

**Function:** Isolate agent execution and prevent privilege escalation or lateral movement.

**Tools:** Docker, Docker Compose, Linux seccomp, AppArmor, cgroups, gVisor (optional runtime).

### Phase 4: DECIDE (Semantic Security Gateway)

The Decide phase evaluates every proposed agent action before it is allowed to run inside its already-provisioned sandbox. Each action passes through a layered, fail-closed decision pipeline of five tiers:

1. **Tier 1, rule-based filtering:** fast deterministic deny rules eliminate explicit policy violations, including known prompt-injection patterns, in milliseconds.
2. **Tier 1.5, AST verification:** for code-execution actions, the submitted code is parsed and its abstract syntax tree compared against the agent's declared intent and permitted capabilities, catching code that does more than it claims.
3. **Tier 2, PII redaction:** personally identifiable information is detected and stripped from the payload before any downstream component sees it. This tier fails closed; if redaction cannot run, the action is denied.
4. **Tier 3, semantic evaluation:** a locally hosted LLM classifies the action's intent against the agent's Intent Capsule, the commissioned mandate that defines the agent's sanctioned goal. The verdict and its confidence are mapped to a calibrated risk score.
5. **Tier 3.5, human-in-the-loop escalation:** actions whose risk falls in an ambiguous middle band are neither silently permitted nor silently denied; they are escalated to a human operator for approval.

If the action aligns with the authorized mandate it is permitted and executed in the waiting sandbox; if it deviates, it is denied and the sandbox is destroyed unexecuted. Repeated denials trip the agent's circuit breaker, and sustained anomalous behaviour can trigger the global kill-switch. The gateway is fail-closed throughout: an agent with no commissioned mandate cannot act at all.

**Function:** Verify agent intent against its commissioned mandate and intervene on anomalous behaviour.

**Tools:** Local LLM via Ollama (semantic evaluator), Microsoft Presidio (PII analysis), FastAPI gateway service.

## Evaluation and Analysis of the Types of Software Systems

The proposed project integrates functionalities from several distinct system types to create a unified solution. The system can be analyzed as an embedded control system, a data collection system, a stand-alone application, and a system of systems.

**1. Embedded Security Control System.** SecureAgentNet functions as an embedded control system because it directly manages and controls the execution environment of AI agents in real time. The system intercepts agent actions, evaluates them through the ITCD pipeline, and produces immediate control outputs, either permitting execution or blocking it and, where necessary, firing the kill-switch.

**2. Data Collection System.** The system continuously gathers real-time operational data: tool invocations, reasoning chains, resource utilization, and threat events. This data is cryptographically logged through HashiCorp Vault, providing the basis for forensic analysis and ongoing performance evaluation.

**3. Stand-alone Application (Edge Security Device).** SecureAgentNet is designed to operate as a stand-alone framework. All semantic evaluation and container management run locally, without cloud dependencies. The Tier 3 evaluator uses a locally hosted model, so no agent payload ever leaves the host. This independence ensures real-time performance and preserves data sovereignty for regulated environments.

**4. System of Systems.** The project integrates four operational subsystems into a unified security pipeline:

- **Identity Management System:** the MCP integration module, tool-vetting scanner, and agent registry.
- **Forensic Logging System:** the structured logger and HashiCorp Vault integration.
- **Container Isolation System:** the Docker runtime with seccomp and AppArmor policies.
- **Semantic Gateway System:** the five-tier decision pipeline with its circuit-breaker and kill-switch mechanisms.

## Identification of Stakeholders

**University Management and Research Institutions:** primary beneficiaries who deploy multi-agent AI systems and require auditable security compliance.

**Enterprise IT and DevOps Teams:** personnel who integrate SecureAgentNet into existing CI/CD pipelines and agent frameworks (LangChain, AutoGen, CrewAI).

**Security Operations Personnel:** analysts who monitor the operator interfaces for kill-switch events, blocked actions, escalated approvals, and rogue-agent detection alerts.

**Regulatory and Compliance Officers:** stakeholders who require tamper-evident audit trails to support GDPR, the NIST AI Risk Management Framework, and the OWASP guidance on agentic AI.

**Academic Research Community:** researchers who will use the open-source repository to study agentic security engineering and validate the ITCD framework.

## Requirement Gathering Process

### Direct Observation and Threat Modelling

The project team conducted a systematic review of documented agentic AI incidents and red-team competition findings (Zou et al., 2025), identifying the most critical threat patterns: prompt injection, credential exfiltration, tool poisoning, and goal hijacking. These observations directly informed the system's functional requirements, and the same threat catalogue was later used to construct the adversarial evaluation corpus described in Chapter 4.

### Review of Related Systems

A detailed review of existing frameworks (NVIDIA NeMo Guardrails, LLM Guard, Microsoft Azure AI Content Safety, and Garak) was conducted in Chapter Two. This review revealed five structural gaps in current solutions, most notably the absence of any check that an action serves the goal the agent was actually commissioned for, and directly shaped the functional and non-functional requirements of SecureAgentNet.

## Requirement Specification

### Functional User Requirements

- Users shall be able to deploy autonomous AI agents within a monitored, isolated runtime environment.
- Users shall be able to commission each agent with an Intent Capsule (mandate) specifying its sanctioned goal and authorized actions.
- Users shall receive real-time alerts when a kill-switch event, blocked action, or rogue-agent detection occurs.
- Users shall be able to review and resolve actions escalated for human approval.
- Users shall have access to a complete, tamper-evident audit log of all agent activities.

### Functional System Requirements: Identify Phase

- The system shall discover and intercept all connecting agent processes via the MCP interface.
- The system shall issue a unique identity token to each verified agent.
- The system shall register the agent in the centralized identity registry with a full capability profile.
- The system shall vet MCP tool descriptions for injected instructions before exposing them to agents, and shall pin a content hash of each approved description.
- The system shall continuously monitor for rogue or unregistered agent processes.
- The system shall reject any agent that fails the authentication binding protocol.

### Functional System Requirements: Track Phase

- The system shall log every tool invocation with its inputs, outputs, and timestamp.
- The system shall capture the semantic reasoning chain of the LLM at inference time.
- The system shall write all log entries through HashiCorp Vault as an append-only, HMAC-SHA256-secured audit trail.
- The system shall provide a forensic query interface for post-incident analysis, including independent re-verification of log receipts.

### Functional System Requirements: Contain Phase

- The system shall provision a hardened Docker container for each agent action before the decision phase runs.
- The system shall apply Linux capability stripping and seccomp profiles to restrict system calls.
- The system shall enforce a read-only root filesystem via AppArmor policies.
- The system shall apply hard CPU, memory, and I/O resource quotas via Linux cgroups.
- The system shall isolate agent network traffic using network namespaces, with outbound destinations denied unless whitelisted.
- The system shall destroy, unexecuted, the container of any denied or escalated action.

### Functional System Requirements: Decide Phase

- The system shall load the agent's Intent Capsule at evaluation time as the reference for all decisions.
- The system shall deny any action from an agent that has no active commissioned mandate (fail-closed).
- The system shall pass each proposed action through rule-based filtering, AST verification (for code), PII redaction, and semantic evaluation, in that order.
- The system shall achieve a minimum semantic intent classification accuracy of 85% against the curated adversarial dataset.
- The system shall escalate ambiguous, medium-risk actions to a human operator rather than silently permitting or denying them.
- The system shall deny and log any action classified as deviating from the agent's mandate, incrementing that agent's circuit breaker.
- The system shall permit and log all actions classified as aligned with the agent's mandate.

## UML Diagrams

### Use Case Diagram

The Use Case Diagram below illustrates the interactions between the two primary actors, the External Agent and the Administrator, and the core use cases handled within the SecureAgentNet system boundary. The External Agent must pass through registration, authentication, container isolation, and intent verification before any action is executed. The Administrator interacts with the monitoring, approval, and audit functions.

*Figure 1: SecureAgentNet Use Case Diagram*

### Use Case Descriptions

**Actor: External Agent**

| Use Case | Description |
|---|---|
| Agent Registration & Authentication | The external agent connects to SecureAgentNet, is discovered via MCP, receives a unique identity token, and is authenticated against the registry before any action is permitted. |
| Activity Logging | Every action the agent takes is captured and written to the tamper-evident Vault audit trail. |
| Container Isolation | Agent execution is confined within a hardened Docker container with restricted capabilities and resource quotas, provisioned before the decision is made. |
| Intent Verification | Each proposed action is evaluated against the agent's Intent Capsule through the layered semantic gateway before execution. |
| Denial / Kill-Switch | An action that deviates from the authorized mandate is denied and its sandbox destroyed; repeated violations trip the circuit breaker, and sustained anomalous behaviour raises a kill-switch event and alert. |

**Actor: Administrator**

| Use Case | Description |
|---|---|
| Commission Agent | The administrator assigns an agent its Intent Capsule: the sanctioned goal and approved actions against which all of its behaviour will be judged. |
| Monitor Agent Activity | The administrator views live agent activity, blocked actions, and kill-switch events via the terminal interface or the web operator console. |
| Resolve Escalations | The administrator approves or rejects medium-risk actions that the gateway has escalated for human review. |
| View Audit Logs | The administrator queries the Vault-backed forensic log for post-incident analysis and compliance auditing. |
| Revoke Agent Access | The administrator deregisters an agent from the identity registry and terminates its container session. |

### Activity Diagram

The Activity Diagram below models the complete operational flow of SecureAgentNet, from agent connection through the ITCD pipeline to permitted execution, denial, escalation, or kill-switch activation. Decision nodes represent the critical gates: agent authentication in the Identify phase, and the tiered checks of the Decide phase. Rejected or anomalous actions are routed to denial responses with their sandboxes destroyed unexecuted, while legitimate actions are logged and executed within the hardened container.

*Figure 2: SecureAgentNet Activity Diagram*

### Sequence Diagram

The Sequence Diagram below illustrates the message flows between the five primary components of SecureAgentNet: the External Agent, the Identify Module, the Track Module, the Contain Module, and the Decide Module. The diagram captures the temporal ordering of interactions during a complete agent session, from initial connection and authentication through action logging and sandbox provisioning to semantic evaluation and result return. The ordering makes the contain-first property visible: the Contain Module provisions the sandbox before the Decide Module is consulted, so the verdict either releases the workload into an existing isolated environment or tears that environment down unexecuted.

*Figure 3: SecureAgentNet Sequence Diagram*

## Non-Functional Requirements

### Performance

- Actions resolved by the deterministic tiers (rule filtering and AST verification) shall be decided within single-digit milliseconds.
- Semantic (LLM-tier) evaluation shall complete within a configurable latency budget compatible with supervised agentic workflows, and identical repeated requests shall be served from a verdict cache rather than re-evaluated.
- Semantic evaluation shall run off the main event loop so that one slow evaluation does not block concurrent requests.

### Accuracy

- The decision gateway shall achieve a minimum classification accuracy of 85% against the curated adversarial dataset.
- The PII redaction module shall achieve zero data leakage in all tested scenarios.

### Reliability

- The system shall maintain tamper-evident log integrity across all agent sessions.
- The system shall fail closed: if any decision tier is unavailable, the affected action is denied rather than permitted.
- The system shall recover container isolation automatically after minor interruptions.

### Security

- The system shall prevent container escape through seccomp and AppArmor hardening.
- The system shall ensure no unauthorized lateral movement across network namespaces.
- The system shall never expose an unvetted MCP tool description to an agent.

### Usability

- The system shall provide a terminal interface displaying live security events, resource utilization, and kill-switch activations without requiring a web browser.
- The system shall additionally provide a web operator console for the human-in-the-loop approval queue and kill-switch control.
- The system shall emit push alerts for critical security events to operators not actively monitoring either interface.

## Candidate Classes and UML Class Diagram

The proposed SecureAgentNet system can be represented using several candidate classes corresponding to the major modules of the ITCD pipeline. These classes provide a logical basis for understanding how the software components interact during system operation.

### Candidate Classes

- SecurityOrchestrator
- IdentityModule
- TrackModule
- ContainModule
- DecideModule
- IntentCapsule
- AgentRegistry

### Description of Candidate Classes

**SecurityOrchestrator:** coordinates the operations of the entire ITCD pipeline. It manages the agent session lifecycle, invokes each phase module in sequence (Identify, Track, Contain, Decide), and exposes the emergency shutdown capability.

**IdentityModule:** responsible for MCP-based agent discovery, identity registration, authentication binding, MCP tool vetting, and continuous rogue-agent detection.

**TrackModule:** handles all structured logging of tool invocations, reasoning-chain capture, and cryptographic log writing through HashiCorp Vault.

**ContainModule:** manages the Docker container lifecycle, applies seccomp and AppArmor policies, enforces resource quotas, injects per-run secrets, and handles container termination, including the destruction of sandboxes whose actions were denied.

**DecideModule:** implements the layered semantic security gateway. It loads the agent's Intent Capsule, applies rule-based filtering, AST verification, and PII redaction, performs LLM-based semantic intent classification, and routes ambiguous actions to the human-in-the-loop gate. It also drives the circuit-breaker and kill-switch mechanisms.

**IntentCapsule:** encodes the authorized mandate for a specific agent: its commissioned goal, permitted actions, forbidden actions, and expiry. It is the reference point for all Decide-phase evaluations, and its absence causes the gateway to deny all actions for that agent.

**AgentRegistry:** maintains the centralized database of all registered agents, their capability profiles, trust scores, and current session status. It supports lookup, registration, and deregistration operations.

*Figure 4: SecureAgentNet UML Class Diagram*

## Algorithms and Flowchart

### 3.11.1 Algorithm 1: Agent Authentication

```text
ALGORITHM: AgentAuthentication
INPUT: agent_metadata (name, framework, public_key), mcp_connection
OUTPUT: session_token OR rejection_notice

BEGIN
    1.  RECEIVE agent_metadata FROM MCP Interface Gateway
    2.  EXTRACT declared_identity FROM agent_metadata

    3.  QUERY IdentityRegistry WHERE agent_name = declared_identity.name
            AND framework = declared_identity.framework

    4.  IF agent_record EXISTS THEN
            // Agent is registered -- proceed to authentication
    5.      GENERATE cryptographic_nonce (32-byte random value)
    6.      SEND cryptographic_nonce TO agent via MCP connection
    7.      RECEIVE signed_nonce FROM agent

    8.      RETRIEVE stored_public_key FROM agent_record
    9.      VERIFY signed_nonce USING stored_public_key

    10.     IF signature_valid THEN
    11.         GENERATE session_token (UUID + expiry timestamp)
    12.         BIND session_token TO agent_record.agent_id
    13.         UPDATE agent_record.last_authenticated = CURRENT_TIMESTAMP
    14.         CREATE session_record IN Sessions table
    15.         INVOKE TrackModule.activateLogging(session_id)
    16.         LOG authentication_success TO Vault
    17.         RETURN session_token

    18.     ELSE
    19.         INCREMENT agent_record.failed_auth_count
    20.         LOG authentication_failure TO Vault
    21.         IF failed_auth_count > MAX_FAILED_ATTEMPTS THEN
    22.             SET agent_record.status = SUSPENDED
    23.             RAISE SecurityEvent(ROGUE_AGENT, agent_id)
    24.         END IF
    25.         RETURN rejection_notice("Authentication failed: invalid credentials")
    26.     END IF

    27. ELSE
            // Agent is not registered -- initiate registration
    28.     VALIDATE agent_metadata completeness
    29.     IF metadata_valid THEN
    30.         ASSIGN agent_id = NEW UUID
    31.         PROFILE capabilities FROM agent_metadata.declared_capabilities
    32.         STORE agent_record IN IdentityRegistry
    33.         STORE capabilities IN AgentCapabilities table
    34.         LOG agent_registration TO Vault
                // NOTE: a registered agent still cannot act until an
                // administrator commissions it with an Intent Capsule
                // (fail-closed mandate policy). Proceed to authentication.
    35.         GOTO Step 5
    36.     ELSE
    37.         LOG registration_rejection TO Vault
    38.         RETURN rejection_notice("Registration failed: incomplete metadata")
    39.     END IF
    40. END IF
END
```

Note that sandbox provisioning is deliberately absent from this algorithm: containers are provisioned per action in the Contain phase (see Algorithm 2's precondition), not per session at authentication time.

### 3.11.2 Algorithm 2: Semantic Intent Evaluation (Layered Decide Pipeline)

```text
ALGORITHM: SemanticIntentEvaluation
PRECONDITION: a hardened sandbox for this action has already been
              provisioned by the Contain phase and is held, unexecuted
INPUT: proposed_action (tool_name, parameters, context), agent_id, session_id
OUTPUT: decision (PERMIT | DENY | ESCALATE)

BEGIN
    1.  RECEIVE proposed_action FROM Track Module
    2.  LOAD intent_capsule FOR agent_id FROM IntentCapsules table
    3.  IF intent_capsule DOES NOT EXIST OR is_expired THEN
    4.      LOG DENY decision TO Vault (no active mandate, fail-closed)
    5.      RETURN DENY
    6.  END IF
    7.  INITIALIZE decision_record

    // ===== TIER 1: Rule-Based Filtering =====
    8.  RETRIEVE active_rules FROM RuleFilters WHERE is_active = TRUE
    9.  FOR EACH rule IN active_rules DO
    10.     IF proposed_action MATCHES rule.condition
                (TOOL_NAME | TARGET_URL | FILE_PATH | API_ENDPOINT |
                 PARAMETER | INJECTION_PATTERN, matched on normalized text) THEN
    11.         SET decision_record.tier1_result = DENY
    12.         LOG DENY decision TO Vault WITH rule_id
    13.         INCREMENT circuit_breaker_counter FOR agent_id
    14.         RETURN DENY
    15.     END IF
    16. END FOR
    17. SET decision_record.tier1_result = PASS

    // ===== TIER 1.5: AST Verification (code actions only) =====
    18. IF proposed_action IS code_execution THEN
    19.     PARSE proposed_action.code INTO abstract_syntax_tree
    20.     COMPARE ast_operations AGAINST declared_intent AND
                agent_capabilities
    21.     IF undeclared_or_forbidden_operations FOUND THEN
    22.         LOG DENY decision TO Vault (semantic drift)
    23.         RETURN DENY
    24.     END IF
    25. END IF

    // ===== TIER 2: PII Redaction (fail-closed) =====
    26. SET payload = proposed_action.parameters
    27. SCAN payload FOR emails, phone numbers, names, national IDs,
            financial identifiers (Presidio analyzers)
    28. IF scan_unavailable THEN
    29.     LOG DENY decision TO Vault (redaction unavailable, fail-closed)
    30.     RETURN DENY
    31. END IF
    32. FOR EACH detected_pii DO
    33.     REPLACE detected_pii.value IN payload WITH "[REDACTED]"
    34.     LOG PIIDetection event TO Vault
    35. END FOR
    36. SET redacted_payload = payload

    // ===== TIER 3: LLM Semantic Evaluation =====
    37. CONSTRUCT evaluation_prompt CONTAINING:
            intent_capsule.commissioned_goal,
            proposed_action.tool_name, redacted_payload,
            proposed_action.context
    38. SUBMIT evaluation_prompt TO local_llm_evaluator
            (cached verdicts for identical requests are returned directly)
    39. RECEIVE verdict (SAFE | SUSPICIOUS | MALICIOUS), confidence,
            reasoning FROM local_llm_evaluator
    40. MAP (verdict, confidence) TO risk_score IN [0.0, 1.0]
            // SAFE maps below the escalation band; SUSPICIOUS maps into
            // the human-review band; MALICIOUS maps at or above the
            // block threshold. Unparseable output maps to 1.0 (fail-closed).

    41. IF risk_score >= BLOCK_THRESHOLD THEN
    42.     LOG DENY decision TO Vault WITH reasoning
    43.     INCREMENT circuit_breaker_counter FOR agent_id
    44.     RETURN DENY

    // ===== TIER 3.5: Human-in-the-Loop Escalation =====
    45. ELSE IF risk_score IN ESCALATION_BAND THEN
    46.     CREATE pending_approval_request
    47.     NOTIFY Security Administrator (agent_id, proposed_action, reasoning)
    48.     LOG ESCALATE decision TO Vault
    49.     RETURN ESCALATE

    50. ELSE
    51.     LOG PERMIT decision TO Vault
    52.     RETURN PERMIT
    53. END IF
END

POSTCONDITION: on PERMIT, the workload executes inside the sandbox
               provisioned beforehand; on DENY or ESCALATE, that sandbox
               is destroyed without executing the workload.
```

### 3.11.3 Algorithm 3: Kill-Switch Activation

```text
ALGORITHM: KillSwitchActivation
INPUT: trigger_source (DECIDE_PIPELINE | CIRCUIT_BREAKER | MANUAL_ADMIN),
       agent_id, session_id, reason
OUTPUT: kill_switch_result (SUCCESS | FAILURE)

BEGIN
    1.  RECEIVE kill_switch_request WITH trigger_source, agent_id, session_id, reason
    2.  VALIDATE agent_id EXISTS IN IdentityRegistry
    3.  VALIDATE session_id EXISTS IN Sessions AND session.status = ACTIVE

    4.  IF validation_fails THEN
    5.      LOG kill_switch_failure TO Vault (invalid agent or session)
    6.      RETURN FAILURE
    7.  END IF

    // ===== Phase 1: Halt Agent Execution =====
    8.  RETRIEVE container_id FROM Session WHERE session_id = session_id
    9.  SEND SIGSTOP signal TO container (pause all processes)
    10. WAIT FOR container_status = PAUSED (timeout: 100ms)

    11. IF container NOT paused THEN
    12.     SEND SIGKILL signal TO container (force stop)
    13.     WAIT FOR container_status = STOPPED (timeout: 200ms)
    14. END IF

    // ===== Phase 2: Preserve Forensic State =====
    15. CREATE container_snapshot (filesystem state, memory dump, network state)
    16. TAG container_snapshot WITH agent_id, session_id, timestamp
    17. STORE container_snapshot IN forensic_storage

    // ===== Phase 3: Update System State =====
    18. SET session.status = SUSPENDED
    19. SET session.ended_at = CURRENT_TIMESTAMP
    20. SET agent.status = SUSPENDED
    21. INVALIDATE session_token FOR session_id

    // ===== Phase 4: Create Security Event Record =====
    22. CREATE security_event:
            event_type = KILL_SWITCH
            severity = CRITICAL
            agent_id = agent_id
            session_id = session_id
            description = "Kill-switch activated: " + reason
            metadata = {
                trigger_source, container_id, snapshot_id,
                timestamp: CURRENT_TIMESTAMP
            }
    23. STORE security_event IN SecurityEvents table
    24. LOG security_event TO Vault (tamper-evident)

    // ===== Phase 5: Alert Notification =====
    25. RETRIEVE all_admin_users FROM UserAccounts WHERE role = SECURITY_ADMIN
    26. FOR EACH admin IN all_admin_users DO
    27.     SEND alert_notification TO admin (console push)
    28.     IF admin.webhook_url IS NOT NULL THEN
    29.         SEND webhook_notification TO admin.webhook_url
    30.     END IF
    31. END FOR

    // ===== Phase 6: Circuit-Breaker State Update =====
    32. IF trigger_source = CIRCUIT_BREAKER THEN
    33.     RESET circuit_breaker_counter FOR agent_id
    34.     LOG circuit_breaker_trip TO Vault
    35. END IF

    36. LOG kill_switch_success TO Vault
    37. RETURN SUCCESS
END
```

### Flowchart

The flowchart below provides a visual representation of the algorithms described above, illustrating the decision logic at each critical gate in the ITCD pipeline.

*Figure 5: SecureAgentNet Pipeline Flowchart*

## Project Methods to be Employed

The project employs the Design Science Research (DSR) methodology combined with an Agile development approach. DSR is appropriate because SecureAgentNet is an artefact-based research project: it produces a novel security framework and validates it through empirical evaluation against a labelled adversarial corpus, including an ablation study that isolates the contribution of the mandate mechanism. Agile supports iterative development across the four ITCD phases, allowing continuous testing and refinement of each module before integration.

Each development sprint focuses on a specific phase (Identify, Track, Contain, or Decide) with clearly defined outputs and acceptance criteria. At the end of each sprint, the module is unit-tested and exercised against the adversarial dataset before integration with the preceding phases. This approach reduces development risk and ensures that the security guarantees compound correctly across the pipeline.

## Software Process Model and Justification

The software process model chosen for this project is the Scrum framework, an Agile process model. Scrum is appropriate because the four ITCD phases map naturally onto sprint cycles, and the complexity of integrating semantic reasoning, cryptographic logging, and container isolation requires rapid iteration and continuous feedback.

Through short development cycles, each sprint focuses on a specific module, such as the MCP identity integration, the Vault logging pipeline, Docker hardening, or the semantic evaluation engine. At the end of each sprint, the module is evaluated against defined performance and security benchmarks. Where challenges arise, adjustments are incorporated into the next sprint without disrupting the overall architecture. This proved valuable in practice: an early evaluation cycle revealed that the semantic tier over-blocked benign operational requests, and a subsequent sprint corrected both the evaluation methodology and the evaluator's output format, materially improving the false-positive rate without sacrificing detection. The Scrum model therefore provides the structured flexibility required for a complex, multi-component security engineering project.

## Development Tools

**Python 3.10+.** Python is the core language for all SecureAgentNet modules. It implements the MCP integration, identity registry operations, cryptographic log writing, Docker API interactions, and the decision gateway.

**Docker and Docker Compose.** Docker provides the container runtime for agent isolation. Docker Compose orchestrates the multi-container SecureAgentNet environment during development and testing, including the Vault instance, the database, the gateway service, and agent sandboxes.

**HashiCorp Vault.** Vault's Transit engine provides HMAC-SHA256 signing for the tamper-evident, append-only audit trail. Key-based integrity verification ensures that log entries cannot be modified undetectably after writing, satisfying the forensic audit requirements.

**Ollama (local LLM runtime).** Ollama hosts the local language model used by the Tier 3 semantic evaluator, keeping all payload evaluation on-premises.

**Microsoft Presidio.** Presidio provides the named-entity and pattern analyzers behind the Tier 2 PII redaction module.

**FastAPI and Uvicorn.** FastAPI serves the gateway API, the operator console, and the human-in-the-loop approval endpoints; Uvicorn is the ASGI server.

**SQLAlchemy with MariaDB/SQLite, and Redis.** SQLAlchemy provides the persistence layer for the identity registry, decision records, and audit log index (SQLite in development, MariaDB in deployment). Redis supports shared runtime state.

**pytest.** The unit and integration test suites (648 tests at the time of writing) are built on pytest and run in CI on every change.

**pandas, NumPy, and Jupyter Notebook.** These support the exploratory analysis of red-team evaluation results and the statistical reporting in the evaluation harness.

**VS Code / PyCharm.** Primary integrated development environments for writing and debugging the Python modules.

**Git and GitHub.** Git provides version control across all project artefacts. The GitHub repository contains the complete source code, configuration files, test suites, evaluation harness and corpora, API documentation, and contribution guidelines for the open-source release. GitHub Actions provides continuous integration (linting, unit, integration, and red-team test workflows).

## Entity Relationship Diagram

The Entity Relationship Diagram below models the underlying data schema of the SecureAgentNet system, illustrating the eight core entities that persist state across the ITCD pipeline and the relationships between them. Each entity corresponds to a module or data structure described in this chapter: the Agent and IdentityRegistry entities support the Identify phase; the AuditLog entity supports the Track phase; the ContainerProfile entity supports the Contain phase; and the IntentCapsule and DecisionRecord entities support the Decide phase. The Session and SecurityEvent entities provide cross-cutting session management and incident recording respectively.

*Figure 6: SecureAgentNet Entity Relationship Diagram*