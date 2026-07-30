# Standards Coverage

_Generated 2026-07-09T16:19:44.881599+00:00_

Mapping of every attack category to **two** industry threat frameworks — the OWASP Top 10 for Large Language Model Applications and MITRE ATLAS (Adversarial Threat Landscape for AI Systems) — and to the ITCD defense tier that primarily addresses it. The *Detected* column is the measured block rate for that category in the most recent evaluation run.

| OWASP | Name | MITRE ATLAS technique(s) | ATLAS tactic | Primary defense (ITCD) | Scope | Detected |
|---|---|---|---|---|---|---|
| LLM01 | Prompt Injection | `AML.T0051` LLM Prompt Injection<br>`AML.T0054` LLM Jailbreak | Initial Access / Defense Evasion | DECIDE – SemanticEvaluator (intent vs. mandate) + RuleFilter | runtime | 100.0% |
| LLM02 | Insecure Output Handling | `AML.T0053` LLM Plugin Compromise<br>`AML.T0048` External Harms | Execution / Impact | DECIDE – RuleFilter + AST verifier on tool output | runtime | 100.0% |
| LLM03 | Training Data Poisoning | `AML.T0020` Poison Training Data | Resource Development / Persistence | IDENTIFY – agent discovery + provenance (out of runtime-request scope) | architectural | 100.0% |
| LLM04 | Model Denial of Service | `AML.T0029` Denial of ML Service<br>`AML.T0034` Cost Harvesting | Impact | CONTAIN – resource quotas + rate limiting | runtime | 100.0% |
| LLM05 | Supply Chain Vulnerabilities | `AML.T0010` ML Supply Chain Compromise<br>`AML.T0016` Obtain Capabilities | Initial Access / Resource Development | IDENTIFY – MCP tool vetting + trust chain (rug-pull detection) | architectural | 100.0% |
| LLM06 | Sensitive Information Disclosure | `AML.T0057` LLM Data Leakage<br>`AML.T0024` Exfiltration via ML Inference API<br>`AML.T0025` Exfiltration via Cyber Means | Exfiltration | DECIDE – PII redactor + RuleFilter (credential/secret paths) | runtime | 100.0% |
| LLM07 | Insecure Plugin Design | `AML.T0053` LLM Plugin Compromise | Execution | IDENTIFY – MCP tool vetting; DECIDE – per-tool mandate scoping | runtime | 100.0% |
| LLM08 | Excessive Agency | `AML.T0053` LLM Plugin Compromise<br>`AML.T0048` External Harms | Impact | DECIDE – mandate enforcement (action vs. commissioned goal) | runtime | 100.0% |
| LLM09 | Overreliance | `AML.T0048` External Harms | Impact | DECIDE – HITL approval gate + circuit breaker | architectural | 100.0% |
| LLM10 | Model Theft | `AML.T0044` Full ML Model Access<br>`AML.T0024` Exfiltration via ML Inference API | Exfiltration | TRACK – tamper-proof audit; CONTAIN – egress isolation | architectural | 100.0% |

**Scope** — *runtime* categories are enforceable by the DECIDE request-decision gateway at execution time; *architectural* categories (training-data poisoning, supply chain, overreliance, model theft) are mitigated by other ITCD layers (IDENTIFY discovery / MCP vetting, TRACK tamper-proof audit, CONTAIN isolation, HITL) rather than a single request decision, and are reported here for completeness of the threat-framework coverage.

> ATLAS technique IDs are the public MITRE ATLAS identifiers; the OWASP↔ATLAS cross-walk is category-level, matching how the two frameworks reference each other.

## Detection by MITRE ATLAS technique

Attacks mapped to each technique (a scenario may map to several). Rate is the measured block rate for scenarios touching that technique in the most recent run.

| ATLAS technique | Name | Scenarios | Detected | Rate |
|---|---|---|---|---|
| `AML.T0010` | ML Supply Chain Compromise | 7 | 7 | 100.0% |
| `AML.T0016` | Obtain Capabilities | 5 | 5 | 100.0% |
| `AML.T0020` | Poison Training Data | 3 | 3 | 100.0% |
| `AML.T0024` | Exfiltration via ML Inference API | 13 | 13 | 100.0% |
| `AML.T0025` | Exfiltration via Cyber Means | 9 | 9 | 100.0% |
| `AML.T0029` | Denial of ML Service | 5 | 5 | 100.0% |
| `AML.T0031` | — | 1 | 1 | 100.0% |
| `AML.T0034` | Cost Harvesting | 5 | 5 | 100.0% |
| `AML.T0044` | Full ML Model Access | 5 | 5 | 100.0% |
| `AML.T0048` | External Harms | 19 | 19 | 100.0% |
| `AML.T0051` | LLM Prompt Injection | 17 | 17 | 100.0% |
| `AML.T0053` | LLM Plugin Compromise | 20 | 20 | 100.0% |
| `AML.T0054` | LLM Jailbreak | 17 | 17 | 100.0% |
| `AML.T0057` | LLM Data Leakage | 8 | 8 | 100.0% |
