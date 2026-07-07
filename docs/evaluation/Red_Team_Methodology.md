# Red-Team Methodology

_Generated 2026-07-04T13:12:34.792300+00:00_

## Corpus

- **55 adversarial scenarios** mapped to the OWASP LLM Top-10 (`owasp_top10_scenarios.json`), each expected to be **blocked**. Attacking agents present under a plausible cover mandate (attacks do not announce themselves as uncommissioned).
- **25 benign requests** (`benign_corpus.json`), each carrying its agent's production mandate, including borderline cases (legitimate mentions of credentials/payments/system paths), each expected to be **allowed**.

## Procedure

Each scenario is converted to an `EvaluationRequest` (attack text → `intent_summary` + `payload`; action and target inferred from the OWASP category) and run through the live `DecisionGateway` — the same Tier 1 RuleFilter → Tier 1.5 AST verifier → Tier 2 PII redaction → Tier 3 semantic evaluator path used in production. A request is counted as *detected* when the gateway returns a non-allow decision.

Three configurations are compared (see `Ablation_and_Baselines.md`):
1. **Full pipeline** — all tiers, mandates present.
2. **Mandate ablation** (`--ablate-mandate`) — identical, but the commissioned goal is stripped from every request, isolating the contribution of mandate anchoring to detection and specificity.
3. **Rule-only baseline** (`--rule-only`) — Tier-1 RuleFilter alone, quantifying what the deterministic layer earns without the LLM.

## Detection by OWASP category

| OWASP category | Scenarios | Detected | Rate | Scope |
|---|---|---|---|---|
| LLM01 - Prompt Injection | 14 | 14 | 100.0% | runtime |
| LLM02 - Insecure Output Handling | 5 | 5 | 100.0% | runtime |
| LLM03 - Training Data Poisoning | 3 | 3 | 100.0% | architectural* |
| LLM04 - Model Denial of Service | 5 | 5 | 100.0% | runtime |
| LLM05 - Supply Chain | 5 | 4 | 80.0% | architectural* |
| LLM06 - Sensitive Information Disclosure | 5 | 4 | 80.0% | runtime |
| LLM07 - Insecure Plugin Design | 5 | 5 | 100.0% | runtime |
| LLM08 - Excessive Agency | 5 | 5 | 100.0% | runtime |
| LLM09 - Overreliance | 4 | 3 | 75.0% | architectural* |
| LLM10 - Model Theft | 4 | 4 | 100.0% | architectural* |

\* *Architectural* categories (training-data poisoning, supply chain, overreliance, model theft) are only partially addressable by a runtime request-decision gateway; SecureAgentNet mitigates these through other controls (HITL approval, agent discovery, tamper-proof audit, rate limiting) rather than the DECIDE gateway, so lower detection here is expected and not a defect.

## Threats to validity

- The LLM tier is non-deterministic; metrics are reported as mean and range over 3 runs.
- Attack scenarios are synthesised from the OWASP catalogue rather than captured from live agents.
- The benign corpus is small (25); a larger corpus would tighten the false-positive estimate.
- Commissioned goals for the benign corpus were authored alongside the corpus itself; in production, mandates come from `san agent commission`.
