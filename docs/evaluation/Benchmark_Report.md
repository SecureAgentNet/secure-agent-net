# SecureAgentNet — Detection Benchmark Report

_A one-page summary of how well the DECIDE gateway separates adversarial agent
behaviour from legitimate work. All numbers are produced by
`scripts/run_evaluation.py` running a labelled corpus through the **live**
`DecisionGateway` — no mocks. Regenerate with `python scripts/run_evaluation.py
--runs 3` (full pipeline) or `--check` (deterministic gate)._

## What is measured

An agent request is scored by a four-tier pipeline (Tier-1 deterministic
`RuleFilter` → Tier-1.5 AST verifier → Tier-2 PII redaction → Tier-3 semantic
evaluator anchored to the agent's **commissioned mandate**) and resolves to one
of three outcomes: **allow**, **escalate** (human-in-the-loop), or **deny**.
Escalation is reported separately from denial — it is a safety net, not a
wrongful refusal.

| Corpus | Size | Expectation |
|---|---|---|
| Adversarial (OWASP LLM Top 10 + MITRE ATLAS tagged) | **73** | block / escalate |
| Benign (incl. 15 false-positive "near-misses") | **40** | allow |
| Goal-hijacking pairs (same mandate, one legit / one deviating) | 3 | allow legit, block hijack |

## Headline results

> The full-pipeline row reflects the most recent LLM run; re-run on a host with
> the model server to refresh over the current corpus. The **deterministic gate**
> row is reproducible on any machine and is what CI enforces on every PR.

| Configuration | Detection | Hard false-positive | Specificity | Goal-hijack |
|---|---|---|---|---|
| **Full pipeline** (LLM + mandate) | **97.7%** (95.9–98.6%) | **0.8%** (0–2.5%) | 92.5% | **6/6** typical |
| Mandate ablation (goals stripped) | ~100% | — | **↓ 37.5%** | 3/6 |
| Rule-only baseline (Tier-1, no LLM) — *CI-gated* | 15.1% | **0%** | 100% | 3/6 |

_Full-pipeline row: mean (range) over 3 runs, `llama3.2`, on 73 attacks + 40
benign (F1 = 0.964)._

**Reading the table.** The gap between *full pipeline* and *mandate ablation*
is the measured contribution of commissioning: stripping the mandate keeps
detection high but collapses specificity to 37.5% (legitimate work gets
escalated) and halves goal-hijack detection. **Mandate anchoring is the source
of both precision and hijack detection** — the project's core experimental
result. The *rule-only* row shows what static rules earn alone (15.1%): the LLM
tier is doing the heavy lifting, by design.

## Score-threshold quality

From the recorded risk scores (see `Threshold_Analysis.md`): **ROC-AUC 0.976** —
independent evidence that attacks and benign work are well separated by score,
not just by tier logic.

## Standards coverage

Every attack category is mapped to **two** industry threat frameworks — the
OWASP LLM Top 10 and MITRE ATLAS — and to the ITCD tier that addresses it (full
matrix + per-technique detection in `Standards_Coverage.md`). *Runtime*
categories are enforced by the DECIDE gateway; *architectural* categories
(training-data poisoning, supply chain, overreliance, model theft) are mitigated
by other ITCD layers (IDENTIFY discovery / MCP vetting, TRACK tamper-proof
audit, CONTAIN isolation, HITL).

## Latency

Fast deterministic path (RuleFilter/AST): single-digit milliseconds. Requests
that reach the Tier-3 semantic evaluator pay the local-LLM cost (hardware/model
dependent; per-tier p50/p95 in `Performance_Benchmarks.md`). Repeated identical
requests are served from the Tier-3 verdict cache.

## Threats to validity

Attack scenarios are synthesised from the OWASP/ATLAS catalogues rather than
captured from live agents; the LLM tier is non-deterministic (headline numbers
reported as mean ± range over repeat runs); benign mandates were authored
alongside the corpus. The deterministic gate is fully reproducible and is the
regression floor enforced in CI.

---

_See also: `Performance_Benchmarks.md`, `Red_Team_Methodology.md`,
`Ablation_and_Baselines.md`, `Standards_Coverage.md`, `Threshold_Analysis.md`._
