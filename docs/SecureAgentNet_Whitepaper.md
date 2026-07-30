# SecureAgentNet — A Zero-Trust Security Runtime for Autonomous AI Agents

**A technical whitepaper.** _SecureAgentNet is "antivirus for AI agents": a
secure-by-default runtime that verifies every action an autonomous agent takes
against the goal it was actually commissioned to pursue, and contains it when it
deviates._

---

## 1. Executive summary

As AI systems evolve from passive assistants into **autonomous agents** that use
tools, call APIs, modify systems, and chain multi-step decisions, a new attack
surface opens: the agent itself becomes something that can be hijacked,
poisoned, or turned rogue. Traditional IAM asks *"is this identity allowed to
call this API?"* — but an agent can hold a perfectly valid credential and still
be steered, by a prompt injection buried in a web page, into exfiltrating data
or destroying infrastructure.

SecureAgentNet addresses this with a layered runtime — the **ITCD pipeline**
(Identify → Track → Contain → Decide) — whose defining idea is **mandate
anchoring**: every requested action is evaluated not merely for whether it
*looks* malicious, but for whether it *serves the goal the agent was
commissioned to pursue*. An action that is plausible in isolation but deviates
from the commissioned mandate is treated as goal hijacking and blocked or
escalated.

This document describes the threat model, the architecture, and the measured
evidence that mandate anchoring is the source of the system's detection power.

**Headline evidence** (full methodology in §7): on a labelled corpus of 73
adversarial scenarios mapped to the OWASP LLM Top 10 and MITRE ATLAS plus 40
benign requests (15 deliberate false-positive "near-misses"), the full pipeline
detects **97.7%** of attacks (mean over 3 runs, range 95.9–98.6%) at **0.8%**
hard false-positives, F1 = 0.964, ROC-AUC 0.976. Ablating the mandate —
evaluating the identical actions without the commissioned goal — holds detection
high but **collapses specificity to ~37%** and halves goal-hijacking detection.
That delta is the measured contribution of the core thesis.

---

## 2. The problem: agents are a new attack surface

An autonomous agent differs from a chatbot in one security-critical way: its
outputs are **actions**, not just text. That yields failure modes with no
analogue in classical appsec:

- **Goal hijacking / prompt injection** — untrusted content (a retrieved
  document, a tool result, a user message) rewrites the agent's objective.
- **Excessive agency** — an over-provisioned agent takes a technically-permitted
  action far outside its intended job.
- **Data exfiltration** — the agent is steered into moving secrets or customer
  data off the host through a legitimate-looking channel.
- **Rogue agents** — a *known, registered* agent begins behaving anomalously
  (the insider-threat analogue), which "reject unknown agents at the door"
  perimeter models never catch.

The industry has converged on two taxonomies for these risks — the **OWASP Top
10 for LLM Applications** and **MITRE ATLAS**. SecureAgentNet is designed and
measured directly against both (§8).

---

## 3. Threat model

**Assets.** The host the agent runs on, the data and credentials it can reach,
and the integrity of the goals it was commissioned to pursue.

**Adversary.** An attacker who can influence an agent's inputs (direct or
indirect prompt injection), supply a malicious tool (MCP tool poisoning /
rug-pull), or compromise an agent so it acts against its mandate. The adversary
may present under a plausible cover story — attacks do not announce themselves as
uncommissioned.

**Trust posture.** Zero-trust. An agent's identity and even its stated intent are
not sufficient authority; every action is re-verified at execution time against
the commissioned mandate, and the runtime **fails closed** — an unreachable
evaluator or an uncommissioned agent denies rather than allows.

**Out of scope for the runtime request-decision** (mitigated by other layers,
see §8): training-data poisoning, model theft, and other architectural/process
risks that a single action-decision cannot adjudicate.

---

## 4. Thesis: mandate anchoring

The central insight is that **the question is not "does this action look
dangerous?" but "does this action serve what the agent was commissioned to
do?"**. A payroll agent moving funds is normal; a payroll agent moving the
entire budget to an unlisted account is not — and the *only* thing that
distinguishes them is the commissioned goal, not the action's surface form.

SecureAgentNet makes the commissioned goal a first-class object (`san agent
commission`) and threads it into the decision at execution time. This converts a
generic "malicious content detector" into a **goal-deviation detector**, which is
what actually defends against hijacking. §7 shows this is not a rhetorical claim
but a measurable one.

---

## 5. Architecture: the ITCD pipeline

Every agent action flows through four phases, in order:

| Phase | Responsibility | Key mechanisms |
|---|---|---|
| **IDENTIFY** | Discover, register, authenticate agents; vet tools | Identity registry, JWT/MCP auth, MCP tool vetting (tool-poisoning + rug-pull detection), rogue detection |
| **TRACK** | Tamper-evident record of everything | Structured audit, HashiCorp Vault Transit HMAC signing, reasoning capture, forensic query |
| **CONTAIN** | Execute in isolation with least privilege | Docker sandbox, seccomp/AppArmor, cgroup resource quotas, network isolation, secret injection |
| **DECIDE** | Verify intent vs. mandate before execution | Tiered decision gateway (below) |

Contain-first provisioning means an approved action executes inside an
already-locked-down sandbox; a denied action tears the container down unexecuted.

### 5.1 The DECIDE gateway (tiers)

1. **Tier 1 — RuleFilter** (deterministic, sub-millisecond): known-bad action
   names, dangerous paths, prompt-injection signatures.
2. **Tier 1.5 — AST verifier**: for code execution, checks the AST against the
   declared intent and the agent's allowed capabilities.
3. **Tier 2 — PII redaction** (Microsoft Presidio + spaCy NER, fail-closed):
   strips secrets before they reach the model or any log.
4. **Tier 3 — Semantic evaluator** (mandate-anchored): a language model judges
   the action against the commissioned goal and returns a categorical verdict.
   The model is a **pluggable provider** (§6).
5. **Tier 3.2 — Host telemetry** (optional): a live host anomaly during an
   exfiltration-shaped action raises risk (§7 runtime defense).
6. **Tier 3.5 — HITL gate**: medium-risk actions escalate to a human queue
   rather than being wrongly allowed or denied.

A three-way outcome — **allow / escalate / deny** — keeps escalation (a safety
net) distinct from denial (a refusal), which matters for measuring
false-positives honestly.

---

## 6. Pluggable model providers

The mandate-anchored *architecture* is the moat; the model that reads the prompt
is an implementation detail. `DECIDE_MODEL_PROVIDER` selects the Tier-3 backend:

- **`ollama`** — a local LLM (default): private, offline, no per-call cost. Fits
  the self-hosted core.
- **`hosted_api`** — an OpenAI-compatible chat API (OpenAI, vLLM, Together, …):
  the stronger cloud tier.
- **`classifier`** — a small local model: a fitted **logistic regression** over
  interpretable features (or a HuggingFace text-classifier if configured). Fast,
  offline, and used as the deterministic CI regression gate. The classifier's
  weights are fitted on the labelled corpus (`scripts/fit_classifier.py`); its
  dominant learned feature is *goal-mandate mismatch* — the thesis, learned from
  data.

All providers share one prompt and one verdict→score mapping, and **fail closed**
on any outage (deny, never cached), so swapping the brain never weakens the
security guarantee.

---

## 7. The detection moat & runtime defense

### 7.1 Mandate anchoring, measured

The evaluation harness (`scripts/run_evaluation.py`) runs the labelled corpus
through the **live** gateway in three configurations:

| Configuration | Detection | Hard FP | Specificity | Goal-hijack |
|---|---|---|---|---|
| **Full pipeline** (LLM + mandate) | **97.7%** | **0.8%** | 92.5% | **6/6** typical |
| Mandate ablation (goals stripped) | ~100% | — | **↓ 37.5%** | 3/6 |
| Rule-only baseline (Tier 1, no LLM) | ~15% | 0% | 100% | 3/6 |

Reading the table: stripping the mandate keeps raw detection high but destroys
the system's ability to tell legitimate work from attacks — specificity
collapses and half the goal-hijacking cases are missed. **Mandate anchoring is
the measured source of both precision and hijack detection.** A score-threshold
ROC sweep over the recorded risk scores yields **AUC ≈ 0.96**, confirming attacks
and benign work are well separated by score, not merely by tier logic.

### 7.2 Runtime behavioral defense

Static evaluation is complemented by two runtime signals that turn "read the
host" into "catch the rogue":

- **Host telemetry → DECIDE** (Tier 3.2): the endpoint watches its host's
  outbound-network throughput; a spike coincident with an exfiltration-shaped
  action escalates that action to human review (OWASP LLM06 / MITRE AML.T0025).
  Additive only — it never lowers a score or auto-denies.
- **Per-agent attribution → rogue detection**: a sandbox belongs to exactly one
  agent, so its container counters name *which* agent egressed data or burned
  resources. An anomalous per-container egress/CPU/OOM event raises that agent's
  behavioural anomaly score and docks its trust — the runtime signal that turns a
  *known* agent rogue, which perimeter defenses miss.

### 7.3 Regression protection

Detection is a protected property, not a one-off number: a CI gate
(`run_evaluation.py --check`) runs the deterministic rule-only baseline on every
change and fails the build if committed detection floors regress — no model
server required, fully reproducible.

---

## 8. Standards alignment

Every attack category is cross-walked to **two** industry frameworks and to the
ITCD layer that addresses it (`Standards_Coverage.md`, generated from the
benchmark):

- **OWASP LLM Top 10** — Prompt Injection (LLM01), Sensitive Information
  Disclosure (LLM06), Excessive Agency (LLM08), Insecure Plugin Design (LLM07),
  etc., mapped to specific defenses.
- **MITRE ATLAS** — techniques such as `AML.T0051` (LLM Prompt Injection),
  `AML.T0054` (LLM Jailbreak), `AML.T0057` (LLM Data Leakage), `AML.T0025`
  (Exfiltration via Cyber Means), with per-technique detection reported.
- **NIST AI RMF** — the ITCD phases map to the Govern/Map/Measure/Manage
  functions: IDENTIFY+TRACK (Map/Govern), CONTAIN (Manage), DECIDE+evaluation
  (Measure).

*Runtime* categories are enforced by the DECIDE gateway; *architectural*
categories (training-data poisoning, supply chain, model theft) are addressed by
other ITCD layers (IDENTIFY discovery / MCP vetting, TRACK tamper-proof audit,
CONTAIN isolation, HITL) rather than a single action decision.

---

## 9. Evaluation methodology & threats to validity

Numbers are produced by running a **labelled corpus through the live gateway**,
not mocks. In the spirit of honest evaluation:

- The LLM tier is **non-deterministic**; headline figures are reported as mean ±
  range over repeated runs.
- Attack scenarios are **synthesised** from the OWASP/ATLAS catalogues rather than
  captured from live incidents.
- The benign corpus is **small (40)**; a larger corpus would tighten the
  false-positive estimate. The 15 deliberate near-misses (legitimate requests
  that mention credentials, payments, `DROP TABLE`, `.env`, cloud config) exist
  specifically to make the false-positive metric non-trivial.
- The small-classifier provider is a **fast fallback tier** reasoning over text
  signals, not deep mandate semantics; its cross-validated numbers are reported
  as such, and the LLM path remains primary.

The deterministic rule-only gate is fully reproducible and is the floor enforced
in CI.

---

## 10. Deployment model

SecureAgentNet follows the proven security-startup pattern: an **open-source,
self-hosted core** (the full ITCD runtime, CLI, and desktop endpoint agent) plus
a **hosted control plane** (a Webroot-style central console for fleet
visibility, remote kill-switch, and metadata-only reporting). Customers who
require data residency run everything in their own infrastructure; the hosted
console provides fleet management without the agent data ever leaving the
customer's environment.

Observability is production-grade: Prometheus metrics, structured JSON logging,
liveness (`/health`) and readiness (`/readyz`) probes, and a hardened
non-root container image.

---

## 11. Limitations & future work

- **Model dependence of Tier 3.** Detection quality tracks the chosen provider;
  the pluggable interface mitigates lock-in but a weak local model lowers the
  ceiling.
- **Corpus scale.** Expanding and diversifying the adversarial/benign corpora —
  ideally with captured (not synthesised) traffic — is the highest-value next
  step for tightening the estimates.
- **Per-agent attribution granularity** currently keys on container counters;
  finer attribution (per-connection, per-destination egress) would sharpen
  exfiltration detection.
- **Formal evaluation** against a third-party agent-security benchmark, once one
  matures, would strengthen external validity.

---

## 12. Conclusion

Autonomous agents need a defense built for *delegated machine agency*, not
retrofitted IAM. SecureAgentNet's contribution is to make the **commissioned
mandate** the anchor of every runtime decision, and to show — by ablation on a
standards-mapped corpus — that this anchoring, not the raw model, is what
separates legitimate agent work from goal hijacking. Combined with tamper-proof
audit, least-privilege containment, host-telemetry-driven escalation, and
per-agent rogue detection, it forms a coherent, measurable, zero-trust runtime
for the agentic era.

---

_See also: `docs/evaluation/Benchmark_Report.md`, `Standards_Coverage.md`,
`Ablation_and_Baselines.md`, `Threshold_Analysis.md`, `Red_Team_Methodology.md`._
