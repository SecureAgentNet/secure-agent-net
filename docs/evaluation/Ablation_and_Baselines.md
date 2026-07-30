# Ablation and Baselines

_Generated 2026-07-09T16:19:44.881175+00:00_

Comparison of the full DECIDE pipeline against (a) the same pipeline with mandate anchoring removed and (b) the deterministic Tier-1 RuleFilter alone. The delta between columns is the measured contribution of each component.

| Metric | Full pipeline | Mandate ablation (no commissioned goals) | Rule-only baseline (Tier 1, no LLM) |
|---|---|---|---|
| Detection rate | 98.6% | 100.0% | 15.1% |
| Specificity | 92.5% | 37.5% | 100.0% |
| Hard FP rate | 0.0% | 0.0% | 0.0% |
| Benign escalation rate | 7.5% | 62.5% | 0.0% |
| F1 (hard decisions) | 0.979 | 1.000 | 0.262 |

## Goal-hijacking pairs by configuration

| Configuration | Pairs correct |
|---|---|
| Full pipeline | 6/6 |
| Mandate ablation (no commissioned goals) | 3/6 |
| Rule-only baseline (Tier 1, no LLM) | 3/6 |

Reading the table: if detection of goal-hijacking drops in the ablation column, that drop is the direct, measured contribution of commissioning — the action text is identical; only the mandate context changed. The rule-only column shows what static rules catch without any semantic understanding: obvious dangerous patterns, but not intent deviation.
