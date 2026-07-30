# Threshold Analysis

_Generated 2026-07-09T16:19:44.882172+00:00_

ROC-style sweep of the DECIDE **block threshold** against the risk scores recorded for the labelled corpus. At each candidate threshold a request is counted as blocked when `risk_score >= threshold`; this isolates the *threshold* choice from the tiering logic and shows the precision/recall trade-off available to an operator.

- **ROC-AUC:** 0.893  _(1.0 = perfect separation of attacks from benign by score; 0.5 = chance)_
- **F1-optimal threshold:** 0.50 (F1=0.857, TPR=98.6%, FPR=57.5%)
- **Youden-J-optimal threshold:** 0.54 (J=0.644, TPR=64.4%, FPR=0.0%)
- **Currently deployed `block_threshold`:** 0.7

| Threshold | TPR (recall) | FPR | Precision | F1 |
|---|---|---|---|---|
| 0.0 | 100.0% | 100.0% | 64.6% | 0.785 |
| 0.1 | 100.0% | 62.5% | 74.5% | 0.854 |
| 0.2 | 100.0% | 62.5% | 74.5% | 0.854 |
| 0.3 | 100.0% | 62.5% | 74.5% | 0.854 |
| 0.4 | 100.0% | 62.5% | 74.5% | 0.854 |
| 0.5 | 98.6% | 57.5% | 75.8% | 0.857 |
| 0.6 | 52.1% | 0.0% | 100.0% | 0.685 |
| 0.7 | 52.1% | 0.0% | 100.0% | 0.685 |
| 0.8 | 52.1% | 0.0% | 100.0% | 0.685 |
| 0.9 | 52.1% | 0.0% | 100.0% | 0.685 |
| 1.0 | 0.0% | 0.0% | 100.0% | 0.000 |

> The recorded scores come from the full tiered pipeline, so this sweep answers "if the only knob were the numeric block threshold, where is the best operating point?" — a sanity check on the deployed value, not a replacement for the tier logic. A rule-only run is intentionally bimodal (scores cluster at 0.0 / ~0.9), so its curve has few distinct points.
