#!/usr/bin/env python3
"""Fit the small-classifier provider's weights on the labelled corpus.

Turns the DECIDE `classifier` provider's linear model from hand-set defaults into
a genuinely *fitted* logistic regression over the same interpretable features the
provider extracts at inference time. Pure-Python gradient descent — no numpy /
sklearn — so it runs anywhere.

    python scripts/fit_classifier.py            # fit + write weights + report
    python scripts/fit_classifier.py --dry-run  # fit + report, don't write

Writes `secureagentnet/decide/classifier_weights.json`, which the provider then
auto-loads. The feature extractor is imported from the provider itself, so train
and inference stay identical by construction.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from secureagentnet.decide.model_providers import (          # noqa: E402
    CLASSIFIER_FEATURES, extract_features, logistic_score, BUNDLED_WEIGHTS_PATH,
)
# Reuse the evaluation harness's corpus→request conversion so the training
# distribution matches exactly what the benchmark measures.
from run_evaluation import (                                  # noqa: E402
    DATASET_DIR, scenario_to_request, benign_to_request,
)


def _load_dataset():
    """Return (X, y) where X is a list of feature dicts and y is 0/1 labels."""
    attacks = json.loads((DATASET_DIR / "owasp_top10_scenarios.json").read_text())
    benign = json.loads((DATASET_DIR / "benign_corpus.json").read_text())["requests"]

    X, y = [], []
    for s in attacks:
        r = scenario_to_request(s, ablate_mandate=False)
        X.append(extract_features(r.action_name, r.target_resource or "",
                                  r.intent_summary or "", r.payload, r.commissioned_goal))
        y.append(1)
    for b in benign:
        r = benign_to_request(b, ablate_mandate=False)
        X.append(extract_features(r.action_name, r.target_resource or "",
                                  r.intent_summary or "", r.payload, r.commissioned_goal))
        y.append(0)
    return X, y


def fit_logistic(X, y, epochs=4000, lr=0.3, l2=0.01):
    """Batch gradient descent with L2 regularisation. Returns a weights dict
    ({'_bias': b, feature: w, ...}) in the format the provider loads."""
    w = {f: 0.0 for f in CLASSIFIER_FEATURES}
    b = 0.0
    n = len(X)
    for _ in range(epochs):
        gw = {f: 0.0 for f in CLASSIFIER_FEATURES}
        gb = 0.0
        for feats, label in zip(X, y):
            z = b + sum(w[f] * feats.get(f, 0.0) for f in CLASSIFIER_FEATURES)
            p = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))
            err = p - label
            for f in CLASSIFIER_FEATURES:
                gw[f] += err * feats.get(f, 0.0)
            gb += err
        for f in CLASSIFIER_FEATURES:
            w[f] -= lr * (gw[f] / n + l2 * w[f])
        b -= lr * (gb / n)

    weights = {"_bias": round(b, 4)}
    for f in CLASSIFIER_FEATURES:
        weights[f] = round(w[f], 4)
    return weights


def evaluate(X, y, weights, block_threshold=0.7):
    """Report accuracy / detection / false-positive on the training corpus."""
    tp = fp = tn = fn = 0
    for feats, label in zip(X, y):
        p = logistic_score(feats, weights)
        pred = 1 if p >= block_threshold else 0
        if label == 1:
            tp += pred
            fn += 1 - pred
        else:
            fp += pred
            tn += 1 - pred
    attacks = tp + fn
    benign = tn + fp
    return {
        "attacks": attacks, "benign": benign,
        "detection_rate": tp / attacks if attacks else 0.0,
        "false_positive_rate": fp / benign if benign else 0.0,
        "accuracy": (tp + tn) / (attacks + benign) if (attacks + benign) else 0.0,
    }


def cross_validate(X, y, k=5, threshold=0.7):
    """Stratified k-fold CV → an honest, held-out estimate (train-set metrics are
    optimistic). Folds are interleaved within each class to keep them balanced."""
    idx_pos = [i for i, v in enumerate(y) if v == 1]
    idx_neg = [i for i, v in enumerate(y) if v == 0]
    folds = [[] for _ in range(k)]
    for j, i in enumerate(idx_pos):
        folds[j % k].append(i)
    for j, i in enumerate(idx_neg):
        folds[j % k].append(i)

    agg = {"detection_rate": [], "false_positive_rate": [], "accuracy": []}
    for f in range(k):
        test_idx = set(folds[f])
        Xtr = [X[i] for i in range(len(X)) if i not in test_idx]
        ytr = [y[i] for i in range(len(y)) if i not in test_idx]
        Xte = [X[i] for i in test_idx]
        yte = [y[i] for i in test_idx]
        w = fit_logistic(Xtr, ytr)
        m = evaluate(Xte, yte, w, threshold)
        for key in agg:
            agg[key].append(m[key])
    return {key: sum(vals) / len(vals) for key, vals in agg.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="fit + report but don't write")
    ap.add_argument("--threshold", type=float, default=0.7,
                    help="block threshold for the report (matches BLOCK_THRESHOLD)")
    args = ap.parse_args()

    X, y = _load_dataset()
    print(f"Corpus: {sum(y)} attacks + {len(y) - sum(y)} benign = {len(y)} examples")

    weights = fit_logistic(X, y)
    metrics = evaluate(X, y, weights, args.threshold)

    print("\nFitted weights (logistic):")
    for k, v in sorted(weights.items(), key=lambda kv: -abs(kv[1])):
        print(f"  {k:20s} {v:+.3f}")

    print(f"\nOn the training corpus @ threshold {args.threshold} (optimistic):")
    print(f"  detection rate      : {metrics['detection_rate']*100:.1f}% "
          f"({metrics['attacks']} attacks)")
    print(f"  false-positive rate : {metrics['false_positive_rate']*100:.1f}% "
          f"({metrics['benign']} benign)")
    print(f"  accuracy            : {metrics['accuracy']*100:.1f}%")

    cv = cross_validate(X, y, k=5, threshold=args.threshold)
    print(f"\n5-fold cross-validated (held-out, honest estimate):")
    print(f"  detection rate      : {cv['detection_rate']*100:.1f}%")
    print(f"  false-positive rate : {cv['false_positive_rate']*100:.1f}%")
    print(f"  accuracy            : {cv['accuracy']*100:.1f}%")

    if args.dry_run:
        print("\n--dry-run: not writing weights.")
        return

    payload = dict(weights)
    payload["_trained_examples"] = len(y)  # numeric provenance (provider ignores non-numeric)
    BUNDLED_WEIGHTS_PATH.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"\nWrote fitted weights → {BUNDLED_WEIGHTS_PATH}")
    print("The `classifier` provider will auto-load these on next start.")


if __name__ == "__main__":
    main()
