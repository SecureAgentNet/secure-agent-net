import hashlib
import json
import threading
import time
import logging

from secureagentnet.core.config import get_settings
from secureagentnet.decide.models import EvaluationRequest
from secureagentnet.decide.model_providers import get_provider, ProviderUnavailable

logger = logging.getLogger("SecureAgentNet.Decide")


class SemanticEvaluator:
    """
    Tier 3 Evaluation: detects complex attacks (prompt injection, data
    exfiltration, goal hijacking) by reasoning about the requested action
    against the agent's commissioned mandate.

    The underlying model is a **pluggable provider** (local Ollama, a hosted
    OpenAI-compatible API, or a small local classifier) selected by
    ``DECIDE_MODEL_PROVIDER`` — see :mod:`secureagentnet.decide.model_providers`.
    This class owns the concerns that must hold regardless of provider:

    - **Caching**: verdicts for identical requests are cached for a short TTL so
      repeated actions don't pay the model cost every time.
    - **Fail-closed**: a provider that is unreachable/unusable denies the request
      (score 1.0) and the denial is never cached, so a transient outage cannot
      keep denying after recovery.
    """

    _cache: dict = {}
    _cache_lock = threading.Lock()
    _CACHE_MAX_ENTRIES = 1024

    def __init__(self, provider=None):
        self.settings = get_settings()
        # Allow injection for tests; otherwise build from config.
        self.provider = provider or get_provider(self.settings)
        logger.info("SemanticEvaluator using model provider: %s", self.provider.name)

    @classmethod
    def clear_cache(cls):
        with cls._cache_lock:
            cls._cache.clear()

    @staticmethod
    def _cache_key(request: EvaluationRequest, redacted_payload: dict) -> str:
        material = json.dumps(
            [
                request.agent_id,
                request.action_name,
                request.target_resource,
                request.intent_summary,
                request.commissioned_goal,
                redacted_payload,
            ],
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(material.encode()).hexdigest()

    def evaluate(self, request: EvaluationRequest, redacted_payload: dict) -> tuple[float, str]:
        """
        Evaluate the request via the configured model provider.
        Returns (risk_score, reason).
        """
        ttl = getattr(self.settings, "semantic_cache_ttl", 0)
        use_cache = isinstance(ttl, (int, float)) and ttl > 0
        key = self._cache_key(request, redacted_payload)

        if use_cache:
            with self._cache_lock:
                hit = self._cache.get(key)
                if hit is not None and (time.monotonic() - hit[0]) < ttl:
                    logger.debug("Semantic verdict cache hit for %s", request.action_name)
                    return hit[1], hit[2]

        score, reason, cacheable = self._evaluate_uncached(request, redacted_payload)

        if use_cache and cacheable:
            with self._cache_lock:
                if len(self._cache) >= self._CACHE_MAX_ENTRIES:
                    oldest = min(self._cache, key=lambda k: self._cache[k][0])
                    del self._cache[oldest]
                self._cache[key] = (time.monotonic(), score, reason)

        return score, reason

    def _evaluate_uncached(self, request: EvaluationRequest,
                           redacted_payload: dict) -> tuple[float, str, bool]:
        """Delegate to the provider. Returns (risk_score, reason, cacheable).
        A provider failure fails closed (deny) and is not cached."""
        try:
            score, reason = self.provider.classify(request, redacted_payload)
            return score, reason, True
        except ProviderUnavailable as e:
            logger.error("Semantic provider '%s' unavailable: %s", self.provider.name, e)
            return 1.0, "Security Evaluator unavailable. Denying request.", False

    # Verdict/score parsing lives in `model_providers` now (shared across all
    # providers); these thin delegators keep the parsing contract addressable
    # from the evaluator for callers and tests.
    @staticmethod
    def _parse_verdict(text: str):
        from secureagentnet.decide.model_providers import parse_verdict_json
        return parse_verdict_json(text)

    @staticmethod
    def _parse_llm_response(text: str):
        from secureagentnet.decide.model_providers import _parse_legacy_score
        return _parse_legacy_score(text)
