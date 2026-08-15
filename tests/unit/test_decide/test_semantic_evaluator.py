import pytest
from unittest.mock import MagicMock, patch
from secureagentnet.decide.semantic_evaluator import SemanticEvaluator
from secureagentnet.decide.models import EvaluationRequest


class TestSemanticEvaluator:
    @pytest.fixture
    def evaluator(self):
        with patch("secureagentnet.decide.semantic_evaluator.get_settings") as mock_get_settings:
            settings = MagicMock()
            settings.ollama_api_url = "http://localhost:11434/api/generate"
            settings.ollama_model = "llama2:test"
            settings.ollama_timeout = 15
            settings.ollama_retry_count = 2
            mock_get_settings.return_value = settings
            yield SemanticEvaluator()

    @pytest.fixture
    def sample_request(self):
        return EvaluationRequest(
            agent_id="agent-1",
            action_name="read_file",
            target_resource="/tmp/data.txt",
            intent_summary="Reading file for analysis",
            payload={"path": "/tmp/data.txt"},
        )

    def test_parse_llm_response_safe(self, evaluator):
        text = "SCORE: 0.05\nREASON: This is a benign file read operation."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 0.05
        assert reason == "This is a benign file read operation."

    def test_parse_llm_response_malicious(self, evaluator):
        text = "SCORE: 0.95\nREASON: High risk of data exfiltration detected."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 0.95
        assert reason == "High risk of data exfiltration detected."

    def test_parse_llm_response_max_score(self, evaluator):
        text = "SCORE: 1.0\nREASON: Critical attack detected."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 1.0

    def test_parse_llm_response_min_score(self, evaluator):
        text = "SCORE: 0.0\nREASON: Nothing suspicious."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 0.0

    def test_parse_llm_response_clamps_above_one(self, evaluator):
        text = "SCORE: 1.5\nREASON: Over max."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 1.0

    def test_parse_llm_response_clamps_below_zero(self, evaluator):
        text = "SCORE: -0.5\nREASON: Under min."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 0.0

    def test_parse_llm_response_malformed(self, evaluator):
        text = "This is not a valid response with SCORE and REASON format."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 1.0
        assert reason == "Failed to parse LLM response securely. Denying by default."

    def test_parse_llm_response_partial_malformed(self, evaluator):
        text = "SCORE: 0.3\nSome random text without REASON"
        score, reason = evaluator._parse_llm_response(text)
        assert score == 0.3
        assert reason == "Failed to parse LLM response securely. Denying by default."

    def test_parse_llm_response_case_insensitive(self, evaluator):
        text = "score: 0.1\nreason: This is safe."
        score, reason = evaluator._parse_llm_response(text)
        assert score == 0.1
        assert reason == "This is safe."

    def test_parse_llm_response_only_score(self, evaluator):
        text = "SCORE: 0.8"
        score, reason = evaluator._parse_llm_response(text)
        assert score == 0.8

    def test_evaluate_returns_safe(self, evaluator, sample_request):
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"response": "SCORE: 0.1\nREASON: Safe request."}
            mock_post.return_value = mock_response

            score, reason = evaluator.evaluate(sample_request, {"path": "/tmp/data.txt"})
            assert score == 0.1
            assert "Safe request" in reason

    def test_evaluate_uses_deterministic_decoding(self, evaluator):
        """A security verdict must be reproducible, so the LLM call pins greedy
        decoding (temperature 0) and a fixed seed rather than sampling."""
        evaluator.provider.settings.decide_temperature = 0.0
        evaluator.provider.settings.decide_seed = 42
        # Unique request so the Tier-3 verdict cache can't serve a prior result.
        req = EvaluationRequest(
            agent_id="agent-det", action_name="read_file",
            target_resource="/tmp/unique-determinism-probe.txt",
            intent_summary="deterministic decoding probe",
            payload={"path": "/tmp/unique-determinism-probe.txt"})
        with patch("requests.post") as mock_post:
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"response": '{"verdict":"SAFE","confidence":0.9,"reason":"ok"}'}
            mock_post.return_value = resp
            evaluator.evaluate(req, {"path": "/tmp/unique-determinism-probe.txt"})
            options = mock_post.call_args.kwargs["json"]["options"]
            assert options["temperature"] == 0.0
            assert options["seed"] == 42

    def test_evaluate_fail_closes(self, evaluator, sample_request):
        import requests
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("LLM unavailable")
            score, reason = evaluator.evaluate(sample_request, {})
            assert score == 1.0
            assert "Security Evaluator unavailable" in reason

    def test_evaluate_http_error(self, evaluator, sample_request):
        import requests
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("HTTP 500")
            mock_post.return_value = mock_response

            score, reason = evaluator.evaluate(sample_request, {})
            assert score == 1.0
            assert "unavailable" in reason

    def test_evaluate_timeout(self, evaluator, sample_request):
        import requests
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.Timeout("Request timed out")
            score, reason = evaluator.evaluate(sample_request, {})
            assert score == 1.0

    # --- JSON verdict format ---

    def test_parse_verdict_safe_confident(self, evaluator):
        parsed = evaluator._parse_verdict(
            '{"verdict": "SAFE", "confidence": 1.0, "reason": "Routine read."}')
        assert parsed is not None
        score, reason = parsed
        assert score == 0.0
        assert reason == "Routine read."

    def test_parse_verdict_safe_unsure_stays_below_hitl(self, evaluator):
        score, _ = evaluator._parse_verdict('{"verdict": "SAFE", "confidence": 0.0}')
        assert score <= 0.2

    def test_parse_verdict_suspicious_lands_in_hitl_band(self, evaluator):
        score, _ = evaluator._parse_verdict(
            '{"verdict": "suspicious", "confidence": 0.5, "reason": "Unusual."}')
        assert 0.4 <= score <= 0.6

    def test_parse_verdict_malicious_meets_block_threshold(self, evaluator):
        score, reason = evaluator._parse_verdict(
            '{"verdict": "MALICIOUS", "confidence": 0.0, "reason": "Exfiltration."}')
        assert score >= 0.8  # always blocked even at zero confidence

    def test_parse_verdict_invalid_returns_none(self, evaluator):
        assert evaluator._parse_verdict("SCORE: 0.5\nREASON: legacy") is None
        assert evaluator._parse_verdict('{"verdict": "BANANA"}') is None
        assert evaluator._parse_verdict('["not", "a", "dict"]') is None
        assert evaluator._parse_verdict("") is None

    def test_evaluate_prefers_json_verdict(self, evaluator, sample_request):
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "response": '{"verdict": "MALICIOUS", "confidence": 1.0, "reason": "Attack."}'}
            mock_post.return_value = mock_response
            score, reason = evaluator.evaluate(sample_request, {"path": "/tmp/x"})
            assert score == 1.0
            assert reason == "Attack."

    # --- verdict cache ---

    @pytest.fixture
    def caching_evaluator(self):
        from secureagentnet.decide.semantic_evaluator import SemanticEvaluator
        with patch("secureagentnet.decide.semantic_evaluator.get_settings") as mock_get_settings:
            settings = MagicMock()
            settings.ollama_api_url = "http://localhost:11434/api/generate"
            settings.ollama_model = "llama2:test"
            settings.ollama_timeout = 15
            settings.ollama_retry_count = 0
            settings.semantic_cache_ttl = 300
            mock_get_settings.return_value = settings
            SemanticEvaluator.clear_cache()
            yield SemanticEvaluator()
            SemanticEvaluator.clear_cache()

    def test_identical_requests_hit_cache(self, caching_evaluator, sample_request):
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "response": '{"verdict": "SAFE", "confidence": 1.0, "reason": "ok"}'}
            mock_post.return_value = mock_response

            first = caching_evaluator.evaluate(sample_request, {"path": "/tmp/data.txt"})
            second = caching_evaluator.evaluate(sample_request, {"path": "/tmp/data.txt"})
            assert first == second
            assert mock_post.call_count == 1

    def test_different_payloads_miss_cache(self, caching_evaluator, sample_request):
        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "response": '{"verdict": "SAFE", "confidence": 1.0, "reason": "ok"}'}
            mock_post.return_value = mock_response

            caching_evaluator.evaluate(sample_request, {"path": "/tmp/a"})
            caching_evaluator.evaluate(sample_request, {"path": "/tmp/b"})
            assert mock_post.call_count == 2

    def test_fail_closed_result_is_not_cached(self, caching_evaluator, sample_request):
        import requests
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.exceptions.ConnectionError("down")
            score, _ = caching_evaluator.evaluate(sample_request, {"path": "/tmp/data.txt"})
            assert score == 1.0

        with patch("requests.post") as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "response": '{"verdict": "SAFE", "confidence": 1.0, "reason": "ok"}'}
            mock_post.return_value = mock_response
            score, _ = caching_evaluator.evaluate(sample_request, {"path": "/tmp/data.txt"})
            assert score == 0.0  # recovered — the transient deny was not cached
            assert mock_post.call_count == 1
