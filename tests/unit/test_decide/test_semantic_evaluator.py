import pytest
from unittest.mock import MagicMock, patch
from src.decide.semantic_evaluator import SemanticEvaluator
from src.decide.models import EvaluationRequest


class TestSemanticEvaluator:
    @pytest.fixture
    def evaluator(self):
        with patch("src.decide.semantic_evaluator.get_settings") as mock_get_settings:
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
