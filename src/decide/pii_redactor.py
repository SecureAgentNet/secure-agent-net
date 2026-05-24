import logging
from typing import Dict, Any, Optional

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngine, NlpArtifacts
from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer, EmailRecognizer, PhoneRecognizer,
    UsSsnRecognizer, IpRecognizer, UsPassportRecognizer,
)
from presidio_anonymizer import AnonymizerEngine, OperatorConfig

from src.core.config import get_settings
from src.core.exceptions import PIIRedactionError

logger = logging.getLogger(__name__)

SUPPORTED_ENTITIES = [
    "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
    "IP_ADDRESS", "US_PASSPORT",
]

_analyzer: Optional[AnalyzerEngine] = None
_anonymizer: Optional[AnonymizerEngine] = None


class _NoOpNlpEngine(NlpEngine):
    def load(self) -> None:
        pass

    def is_loaded(self) -> bool:
        return True

    def get_supported_entities(self) -> set:
        return set()

    def get_supported_languages(self) -> set:
        return {"en"}

    def is_punct(self, word: str) -> bool:
        return False

    def is_stopword(self, word: str, language: str) -> bool:
        return False

    def process_text(self, text: str, language: str) -> NlpArtifacts:
        return NlpArtifacts([], [], [], [], language, "")

    def process_batch(self, texts: list, language: str) -> list:
        return [NlpArtifacts([], [], [], [], language, "") for _ in texts]


def _get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        registry = RecognizerRegistry()
        registry.add_recognizer(CreditCardRecognizer())
        registry.add_recognizer(EmailRecognizer())
        registry.add_recognizer(PhoneRecognizer())
        registry.add_recognizer(UsSsnRecognizer())
        registry.add_recognizer(IpRecognizer())
        registry.add_recognizer(UsPassportRecognizer())
        _analyzer = AnalyzerEngine(registry=registry, nlp_engine=_NoOpNlpEngine())
        recognizer_count = len(_analyzer.registry.recognizers)
        logger.info("Presidio AnalyzerEngine initialized with %d recognizers", recognizer_count)
    return _analyzer


def _get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


class PiiRedactor:
    """Tier 2 Evaluation: Redacts PII using Microsoft Presidio."""

    @classmethod
    def redact_payload(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            analyzer = _get_analyzer()
            anonymizer = _get_anonymizer()
        except Exception as e:
            raise PIIRedactionError(f"Failed to initialize Presidio: {e}") from e

        settings = get_settings()
        threshold = settings.presidio_score_threshold

        redacted = {}
        for key, value in payload.items():
            redacted[key] = cls._redact_value(value, analyzer, anonymizer, threshold)
        return redacted

    @classmethod
    def _redact_value(
        cls, value: Any, analyzer: AnalyzerEngine, anonymizer: AnonymizerEngine, threshold: float
    ) -> Any:
        if isinstance(value, str):
            return cls._redact_string(value, analyzer, anonymizer, threshold)
        if isinstance(value, dict):
            return cls.redact_payload(value)
        if isinstance(value, list):
            return [cls._redact_value(item, analyzer, anonymizer, threshold) for item in value]
        return value

    @classmethod
    def _redact_string(
        cls, text: str, analyzer: AnalyzerEngine, anonymizer: AnonymizerEngine, threshold: float
    ) -> str:
        results = analyzer.analyze(
            text=text,
            language="en",
            entities=SUPPORTED_ENTITIES,
            score_threshold=threshold,
        )
        if not results:
            return text

        operators = {
            result.entity_type: OperatorConfig(
                operator_name="replace",
                params={"new_value": f"[REDACTED_{result.entity_type}]"},
            )
            for result in results
        }

        anonymized = anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text