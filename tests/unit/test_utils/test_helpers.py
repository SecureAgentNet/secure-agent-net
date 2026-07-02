import pytest
from secureagentnet.utils.helpers import (
    sha256_hash,
    generate_correlation_id,
    redact_sensitive_value,
    flatten_dict,
    utc_now,
    format_timestamp,
    truncate_string,
    safe_json_loads,
    safe_json_dumps,
    calculate_execution_time_ms,
    chunk_list,
)
from datetime import datetime, timezone


class TestHelpers:
    def test_sha256_hash(self):
        result = sha256_hash("hello")
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        assert result == expected

    def test_sha256_hash_empty_string(self):
        result = sha256_hash("")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result == expected

    def test_sha256_hash_deterministic(self):
        assert sha256_hash("test") == sha256_hash("test")

    def test_generate_correlation_id(self):
        cid1 = generate_correlation_id()
        cid2 = generate_correlation_id()
        assert cid1.startswith("corr-")
        assert cid2.startswith("corr-")
        assert cid1 != cid2
        assert len(cid1) == 21

    def test_redact_sensitive_value_password(self):
        assert redact_sensitive_value("password", "mysecret123") == "[REDACTED]"

    def test_redact_sensitive_value_secret(self):
        assert redact_sensitive_value("secret_key", "super-secret") == "[REDACTED]"

    def test_redact_sensitive_value_token(self):
        assert redact_sensitive_value("access_token", "abc123") == "[REDACTED]"

    def test_redact_sensitive_value_key(self):
        assert redact_sensitive_value("api_key", "key-98765") == "[REDACTED]"

    def test_redact_sensitive_value_credential(self):
        assert redact_sensitive_value("credential", "admin:pass") == "[REDACTED]"

    def test_redact_sensitive_value_auth(self):
        assert redact_sensitive_value("authorization", "Bearer xxx") == "[REDACTED]"

    def test_redact_sensitive_value_case_insensitive(self):
        assert redact_sensitive_value("API_KEY", "value") == "[REDACTED]"
        assert redact_sensitive_value("ApiKey", "value") == "[REDACTED]"

    def test_redact_sensitive_value_non_sensitive(self):
        assert redact_sensitive_value("username", "john_doe") == "john_doe"

    def test_flatten_dict(self):
        d = {"a": 1, "b": {"c": 2, "d": {"e": 3}}}
        result = flatten_dict(d)
        assert result == {"a": 1, "b.c": 2, "b.d.e": 3}

    def test_flatten_dict_empty(self):
        assert flatten_dict({}) == {}

    def test_flatten_dict_with_separator(self):
        d = {"a": {"b": 1, "c": 2}}
        result = flatten_dict(d, sep="_")
        assert result == {"a_b": 1, "a_c": 2}

    def test_flatten_dict_non_dict_values(self):
        d = {"a": 1, "b": "hello", "c": [1, 2, 3], "d": None}
        result = flatten_dict(d)
        assert result == {"a": 1, "b": "hello", "c": [1, 2, 3], "d": None}

    def test_utc_now(self):
        now = utc_now()
        assert isinstance(now, datetime)
        assert now.tzinfo == timezone.utc

    def test_format_timestamp(self):
        dt = datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        result = format_timestamp(dt)
        assert result == "2025-01-15T10:30:00+00:00"

    def test_format_timestamp_default(self):
        result = format_timestamp()
        assert isinstance(result, str)
        assert "T" in result

    def test_truncate_string_short(self):
        assert truncate_string("hello", 10) == "hello"

    def test_truncate_string_long(self):
        s = "x" * 100
        result = truncate_string(s, 10)
        assert len(result) == 13
        assert result.endswith("...")

    def test_safe_json_loads_valid(self):
        result = safe_json_loads('{"key": "value"}')
        assert result == {"key": "value"}

    def test_safe_json_loads_invalid(self):
        assert safe_json_loads("not-json") is None

    def test_safe_json_loads_none(self):
        assert safe_json_loads(None) is None

    def test_safe_json_dumps(self):
        result = safe_json_dumps({"a": 1, "b": "hello"})
        assert result == '{"a": 1, "b": "hello"}'

    def test_safe_json_dumps_with_datetime(self):
        result = safe_json_dumps({"now": datetime(2025, 1, 1, tzinfo=timezone.utc)})
        assert "2025-01-01" in result

    def test_calculate_execution_time_ms(self):
        import time
        start = time.time()
        time.sleep(0.01)
        elapsed = calculate_execution_time_ms(start)
        assert elapsed >= 10

    def test_chunk_list(self):
        items = [1, 2, 3, 4, 5, 6, 7]
        chunks = list(chunk_list(items, 3))
        assert chunks == [[1, 2, 3], [4, 5, 6], [7]]

    def test_chunk_list_empty(self):
        assert list(chunk_list([], 3)) == []

    def test_chunk_list_exact(self):
        assert list(chunk_list([1, 2], 2)) == [[1, 2]]
