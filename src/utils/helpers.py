import json
import hashlib
import time
from typing import Any, Dict, Optional
from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def format_timestamp(dt: Optional[datetime] = None) -> str:
    if dt is None:
        dt = utc_now()
    return dt.isoformat()


def truncate_string(s: str, max_length: int = 1000) -> str:
    if len(s) <= max_length:
        return s
    return s[:max_length] + "..."


def safe_json_loads(data: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError):
        return None


def safe_json_dumps(data: Any) -> str:
    return json.dumps(data, default=str, ensure_ascii=False)


def generate_correlation_id() -> str:
    import uuid
    return f"corr-{uuid.uuid4().hex[:16]}"


def calculate_execution_time_ms(start_time: float) -> int:
    return int((time.time() - start_time) * 1000)


def redact_sensitive_value(key: str, value: str) -> str:
    sensitive_keys = {"password", "secret", "token", "key", "credential", "auth", "api_key", "apikey"}
    if any(sk in key.lower() for sk in sensitive_keys):
        return "[REDACTED]"
    return value


def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    items: Dict[str, Any] = {}
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(flatten_dict(v, new_key, sep=sep))
        else:
            items[new_key] = v
    return items


def chunk_list(lst: list, chunk_size: int):
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]
