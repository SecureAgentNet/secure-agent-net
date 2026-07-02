import json
import logging
from typing import Optional, Any
from secureagentnet.core.config import get_settings

logger = logging.getLogger("SecureAgentNet.Utils.Redis")

_redis_client = None
_redis_available = False
_redis_attempted = False


def get_redis():
    global _redis_client, _redis_available, _redis_attempted
    if _redis_client is not None:
        return _redis_client
    if _redis_attempted:
        return None
    _redis_attempted = True
    try:
        import redis as redis_mod
        settings = get_settings()
        _redis_client = redis_mod.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password or None,
            db=0,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        _redis_client.ping()
        _redis_available = True
        logger.info("Connected to Redis")
        return _redis_client
    except Exception as e:
        logger.debug(f"Redis unavailable — using in-memory fallback: {e}")
        _redis_client = None
        _redis_available = False
        return None


def is_available() -> bool:
    if _redis_client is None and not _redis_attempted:
        get_redis()
    return _redis_available


def set_value(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    client = get_redis()
    if client is None:
        return False
    try:
        serialized = json.dumps(value) if not isinstance(value, (str, bytes)) else value
        client.set(key, serialized, ex=ttl)
        return True
    except Exception as e:
        logger.debug(f"Redis set failed: {e}")
        return False


def get_value(key: str) -> Optional[Any]:
    client = get_redis()
    if client is None:
        return None
    try:
        value = client.get(key)
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    except Exception as e:
        logger.debug(f"Redis get failed: {e}")
        return None


def delete_key(key: str) -> bool:
    client = get_redis()
    if client is None:
        return False
    try:
        client.delete(key)
        return True
    except Exception as e:
        logger.debug(f"Redis delete failed: {e}")
        return False


def get_limiter_storage_uri() -> str:
    if is_available():
        settings = get_settings()
        pw = f":{settings.redis_password}@" if settings.redis_password else ""
        return f"redis://{pw}{settings.redis_host}:{settings.redis_port}/0"
    return "memory://"
