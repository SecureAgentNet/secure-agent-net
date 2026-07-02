import json
import os
import threading
from pathlib import Path


class PersistenceStore:
    _lock = threading.Lock()

    @classmethod
    def _get_base_dir(cls) -> Path:
        install_dir = os.environ.get("INSTALL_DIR")
        if install_dir:
            base = Path(install_dir) / "data"
        else:
            base = Path.home() / ".secureagentnet" / "data"
        base.mkdir(parents=True, exist_ok=True)
        return base

    @classmethod
    def _get_path(cls, key: str) -> Path:
        return cls._get_base_dir() / f"{key}.json"

    @classmethod
    def save(cls, key: str, data):
        path = cls._get_path(key)
        with cls._lock:
            tmp = path.with_suffix(f".tmp.{os.getpid()}")
            try:
                with open(tmp, "w") as f:
                    json.dump(data, f, default=str)
                tmp.rename(path)
            finally:
                if tmp.exists():
                    tmp.unlink()

    @classmethod
    def load(cls, key: str, default=None):
        path = cls._get_path(key)
        if not path.exists():
            return default
        with cls._lock:
            try:
                with open(path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return default

    @classmethod
    def delete(cls, key: str):
        path = cls._get_path(key)
        with cls._lock:
            if path.exists():
                path.unlink()
