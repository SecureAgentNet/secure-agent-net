"""Owner-only JSON state store.

Everything the framework persists here is private to the endpoint's owner, and
one of the files is the Ed25519 trust-root private key that the entire IDENTIFY
phase verifies against. Written at the default umask these land world-readable,
so any local user could read the root key, sign a manifest for any agent and
walk straight through the trust chain.

Both the directory and every file are therefore created owner-only, and the
mode is re-asserted on existing files so an install created before this change
is repaired the first time it writes.
"""
import json
import os
import stat
import threading
from pathlib import Path

DIR_MODE = 0o700    # rwx------
FILE_MODE = 0o600   # rw-------


class PersistenceStore:
    _lock = threading.Lock()

    @classmethod
    def _get_base_dir(cls) -> Path:
        install_dir = os.environ.get("INSTALL_DIR")
        if install_dir:
            base = Path(install_dir) / "data"
        else:
            base = Path.home() / ".secureagentnet" / "data"
        base.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
        cls._restrict(base, DIR_MODE)
        return base

    @staticmethod
    def _restrict(path: Path, mode: int) -> None:
        """Narrow the mode if it is currently wider. Never widens, never raises.

        ``mkdir`` only applies its mode when it actually creates the directory,
        and a file written before this change keeps whatever mode it had, so the
        permission has to be asserted rather than assumed.
        """
        try:
            current = stat.S_IMODE(path.stat().st_mode)
            if current & ~mode:
                path.chmod(mode)
        except OSError:
            # A read-only mount or a foreign owner is not a reason to lose state.
            pass

    @classmethod
    def _get_path(cls, key: str) -> Path:
        return cls._get_base_dir() / f"{key}.json"

    @classmethod
    def save(cls, key: str, data):
        path = cls._get_path(key)
        with cls._lock:
            tmp = path.with_suffix(f".tmp.{os.getpid()}")
            try:
                # Create the temp file owner-only from the outset: writing it at
                # the default umask and chmod-ing afterwards leaves a window in
                # which the contents are readable.
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
                with os.fdopen(fd, "w") as f:
                    json.dump(data, f, default=str)
                tmp.replace(path)
                cls._restrict(path, FILE_MODE)
            finally:
                if tmp.exists():
                    tmp.unlink()

    @classmethod
    def load(cls, key: str, default=None):
        path = cls._get_path(key)
        if not path.exists():
            return default
        with cls._lock:
            cls._restrict(path, FILE_MODE)
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

    @classmethod
    def repair_permissions(cls) -> int:
        """Re-assert owner-only on the store. Returns how many paths were narrowed."""
        base = cls._get_base_dir()
        fixed = 0
        for path in [base, *base.glob("*.json")]:
            mode = FILE_MODE if path.is_file() else DIR_MODE
            try:
                if stat.S_IMODE(path.stat().st_mode) & ~mode:
                    path.chmod(mode)
                    fixed += 1
            except OSError:
                pass
        return fixed
