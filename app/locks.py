"""Per-key reentrant locks so two concurrent webhooks for the same user
serialize. Different users do not block each other.

The lock pool grows monotonically (never reclaims) which is fine for our
expected user count (≤100). If we ever scale up, swap for a TTL'd cache.
"""
import threading
from contextlib import contextmanager

_pool: dict[str, threading.Lock] = {}
_pool_lock = threading.Lock()


def _lock_for(key: str) -> threading.Lock:
    with _pool_lock:
        lock = _pool.get(key)
        if lock is None:
            lock = threading.Lock()
            _pool[key] = lock
        return lock


@contextmanager
def per_key_lock(key: str):
    lock = _lock_for(key)
    with lock:
        yield
