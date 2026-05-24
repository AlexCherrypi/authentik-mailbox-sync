"""SQLite-based state DB for the reconciler.

Tracks which Mailcow-App-Passwords and Nextcloud-Mail-Accounts were created by
this service for which (user_email, target_email) pair, so we can identify our
own objects later for cleanup.
"""
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS reconciler_mailboxes (
    user_email           TEXT NOT NULL,
    target_email         TEXT NOT NULL,
    mailcow_app_pwd_id   INTEGER,
    nc_account_id        INTEGER,
    first_seen           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_email, target_email)
);
CREATE INDEX IF NOT EXISTS idx_reconciler_mailboxes_user
    ON reconciler_mailboxes(user_email);

CREATE TABLE IF NOT EXISTS reconciler_users_seen (
    user_email TEXT PRIMARY KEY,
    last_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def _set_wal_with_retry(c: sqlite3.Connection, attempts: int = 10, delay: float = 0.2) -> None:
    """journal_mode=WAL needs an exclusive lock; multiple gunicorn workers racing
    on first boot all try to set it. Retry until one wins and the rest see the
    persisted setting."""
    for i in range(attempts):
        try:
            c.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or i == attempts - 1:
                raise
            time.sleep(delay * (1 + i))


class StateDB:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(str(self.path), isolation_level="DEFERRED", timeout=10.0)
        c.row_factory = sqlite3.Row
        _set_wal_with_retry(c)
        c.execute("PRAGMA foreign_keys=ON")
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()
