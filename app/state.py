"""SQLite-based state DB for the sync service.

Tracks which Mailcow app-passwords and Nextcloud-Mail accounts were created
by this service for which ``(user_email, target_email)`` pair, so we can
identify our own objects later for cleanup without touching user-created
objects.
"""
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_mailboxes (
    user_email           TEXT NOT NULL,
    target_email         TEXT NOT NULL,
    mailcow_app_pwd_id   INTEGER,
    nc_account_id        INTEGER,
    first_seen           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_email, target_email)
);
CREATE INDEX IF NOT EXISTS idx_sync_mailboxes_user
    ON sync_mailboxes(user_email);

CREATE TABLE IF NOT EXISTS sync_users_seen (
    user_email TEXT PRIMARY KEY,
    last_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


@dataclass
class MailboxRow:
    user_email: str
    target_email: str
    mailcow_app_pwd_id: Optional[int]
    nc_account_id: Optional[int]
    first_seen: str
    last_seen: str

    @classmethod
    def from_sqlite(cls, row) -> "MailboxRow":
        return cls(
            user_email=row["user_email"],
            target_email=row["target_email"],
            mailcow_app_pwd_id=row["mailcow_app_pwd_id"],
            nc_account_id=row["nc_account_id"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )


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

    # ---- mailbox CRUD ----------------------------------------------------

    def get_for_user(self, user_email: str) -> list[MailboxRow]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM sync_mailboxes WHERE user_email = ? ORDER BY target_email",
                (user_email,),
            ).fetchall()
        return [MailboxRow.from_sqlite(r) for r in rows]

    def get(self, user_email: str, target_email: str) -> Optional[MailboxRow]:
        with self.conn() as c:
            row = c.execute(
                "SELECT * FROM sync_mailboxes WHERE user_email = ? AND target_email = ?",
                (user_email, target_email),
            ).fetchone()
        return MailboxRow.from_sqlite(row) if row else None

    def upsert(
        self,
        user_email: str,
        target_email: str,
        *,
        mailcow_app_pwd_id: Optional[int] = None,
        nc_account_id: Optional[int] = None,
    ) -> None:
        with self.conn() as c:
            c.execute(
                """
                INSERT INTO sync_mailboxes (user_email, target_email,
                                            mailcow_app_pwd_id, nc_account_id)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_email, target_email) DO UPDATE SET
                    mailcow_app_pwd_id = COALESCE(excluded.mailcow_app_pwd_id, mailcow_app_pwd_id),
                    nc_account_id      = COALESCE(excluded.nc_account_id,      nc_account_id),
                    last_seen          = CURRENT_TIMESTAMP
                """,
                (user_email, target_email, mailcow_app_pwd_id, nc_account_id),
            )

    def delete(self, user_email: str, target_email: str) -> None:
        with self.conn() as c:
            c.execute(
                "DELETE FROM sync_mailboxes WHERE user_email = ? AND target_email = ?",
                (user_email, target_email),
            )

    # ---- user tracking ---------------------------------------------------

    def touch_user(self, user_email: str) -> None:
        with self.conn() as c:
            c.execute(
                """
                INSERT INTO sync_users_seen (user_email) VALUES (?)
                ON CONFLICT(user_email) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
                """,
                (user_email,),
            )

    def known_users(self) -> list[str]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT user_email FROM sync_users_seen ORDER BY user_email"
            ).fetchall()
        return [r["user_email"] for r in rows]
