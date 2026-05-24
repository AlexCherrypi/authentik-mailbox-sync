"""Direct Mailcow-DB reads / writes for fields the REST API doesn't expose.

Used for ``sender_acl`` reads (the API exposes the write side via
``edit/mailbox`` but no matching read endpoint) and later for SOGo
``c_settings`` writes (Task 006 — ``sogo-tool`` is broken in the mailcow
container layout, see mailcow/mailcow-dockerized#6355).
"""
import logging
from contextlib import contextmanager

import pymysql

log = logging.getLogger("sync.mailcow.db")


class MailcowDB:
    def __init__(self, host: str, user: str, password: str, database: str,
                 port: int = 3306):
        self._conn_kwargs = dict(
            host=host, user=user, password=password, database=database,
            port=port, charset="utf8mb4", autocommit=False,
            cursorclass=pymysql.cursors.DictCursor,
        )

    @contextmanager
    def conn(self):
        c = pymysql.connect(**self._conn_kwargs)
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # ---- sender_acl read -------------------------------------------------
    #
    # DB schema vs API: Mailcow's ``POST /edit/mailbox {items: [X],
    # attr: {sender_acl: [Y]}}`` writes a row ``(logged_in_as=X, send_as=Y)``.
    # So to mirror what the API would return for "mailbox X's sender_acl",
    # we group by ``logged_in_as`` and collect ``send_as`` values.

    def get_sender_acl(self, mailbox: str) -> set[str]:
        """Return the sender_acl list for *mailbox* — i.e. the users that the
        Mailcow API ``edit/mailbox`` call with ``items=[mailbox]`` would set
        when given ``attr.sender_acl=[...]``."""
        with self.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT send_as FROM sender_acl "
                    "WHERE logged_in_as = %s AND external = 0",
                    (mailbox,),
                )
                return {r["send_as"] for r in cur.fetchall()}

    def get_all_sender_acls(self) -> dict[str, set[str]]:
        """Return ``{mailbox: {user, ...}}`` for every entry in the table —
        cheaper than per-mailbox queries when we already iterate all
        mailboxes."""
        out: dict[str, set[str]] = {}
        with self.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT logged_in_as, send_as FROM sender_acl "
                    "WHERE external = 0"
                )
                for r in cur.fetchall():
                    out.setdefault(r["logged_in_as"], set()).add(r["send_as"])
        return out
