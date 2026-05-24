"""SOGo user-profile settings (``sogo_user_profile.c_settings``).

We write SOGo's ``Mail.DelegateFrom`` / ``Mail.DelegateTo`` /
``Mail.OtherUsersFolders`` keys directly because ``sogo-tool
user-preferences`` doesn't work in Mailcow's container layout
(see https://github.com/mailcow/mailcow-dockerized/issues/6355) and the
SOGo 5.12.2+ HTTP API has no preferences endpoint either.

To stay safe we touch only the keys we manage; the rest of the Mail
subtree (ExpandedFolders, Drafts, etc.) is preserved by a read-modify-write
inside a single transaction.
"""
import json
import logging
from typing import Iterable, Optional

log = logging.getLogger("sync.sogo")


class SogoPrefsError(RuntimeError):
    pass


class SogoPrefs:
    """Atomic accessors for the SOGo Mail-settings subtree.

    The DB connection comes from a ``MailcowDB``-shaped object that exposes
    a ``conn()`` context manager yielding a PyMySQL connection."""

    def __init__(self, db):
        self.db = db

    # ---- read ------------------------------------------------------------

    def get_mail_settings(self, c_uid: str) -> dict:
        with self.db.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT c_settings FROM sogo_user_profile WHERE c_uid = %s",
                    (c_uid,),
                )
                row = cur.fetchone()
        if not row or not row.get("c_settings"):
            return {}
        try:
            return (json.loads(row["c_settings"]) or {}).get("Mail") or {}
        except json.JSONDecodeError:
            log.warning("c_settings for %s is not valid JSON", c_uid)
            return {}

    def get_all_delegate_to(self) -> dict[str, set[str]]:
        """``{mailbox: {users in DelegateTo}}`` over every row in
        ``sogo_user_profile``. Mirrors what SOGo's UI shows in "Mail →
        Delegation"."""
        out: dict[str, set[str]] = {}
        with self.db.conn() as c:
            with c.cursor() as cur:
                cur.execute("SELECT c_uid, c_settings FROM sogo_user_profile")
                for row in cur.fetchall():
                    if not row.get("c_settings"):
                        continue
                    try:
                        s = json.loads(row["c_settings"]) or {}
                    except json.JSONDecodeError:
                        continue
                    dt = (s.get("Mail") or {}).get("DelegateTo") or []
                    if dt:
                        out[row["c_uid"]] = set(dt)
        return out

    def get_delegate_from(self, c_uid: str) -> set[str]:
        return set(self.get_mail_settings(c_uid).get("DelegateFrom") or [])

    # ---- write -----------------------------------------------------------

    def set_user_delegate_from(self, c_uid: str,
                               delegate_from: Iterable[str]) -> bool:
        """Set ``Mail.DelegateFrom`` AND ``Mail.OtherUsersFolders`` (they are
        kept in sync — SOGo uses OtherUsersFolders for the IMAP-tree pane,
        DelegateFrom for the compose From-dropdown). Returns True iff
        anything changed."""
        wanted = sorted(set(delegate_from))
        return self._patch(c_uid, {
            "DelegateFrom": wanted,
            "OtherUsersFolders": wanted,
        })

    def add_user_to_mailbox_delegate_to(self, mailbox: str,
                                       user_email: str) -> bool:
        return self._patch_list_add(mailbox, "DelegateTo", user_email)

    def remove_user_from_mailbox_delegate_to(self, mailbox: str,
                                            user_email: str) -> bool:
        return self._patch_list_remove(mailbox, "DelegateTo", user_email)

    # ---- internal helpers -----------------------------------------------

    def _patch(self, c_uid: str, mail_patch: dict) -> bool:
        """Atomic read-modify-write: apply *mail_patch* to the ``Mail`` subtree
        of *c_uid*'s settings. Returns True if anything actually changed."""
        with self.db.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT c_settings FROM sogo_user_profile WHERE c_uid = %s FOR UPDATE",
                    (c_uid,),
                )
                row = cur.fetchone()
                settings = self._parse_settings(row)
                mail = settings.setdefault("Mail", {})
                changed = False
                for k, v in mail_patch.items():
                    if mail.get(k) != v:
                        mail[k] = v
                        changed = True
                if not changed:
                    return False
                self._upsert(cur, c_uid, settings)
        return True

    def _patch_list_add(self, c_uid: str, key: str, value: str) -> bool:
        with self.db.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT c_settings FROM sogo_user_profile WHERE c_uid = %s FOR UPDATE",
                    (c_uid,),
                )
                row = cur.fetchone()
                settings = self._parse_settings(row)
                mail = settings.setdefault("Mail", {})
                current = set(mail.get(key) or [])
                if value in current:
                    return False
                current.add(value)
                mail[key] = sorted(current)
                self._upsert(cur, c_uid, settings)
        return True

    def _patch_list_remove(self, c_uid: str, key: str, value: str) -> bool:
        with self.db.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "SELECT c_settings FROM sogo_user_profile WHERE c_uid = %s FOR UPDATE",
                    (c_uid,),
                )
                row = cur.fetchone()
                if not row:
                    return False
                settings = self._parse_settings(row)
                mail = settings.get("Mail") or {}
                current = set(mail.get(key) or [])
                if value not in current:
                    return False
                current.discard(value)
                mail[key] = sorted(current)
                settings["Mail"] = mail
                self._upsert(cur, c_uid, settings)
        return True

    @staticmethod
    def _parse_settings(row: Optional[dict]) -> dict:
        if not row or not row.get("c_settings"):
            return {}
        try:
            return json.loads(row["c_settings"]) or {}
        except json.JSONDecodeError:
            log.warning("c_settings is not valid JSON, treating as empty")
            return {}

    @staticmethod
    def _upsert(cursor, c_uid: str, settings: dict) -> None:
        cursor.execute(
            """
            INSERT INTO sogo_user_profile (c_uid, c_settings)
            VALUES (%s, %s)
            ON DUPLICATE KEY UPDATE c_settings = VALUES(c_settings)
            """,
            (c_uid, json.dumps(settings, separators=(",", ":"))),
        )
