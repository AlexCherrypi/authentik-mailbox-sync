"""Thin wrapper around the Mailcow REST API."""
import logging
from typing import Iterable, Optional

import requests

log = logging.getLogger("sync.mailcow")


class MailcowError(RuntimeError):
    pass


class MailcowClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {
            "X-API-Key": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ---- read ------------------------------------------------------------

    def list_mailboxes(self) -> list[dict]:
        r = requests.get(
            f"{self.base_url}/api/v1/get/mailbox/all",
            headers=self._headers(), timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    def get_mailbox(self, mailbox: str) -> Optional[dict]:
        r = requests.get(
            f"{self.base_url}/api/v1/get/mailbox/{mailbox}",
            headers=self._headers(), timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            return data[0] if data else None
        # mailcow returns the dict directly for a single-mailbox query in some versions
        return data or None

    def list_app_passwds(self, mailbox: str) -> list[dict]:
        r = requests.get(
            f"{self.base_url}/api/v1/get/app-passwd/all/{mailbox}",
            headers=self._headers(), timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        return data if isinstance(data, list) else []

    # ---- write -----------------------------------------------------------

    def add_app_passwd(
        self,
        mailbox: str,
        app_name: str,
        password: str,
        protocols: Iterable[str] = ("imap_access", "smtp_access"),
    ) -> int:
        """Create an app password and return its numeric id.

        Mailcow's POST response wraps the new id in ``log.id`` but the schema
        varies across versions, so we list-and-find after the create as the
        reliable path."""
        payload = {
            "active": "1",
            "username": mailbox,
            "app_name": app_name,
            "app_passwd": password,
            "app_passwd2": password,
            "protocols": list(protocols),
        }
        r = requests.post(
            f"{self.base_url}/api/v1/add/app-passwd",
            headers=self._headers(), json=payload, timeout=self.timeout,
        )
        r.raise_for_status()
        # Find our entry by name
        for ap in self.list_app_passwds(mailbox):
            if ap.get("name") == app_name:
                try:
                    return int(ap["id"])
                except (KeyError, ValueError, TypeError) as e:
                    raise MailcowError(
                        f"app_passwd {app_name} found but id invalid: {ap}"
                    ) from e
        raise MailcowError(
            f"add_app_passwd for {mailbox}/{app_name} succeeded but new entry not found"
        )

    def delete_app_passwd(self, ids: list[int]) -> None:
        ids = [int(i) for i in ids if i is not None]
        if not ids:
            return
        r = requests.post(
            f"{self.base_url}/api/v1/delete/app-passwd",
            headers=self._headers(), json=ids, timeout=self.timeout,
        )
        r.raise_for_status()

    def edit_mailbox_sender_acl(self, mailbox: str, sender_acl: list[str]) -> None:
        """Set sender_acl to the given full list (full replace)."""
        payload = {
            "items": [mailbox],
            "attr": {"sender_acl": list(sender_acl)},
        }
        r = requests.post(
            f"{self.base_url}/api/v1/edit/mailbox",
            headers=self._headers(), json=payload, timeout=self.timeout,
        )
        r.raise_for_status()
