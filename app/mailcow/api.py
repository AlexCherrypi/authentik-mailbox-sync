"""Thin wrapper around the Mailcow REST API.

Skelett-Phase: only what's needed for /healthz (list_mailboxes). Add/delete
app-password + sender_acl methods land in Task 004/005.
"""
import requests


class MailcowClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"X-API-Key": self.api_key, "Accept": "application/json"}

    def list_mailboxes(self) -> list[dict]:
        r = requests.get(
            f"{self.base_url}/api/v1/get/mailbox/all",
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()
