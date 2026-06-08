"""Authentik API client — read-only.

Used by ``/reconcile-all`` to fetch the canonical user list together with the
``shared_mailboxes`` attribute coming from each user's groups *and* the user's
own ``attributes.shared_mailboxes`` (per-user override on top of group
membership). One paginated API call per page covers user + all embedded group
attributes (the ``groups_obj`` field), so we don't issue per-user lookups.

This aggregation mirrors the OIDC scope mapping
``aggregated shared_mailboxes for mailcow`` in Authentik, so both code paths
expose the same set of mailboxes to a given user.

Configuration (env vars used by ``app/webhook.py``):
    AUTHENTIK_API_URL   — e.g. ``https://auth.example.org/api/v3``
    AUTHENTIK_API_TOKEN — Bearer token of a service-account user that has
                          ``authentik_core.view_user`` permission

The client trusts the upstream certificate by default. If the deployment uses
an internal CA, set ``AUTHENTIK_API_VERIFY=/path/to/ca.crt`` to point at a
bundle, or ``AUTHENTIK_API_VERIFY=false`` to disable verification.
"""
from __future__ import annotations

import logging
from typing import Iterator

import requests

log = logging.getLogger("sync.authentik")


class AuthentikClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        verify: bool | str = True,
        timeout: float = 30.0,
        page_size: int = 100,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.page_size = page_size
        self.s = requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        })
        self.s.verify = verify

    def list_users_raw(self) -> Iterator[dict]:
        """Yield each active User dict from ``/core/users/``, walking
        pagination via the ``pagination.next`` page number."""
        page = 1
        while True:
            url = f"{self.base_url}/core/users/"
            r = self.s.get(
                url,
                params={"page": page, "page_size": self.page_size, "is_active": "true"},
                timeout=self.timeout,
            )
            r.raise_for_status()
            data = r.json()
            for u in data.get("results", []):
                yield u
            pagination = data.get("pagination") or {}
            next_page = pagination.get("next")
            if not next_page or next_page == page:
                break
            page = next_page

    def list_users_for_sync(self, our_domain: str) -> list[dict]:
        """Return one payload per Authentik user, in the same shape that
        ``reconcile_user`` accepts. ``shared_mailboxes`` is the union of the
        user's groups' ``attributes.shared_mailboxes`` and the user's own
        ``attributes.shared_mailboxes`` (de-duped, with the user's own primary
        email removed).

        Service-account user types are skipped — they don't have human
        mailboxes to reconcile."""
        payloads: list[dict] = []
        for u in self.list_users_raw():
            email = (u.get("email") or "").strip()
            if not email:
                continue
            if not email.endswith("@" + our_domain):
                # Foreign-domain user — we never reconcile those
                continue
            if u.get("type") != "internal":
                # Skip internal_service_account, external, internal_service etc.
                continue

            mailboxes: set[str] = set()
            for g in u.get("groups_obj") or []:
                attrs = g.get("attributes") or {}
                for mb in attrs.get("shared_mailboxes") or []:
                    if isinstance(mb, str):
                        mailboxes.add(mb)
            for mb in (u.get("attributes") or {}).get("shared_mailboxes") or []:
                if isinstance(mb, str):
                    mailboxes.add(mb)
            mailboxes.discard(email)

            payloads.append({
                "username": u.get("username"),
                "email": email,
                "primary_email": email,
                "shared_mailboxes": sorted(mailboxes),
                "additional_emails": sorted(mailboxes),
            })
        log.info("authentik: fetched %d internal users in %s", len(payloads), our_domain)
        return payloads
