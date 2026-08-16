"""Signature / salutation templates for the ``/my-accounts`` endpoint (D-007).

The two salutation variants ("Firmenanrede" / "persoenliche Anrede") live in a
server-side JSON config file that is **mounted into the AMS container as a
volume** and **read fresh on every request** — so wording/footers can be
changed without a tool update and without an AMS rebuild.

The templates are delivered *raw*: the ``{{name}}`` placeholder is intentionally
NOT substituted here. The client tool fills it in with the real user name from
the OIDC claims (D-007: the identity/fullName is a client-side concern, and the
server never needs to know the display name it should render). Keeping the
server dumb about names also means the same cached template survives every user
and the endpoint stays a pure lookup.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("sync.signatures")

DEFAULT_SIGNATURES_CONFIG_PATH = "/config/signatures.json"

# The two variant keys the client UI dropdown maps onto (D-007).
REQUIRED_KEYS = ("firmenanrede", "persoenliche_anrede")


class SignaturesError(RuntimeError):
    """Raised when the signatures config file is missing or malformed."""


def load_signatures(path: str) -> dict:
    """Read and validate the signatures config from *path*.

    Read on every call (never cached) so edits to the mounted file take effect
    immediately. Raises :class:`SignaturesError` on any problem so the caller
    can turn it into a clean 503 instead of a 500/stacktrace.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SignaturesError(f"signatures config not found: {path}") from exc
    except OSError as exc:
        raise SignaturesError(f"signatures config unreadable: {path}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SignaturesError(f"signatures config is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise SignaturesError("signatures config must be a JSON object")

    for key in REQUIRED_KEYS:
        variant = data.get(key)
        if not isinstance(variant, dict):
            raise SignaturesError(f"signatures config missing/invalid variant: {key!r}")
        if "html" not in variant:
            raise SignaturesError(f"signatures variant {key!r} missing 'html'")

    return data
