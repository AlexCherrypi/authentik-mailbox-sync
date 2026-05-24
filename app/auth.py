"""Request-token auth for the sync webhook endpoints.

Why not a real HMAC over the body? Authentik's Generic Webhook transport can
only attach static custom headers, not dynamically compute a signature over
the payload. So we use a shared bearer token in a header instead. The private
authentik_provisioning bridge is the primary boundary; this is defense in
depth against misconfig and future topology changes.

Two separate tokens so a leaked webhook secret cannot trigger the
admin-only sweep endpoint.
"""
import hmac
import logging
import os
from functools import wraps

from flask import jsonify, request

log = logging.getLogger("sync.auth")

_HEADER = {
    "SYNC_WEBHOOK_SECRET": "X-Sync-Webhook-Token",
    "SYNC_ADMIN_TOKEN": "X-Sync-Admin-Token",
}


def require_token(env_var: str):
    """Reject the request with 401 unless the matching header carries the
    secret stored in *env_var*.

    Uses ``hmac.compare_digest`` so timing-side-channels do not leak the
    secret one byte at a time. Fails closed when the env var is unset or
    empty.
    """
    header_name = _HEADER[env_var]

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            expected = os.environ.get(env_var, "")
            sent = request.headers.get(header_name, "")
            if not expected or not hmac.compare_digest(sent, expected):
                log.warning(
                    "auth rejected: header=%s sent=%s remote=%s",
                    header_name, _redact(sent), request.remote_addr,
                )
                return jsonify({"error": "unauthorized"}), 401
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _redact(s: str) -> str:
    if not s:
        return "(none)"
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}...{s[-4:]}"
