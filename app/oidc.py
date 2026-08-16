"""OIDC access-token validation for the ``/my-accounts`` endpoint.

Unlike the shared-bearer-token auth in ``app/auth.py`` (used by the internal
Authentik webhook), ``/my-accounts`` is called by an end-user tool that carries
a per-user OAuth2 access token. We validate that JWT *locally* against the
identity provider's published JWKS — no round-trip to Authentik per request:

- signature (RS256) verified against the provider's JWKS (cached by PyJWT's
  ``PyJWKClient``, refreshed automatically on key rotation / unknown ``kid``)
- ``iss`` must equal the configured issuer
- ``aud`` must equal the configured audience (= client_id of the setup
  provider, so tokens minted for any *other* Authentik application are worthless
  here)
- ``exp`` / ``nbf`` / ``iat`` checked by PyJWT (``exp`` is required)

Everything is fail-closed: an unconfigured validator, a missing/blank bearer
header or any validation error results in a rejection, never a pass-through.
"""
from __future__ import annotations

import logging
from functools import wraps
from typing import Optional

import jwt
from flask import g, jsonify, request

log = logging.getLogger("sync.oidc")


class OidcError(RuntimeError):
    """Raised when a bearer token cannot be validated."""


class OidcValidator:
    """Validate RS256 access-JWTs against a provider's JWKS.

    ``verify=False`` disables signature + claim verification entirely; it exists
    only as an explicit escape hatch for local development and is never the
    default. In that mode no JWKS is fetched.
    """

    def __init__(
        self,
        issuer: str,
        jwks_url: str,
        audience: str,
        *,
        verify: bool = True,
        algorithms: tuple[str, ...] = ("RS256",),
        leeway: float = 30.0,
        timeout: float = 10.0,
    ):
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.audience = audience
        self.verify = verify
        self.algorithms = list(algorithms)
        self.leeway = leeway
        self.timeout = timeout
        self._jwk_client: Optional["jwt.PyJWKClient"] = None

    def _client(self) -> "jwt.PyJWKClient":
        # Lazily built so construction never touches the network; PyJWKClient
        # caches keys internally and refetches when it sees an unknown ``kid``.
        if self._jwk_client is None:
            self._jwk_client = jwt.PyJWKClient(
                self.jwks_url, cache_keys=True, timeout=self.timeout
            )
        return self._jwk_client

    def validate(self, token: str) -> dict:
        """Return the verified claims, or raise :class:`OidcError`."""
        if not token:
            raise OidcError("empty token")

        if not self.verify:
            log.warning("OIDC verify=False — decoding token WITHOUT verification")
            try:
                return jwt.decode(token, options={"verify_signature": False})
            except jwt.PyJWTError as exc:  # malformed token
                raise OidcError(f"decode failed: {exc}") from exc

        try:
            signing_key = self._client().get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={
                    "require": ["exp", "iat"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise OidcError(str(exc)) from exc
        except Exception as exc:  # JWKS fetch / network / key errors
            raise OidcError(f"jwks/key error: {exc}") from exc
        return claims


# ---------------------------------------------------------------------------
# Global validator registry + decorator
#
# webhook.py builds the validator from env vars once and registers it here; the
# decorator then reaches it through this module-level slot. Tests inject a fake
# validator via ``set_oidc_validator`` to exercise the endpoint without a real
# JWKS.
# ---------------------------------------------------------------------------

_validator: Optional[OidcValidator] = None


def set_oidc_validator(validator: Optional[OidcValidator]) -> None:
    global _validator
    _validator = validator


def get_oidc_validator() -> Optional[OidcValidator]:
    return _validator


def require_oidc(fn):
    """Reject the request unless it carries a valid ``Authorization: Bearer``
    access-JWT. On success the verified claims are attached to
    ``flask.g.oidc_claims``.

    - validator not configured        -> 503 (fail-closed, mirrors the
      Authentik ``None`` handling in ``/reconcile-all``)
    - missing / malformed bearer      -> 401
    - invalid / expired / wrong-aud   -> 401
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        validator = get_oidc_validator()
        if validator is None:
            log.warning("require_oidc: no OIDC validator configured")
            return jsonify({
                "error": "oidc not configured",
                "detail": "OIDC_ISSUER / OIDC_JWKS_URL / OIDC_AUDIENCE unset",
            }), 503

        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            log.warning("require_oidc: missing/malformed Authorization header "
                        "remote=%s", request.remote_addr)
            return jsonify({"error": "unauthorized"}), 401
        token = header[len("Bearer "):].strip()

        try:
            claims = validator.validate(token)
        except OidcError as exc:
            log.warning("require_oidc: token rejected (%s) remote=%s",
                        exc, request.remote_addr)
            return jsonify({"error": "unauthorized"}), 401

        g.oidc_claims = claims
        return fn(*args, **kwargs)

    return wrapper
