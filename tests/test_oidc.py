"""Tests for OIDC access-token validation (app/oidc.py).

A real RSA keypair is generated in-test, tokens are signed with PyJWT, and the
JWKS lookup is replaced by a fake ``PyJWKClient`` that hands back the matching
public key — so signature/claim verification runs for real without a network.
"""
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, g, jsonify

from app.oidc import (
    OidcError,
    OidcValidator,
    require_oidc,
    set_oidc_validator,
)

ISSUER = "https://auth.lammers-krueger.de/application/o/mail-setup/"
JWKS_URL = "https://auth.lammers-krueger.de/application/o/mail-setup/jwks/"
AUD = "mail-setup-client-id"
EMAIL = "cloud@lammers-krueger.de"


def _mk_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _priv_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _make_token(signing_key, *, aud=AUD, iss=ISSUER, exp_delta=60,
                iat_delta=0, extra=None, alg="RS256"):
    now = int(time.time())
    payload = {
        "iss": iss,
        "aud": aud,
        "iat": now + iat_delta,
        "exp": now + exp_delta,
        "email": EMAIL,
        "preferred_username": "cloud",
        "name": "Cloud User",
        "shared_mailboxes": ["rechnung@lammers-krueger.de"],
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _priv_pem(signing_key), algorithm=alg)


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJWKClient:
    """Stand-in for jwt.PyJWKClient that always returns the given public key."""

    def __init__(self, public_key):
        self._pub = public_key

    def get_signing_key_from_jwt(self, token):
        return _FakeSigningKey(self._pub)


@pytest.fixture
def keypair():
    key = _mk_key()
    return key, key.public_key()


def _validator_for(public_key, **kw):
    v = OidcValidator(ISSUER, JWKS_URL, AUD, **kw)
    v._jwk_client = _FakeJWKClient(public_key)
    return v


# ---- OidcValidator.validate -----------------------------------------------

def test_valid_token_accepted(keypair):
    priv, pub = keypair
    v = _validator_for(pub)
    claims = v.validate(_make_token(priv))
    assert claims["email"] == EMAIL
    assert claims["aud"] == AUD
    assert claims["shared_mailboxes"] == ["rechnung@lammers-krueger.de"]


def test_wrong_audience_rejected(keypair):
    priv, pub = keypair
    v = _validator_for(pub)
    with pytest.raises(OidcError):
        v.validate(_make_token(priv, aud="some-other-client"))


def test_wrong_issuer_rejected(keypair):
    priv, pub = keypair
    v = _validator_for(pub)
    with pytest.raises(OidcError):
        v.validate(_make_token(priv, iss="https://evil.example/"))


def test_expired_token_rejected(keypair):
    priv, pub = keypair
    v = _validator_for(pub)
    # 5 minutes in the past — well beyond the 30s leeway.
    with pytest.raises(OidcError):
        v.validate(_make_token(priv, exp_delta=-300))


def test_bad_signature_rejected(keypair):
    _priv, pub = keypair
    other = _mk_key()  # sign with a key the validator does NOT trust
    v = _validator_for(pub)
    with pytest.raises(OidcError):
        v.validate(_make_token(other))


def test_missing_exp_rejected(keypair):
    priv, pub = keypair
    v = _validator_for(pub)
    tok = jwt.encode(
        {"iss": ISSUER, "aud": AUD, "iat": int(time.time()), "email": EMAIL},
        _priv_pem(priv), algorithm="RS256",
    )
    with pytest.raises(OidcError):
        v.validate(tok)


def test_empty_token_rejected(keypair):
    _priv, pub = keypair
    v = _validator_for(pub)
    with pytest.raises(OidcError):
        v.validate("")


# ---- require_oidc decorator -----------------------------------------------

def _probe_app(validator):
    set_oidc_validator(validator)
    app = Flask(__name__)

    @app.route("/probe")
    @require_oidc
    def probe():
        return jsonify({"email": g.oidc_claims.get("email")}), 200

    return app


def test_require_oidc_missing_bearer_is_401(keypair):
    _priv, pub = keypair
    app = _probe_app(_validator_for(pub))
    r = app.test_client().get("/probe")
    assert r.status_code == 401


def test_require_oidc_malformed_header_is_401(keypair):
    _priv, pub = keypair
    app = _probe_app(_validator_for(pub))
    r = app.test_client().get("/probe", headers={"Authorization": "Token abc"})
    assert r.status_code == 401


def test_require_oidc_valid_token_passes_claims(keypair):
    priv, pub = keypair
    app = _probe_app(_validator_for(pub))
    tok = _make_token(priv)
    r = app.test_client().get(
        "/probe", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.get_json()["email"] == EMAIL


def test_require_oidc_invalid_token_is_401(keypair):
    priv, pub = keypair
    app = _probe_app(_validator_for(pub))
    tok = _make_token(priv, aud="wrong")
    r = app.test_client().get(
        "/probe", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401


def test_require_oidc_not_configured_is_503():
    app = _probe_app(None)  # fail-closed when no validator registered
    r = app.test_client().get(
        "/probe", headers={"Authorization": "Bearer whatever"})
    assert r.status_code == 503
