"""Endpoint tests for GET /my-accounts (T-009d).

The Flask app is imported with the two import-time env vars set; per-test the
module globals ``mailcow`` and ``state`` are swapped for fakes, request-time env
vars are set via monkeypatch, and a fake OIDC validator injects the claims (so
``require_oidc`` runs for real but does not need a JWKS).
"""
import json
import os
import tempfile

import pytest

# --- import-time requirements of app.webhook (read once at module import) ---
os.environ.setdefault("STATE_DB_PATH", os.path.join(tempfile.mkdtemp(), "boot.db"))
os.environ.setdefault("MAILCOW_API", "http://mailcow.test")

import app.webhook as webhook  # noqa: E402
from app.oidc import set_oidc_validator  # noqa: E402
from app.reconcile import MARKER_PREFIX, TB_MARKER_PREFIX  # noqa: E402
from app.state import StateDB  # noqa: E402

DOMAIN = "lammers-krueger.de"
USER = "cloud@lammers-krueger.de"
RECHNUNG = "rechnung@lammers-krueger.de"
GHOST = "ghost@lammers-krueger.de"
INFO = "info@lammers-krueger.de"
DEVICE = "PC01~alex"


class FakeMailcow:
    def __init__(self, mailboxes):
        self._mbs = list(mailboxes)
        self.added = []      # dicts: mailbox, app_name, password, protocols
        self.deleted = []    # list of id-lists passed to delete_app_passwd
        self._next_id = 1000

    def list_mailboxes(self):
        return [{"username": m} for m in self._mbs]

    def add_app_passwd(self, mailbox, app_name, password,
                       protocols=("imap_access", "smtp_access", "sieve_access")):
        self._next_id += 1
        self.added.append({
            "mailbox": mailbox, "app_name": app_name,
            "password": password, "protocols": tuple(protocols),
        })
        return self._next_id

    def delete_app_passwd(self, ids):
        self.deleted.append(list(ids))


class FakeValidator:
    def __init__(self, claims):
        self._claims = claims

    def validate(self, token):
        return dict(self._claims)


def _claims(*, email=USER, shared=None, name="Cloud User", pref="cloud"):
    return {
        "email": email,
        "name": name,
        "preferred_username": pref,
        "shared_mailboxes": list(shared or []),
    }


@pytest.fixture
def make(tmp_path, monkeypatch):
    sig = tmp_path / "signatures.json"
    sig.write_text(json.dumps({
        "firmenanrede": {"html": "<p>Firma</p>", "from_name": "Lammers & Krüger GBR"},
        "persoenliche_anrede": {"html": "<p>{{name}}</p>", "from_name": "{{name}} | LK"},
    }), encoding="utf-8")

    monkeypatch.setenv("OUR_DOMAIN", DOMAIN)
    monkeypatch.setenv("IMAP_HOST", "mail.lammers-krueger.de")
    monkeypatch.setenv("IMAP_PORT", "993")
    monkeypatch.setenv("IMAP_ENCRYPTION", "ssl")
    monkeypatch.setenv("SMTP_HOST", "mail.lammers-krueger.de")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_ENCRYPTION", "starttls")
    monkeypatch.setenv("MY_ACCOUNTS_ENABLED", "true")
    monkeypatch.setenv("SIGNATURES_CONFIG_PATH", str(sig))

    state = StateDB(str(tmp_path / "state.db"))
    monkeypatch.setattr(webhook, "state", state)

    def _build(*, mailboxes, claims, enabled=True):
        monkeypatch.setenv("MY_ACCOUNTS_ENABLED", "true" if enabled else "false")
        mc = FakeMailcow(mailboxes)
        monkeypatch.setattr(webhook, "mailcow", mc)
        set_oidc_validator(FakeValidator(claims))
        return webhook.app.test_client(), mc, state

    _build.sig_path = sig
    return _build


def _get(client, *, device=DEVICE, use_header=False):
    headers = {"Authorization": "Bearer dummy"}
    if device is not None and use_header:
        headers["X-Device-Id"] = device
        return client.get("/my-accounts", headers=headers)
    if device is not None:
        return client.get(f"/my-accounts?device={device}", headers=headers)
    return client.get("/my-accounts", headers=headers)


# ---- actionable filtering + response shape --------------------------------

def test_actionable_filter_and_skipped_unknown(make):
    client, mc, _state = make(
        mailboxes=[USER, RECHNUNG, INFO],
        claims=_claims(shared=[RECHNUNG, GHOST, "ext@other.com"]),
    )
    r = _get(client)
    assert r.status_code == 200
    body = r.get_json()

    emails = [a["email"] for a in body["accounts"]]
    assert emails == sorted([USER, RECHNUNG])       # INFO not entitled, GHOST/ext gone
    assert body["skipped_unknown"] == [GHOST]        # desired but no mailbox
    # foreign-domain entitlement never even considered
    assert "ext@other.com" not in body["skipped_unknown"]


def test_response_shape(make):
    client, mc, _state = make(
        mailboxes=[USER, RECHNUNG],
        claims=_claims(shared=[RECHNUNG]),
    )
    body = _get(client).get_json()

    assert body["user"] == {
        "email": USER, "name": "Cloud User", "preferred_username": "cloud",
    }
    primary = [a for a in body["accounts"] if a["email"] == USER][0]
    assert primary["is_primary"] is True
    assert primary["username"] == USER
    assert primary["imap"] == {"host": "mail.lammers-krueger.de",
                               "port": 993, "security": "ssl"}
    assert primary["smtp"] == {"host": "mail.lammers-krueger.de",
                               "port": 587, "security": "starttls"}
    assert isinstance(primary["app_password"], str) and primary["app_password"]

    shared = [a for a in body["accounts"] if a["email"] == RECHNUNG][0]
    assert shared["is_primary"] is False

    assert set(body["signatures"].keys()) == {"firmenanrede", "persoenliche_anrede"}
    # no client-side festnagel flag leaks server-side (D-007 correction)
    for acc in body["accounts"]:
        assert "shared" not in acc


# ---- naming invariant ------------------------------------------------------

def test_app_password_naming_is_tb_setup_never_authentik_sync(make):
    client, mc, _state = make(
        mailboxes=[USER, RECHNUNG],
        claims=_claims(shared=[RECHNUNG]),
    )
    _get(client)
    assert len(mc.added) == 2
    for entry in mc.added:
        assert entry["app_name"].startswith(TB_MARKER_PREFIX)
        assert not entry["app_name"].startswith(MARKER_PREFIX)
        # device is encoded into the name
        assert entry["app_name"].endswith(f":{DEVICE}")
        # TB core can't do sieve — scope stays minimal
        assert entry["protocols"] == ("imap_access", "smtp_access")


# ---- re-run idempotency (replace old pwd) ---------------------------------

def test_rerun_deletes_old_pwd_and_mints_new(make):
    client, mc, state = make(
        mailboxes=[USER, RECHNUNG],
        claims=_claims(shared=[RECHNUNG]),
    )
    # Seed a prior credential for exactly (USER, RECHNUNG, DEVICE).
    state.tb_upsert(USER, RECHNUNG, DEVICE, mailcow_app_pwd_id=555)

    body = _get(client).get_json()
    assert body is not None

    # Old id was deleted before minting the replacement.
    assert [555] in mc.deleted
    # A fresh app-pwd was minted for RECHNUNG and recorded with the NEW id.
    new_id = state.tb_get(USER, RECHNUNG, DEVICE).mailcow_app_pwd_id
    assert new_id != 555
    rechnung_add = [a for a in mc.added if a["mailbox"] == RECHNUNG]
    assert len(rechnung_add) == 1
    # USER had no prior credential -> no delete for it
    assert state.tb_get(USER, USER, DEVICE).mailcow_app_pwd_id is not None


def test_device_from_header_also_works(make):
    client, mc, state = make(
        mailboxes=[USER],
        claims=_claims(),
    )
    r = _get(client, device=DEVICE, use_header=True)
    assert r.status_code == 200
    assert state.tb_get(USER, USER, DEVICE) is not None


# ---- error paths -----------------------------------------------------------

def test_missing_device_is_400(make):
    client, mc, _state = make(mailboxes=[USER], claims=_claims())
    r = _get(client, device=None)
    assert r.status_code == 400


def test_invalid_device_is_400(make):
    client, mc, _state = make(mailboxes=[USER], claims=_claims())
    r = _get(client, device="bad id with spaces!")
    assert r.status_code == 400


def test_toggle_off_is_503(make):
    client, mc, _state = make(mailboxes=[USER], claims=_claims(), enabled=False)
    r = _get(client)
    assert r.status_code == 503


def test_token_without_email_is_400(make):
    client, mc, _state = make(mailboxes=[USER], claims=_claims(email=""))
    r = _get(client)
    assert r.status_code == 400


def test_broken_signatures_config_is_503(make, monkeypatch, tmp_path):
    client, mc, _state = make(mailboxes=[USER], claims=_claims())
    bad = tmp_path / "broken.json"
    bad.write_text("{ nope", encoding="utf-8")
    monkeypatch.setenv("SIGNATURES_CONFIG_PATH", str(bad))
    r = _get(client)
    assert r.status_code == 503
    # nothing minted when config is broken (config read happens before minting)
    assert mc.added == []
