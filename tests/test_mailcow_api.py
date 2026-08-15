"""Tests for the Mailcow REST wrapper — focused on the App-Password creation
carrying ``sieve_access`` by default so the same password authenticates
ManageSieve (port 4190) as well as IMAP/SMTP."""
import app.mailcow.api as api_mod
from app.mailcow.api import MailcowClient


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeRequests:
    """Minimal stand-in for the ``requests`` module used inside api.py."""

    def __init__(self, app_pwds):
        self._app_pwds = app_pwds
        self.posts = []
        self.gets = []

    def post(self, url, headers=None, json=None, timeout=None):
        self.posts.append({"url": url, "json": json})
        return _Resp({})

    def get(self, url, headers=None, timeout=None):
        self.gets.append(url)
        # list_app_passwds(...) — return the canned entry
        return _Resp(self._app_pwds)


def _client(monkeypatch, app_pwds):
    fake = _FakeRequests(app_pwds)
    monkeypatch.setattr(api_mod, "requests", fake)
    return MailcowClient("http://nginx-mailcow", "key"), fake


def test_add_app_passwd_default_protocols_include_sieve(monkeypatch):
    name = "authentik-sync:u@lammers-krueger.de:t@lammers-krueger.de"
    c, fake = _client(monkeypatch, [{"id": 42, "name": name}])

    pwd_id = c.add_app_passwd("t@lammers-krueger.de", name, "s3cret")

    assert pwd_id == 42
    sent = fake.posts[0]["json"]
    assert sent["protocols"] == ["imap_access", "smtp_access", "sieve_access"]
    # sanity: the three known access protocols, no accidental extras
    assert "sieve_access" in sent["protocols"]


def test_add_app_passwd_respects_explicit_protocols(monkeypatch):
    name = "authentik-sync:u@lammers-krueger.de:t@lammers-krueger.de"
    c, fake = _client(monkeypatch, [{"id": 7, "name": name}])

    c.add_app_passwd("t@lammers-krueger.de", name, "s3cret",
                     protocols=("imap_access",))

    assert fake.posts[0]["json"]["protocols"] == ["imap_access"]


def test_add_app_passwd_signature_default_has_sieve():
    import inspect

    default = inspect.signature(MailcowClient.add_app_passwd).parameters["protocols"].default
    assert tuple(default) == ("imap_access", "smtp_access", "sieve_access")
