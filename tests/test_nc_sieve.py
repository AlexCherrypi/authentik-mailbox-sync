"""Unit tests for the Nextcloud Mail DB provisioning wrapper
(``app.nextcloud.sieve``).

Everything is exercised by stubbing ``NextcloudMailDB._psql`` so nothing shells
out to ``docker``/``psql``. The stub answers by matching the SQL text and
records every statement so assertions can distinguish reads from writes."""
import subprocess

import pytest

from app.nextcloud.sieve import NextcloudMailDB, NextcloudMailDBError


def _cp(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class _StubPsql:
    """Routes SQL statements to canned results.

    ``responder`` is a callable ``(sql) -> CompletedProcess``. Every call is
    recorded in ``.calls`` so tests can assert what was read vs. written."""

    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def __call__(self, sql, check=True):
        self.calls.append(sql)
        proc = self.responder(sql)
        if check and proc.returncode != 0:
            raise NextcloudMailDBError(f"stub non-zero for checked call: {sql}")
        return proc

    # convenience filters
    def updates(self):
        return [s for s in self.calls if s.lstrip().upper().startswith("UPDATE")]

    def selects(self):
        return [s for s in self.calls if s.lstrip().upper().startswith("SELECT")]


def _client(monkeypatch, responder):
    c = NextcloudMailDB(container="nc-db-test", db_name="ncdb", db_user="nc")
    stub = _StubPsql(responder)
    monkeypatch.setattr(c, "_psql", stub)
    return c, stub


# ---- validation (SQL-injection guard) --------------------------------------

@pytest.mark.parametrize("bad_host", [
    "evil'; DROP TABLE oc_mail_accounts;--",
    "host with space",
    'quote"host',
    "semi;colon",
    "back\\slash",
    "",
])
def test_ensure_sieve_rejects_bad_host_before_any_sql(monkeypatch, bad_host):
    def responder(sql):
        raise AssertionError(f"no SQL should run for a bad host, got: {sql}")

    c, stub = _client(monkeypatch, responder)
    with pytest.raises(NextcloudMailDBError):
        c.ensure_sieve_settings(1, host=bad_host, port=4190, ssl_mode="tls")
    assert stub.calls == []  # validation happened before the SELECT


@pytest.mark.parametrize("bad_port", ["notaport", 0, 70000, -1])
def test_ensure_sieve_rejects_bad_port(monkeypatch, bad_port):
    c, stub = _client(monkeypatch, lambda sql: _cp())
    with pytest.raises(NextcloudMailDBError):
        c.ensure_sieve_settings(1, host="mail.example.com", port=bad_port,
                                ssl_mode="tls")


@pytest.mark.parametrize("bad_mode", ["starttls", "TLS-1.3", "", "yes"])
def test_ensure_sieve_rejects_bad_ssl_mode(monkeypatch, bad_mode):
    c, stub = _client(monkeypatch, lambda sql: _cp())
    with pytest.raises(NextcloudMailDBError):
        c.ensure_sieve_settings(1, host="mail.example.com", port=4190,
                                ssl_mode=bad_mode)


def test_valid_ssl_modes_are_accepted(monkeypatch):
    # already-correct row for each mode -> no-op, no exception
    for mode in ("tls", "ssl", "none"):
        def responder(sql, _mode=mode):
            if sql.startswith("SELECT sieve_enabled"):
                return _cp(stdout=f"t\tmail.example.com\t4190\t{_mode}\t\t")
            return _cp()
        c, stub = _client(monkeypatch, responder)
        assert c.ensure_sieve_settings(1, host="mail.example.com", port=4190,
                                       ssl_mode=mode) is False


# ---- Feature 2: sieve settings ---------------------------------------------

def test_ensure_sieve_noop_when_already_correct(monkeypatch):
    def responder(sql):
        if sql.startswith("SELECT sieve_enabled"):
            return _cp(stdout="t\tmail.example.com\t4190\ttls\t\t")
        return _cp()

    c, stub = _client(monkeypatch, responder)
    changed = c.ensure_sieve_settings(5, host="mail.example.com", port=4190,
                                      ssl_mode="tls")
    assert changed is False
    assert stub.updates() == []  # nothing written


def test_ensure_sieve_updates_when_disabled(monkeypatch):
    def responder(sql):
        if sql.startswith("SELECT sieve_enabled"):
            # sieve currently off, all columns NULL
            return _cp(stdout="f\t\t\t\t\t")
        return _cp()

    c, stub = _client(monkeypatch, responder)
    changed = c.ensure_sieve_settings(5, host="mail.example.com", port=4190,
                                      ssl_mode="tls")
    assert changed is True
    ups = stub.updates()
    assert len(ups) == 1
    up = ups[0]
    assert "sieve_enabled = true" in up
    assert "sieve_host = 'mail.example.com'" in up
    assert "sieve_port = 4190" in up
    assert "sieve_ssl_mode = 'tls'" in up
    assert "sieve_user = NULL" in up
    assert "sieve_password = NULL" in up
    assert "WHERE id = 5" in up


def test_ensure_sieve_updates_when_host_differs(monkeypatch):
    def responder(sql):
        if sql.startswith("SELECT sieve_enabled"):
            return _cp(stdout="t\told.example.com\t4190\ttls\t\t")
        return _cp()

    c, stub = _client(monkeypatch, responder)
    assert c.ensure_sieve_settings(5, host="mail.example.com", port=4190,
                                   ssl_mode="tls") is True
    assert "sieve_host = 'mail.example.com'" in stub.updates()[0]


def test_ensure_sieve_updates_when_creds_leftover(monkeypatch):
    # sieve_user/sieve_password must be driven back to NULL
    def responder(sql):
        if sql.startswith("SELECT sieve_enabled"):
            return _cp(stdout="t\tmail.example.com\t4190\ttls\tolduser\toldpass")
        return _cp()

    c, stub = _client(monkeypatch, responder)
    assert c.ensure_sieve_settings(5, host="mail.example.com", port=4190,
                                   ssl_mode="tls") is True
    assert "sieve_user = NULL" in stub.updates()[0]


def test_ensure_sieve_dry_run_reports_but_does_not_write(monkeypatch):
    def responder(sql):
        if sql.startswith("SELECT sieve_enabled"):
            return _cp(stdout="f\t\t\t\t\t")
        return _cp()

    c, stub = _client(monkeypatch, responder)
    changed = c.ensure_sieve_settings(5, host="mail.example.com", port=4190,
                                      ssl_mode="tls", dry_run=True)
    assert changed is True
    assert stub.updates() == []  # dry-run: SELECT only


def test_ensure_sieve_account_not_found_is_noop(monkeypatch):
    def responder(sql):
        if sql.startswith("SELECT sieve_enabled"):
            return _cp(stdout="")  # no rows
        return _cp()

    c, stub = _client(monkeypatch, responder)
    assert c.ensure_sieve_settings(5, host="mail.example.com", port=4190,
                                   ssl_mode="tls") is False
    assert stub.updates() == []


# ---- account id lookup / quoting -------------------------------------------

def test_get_account_id_single_row(monkeypatch):
    c, stub = _client(monkeypatch, lambda sql: _cp(stdout="17"))
    assert c.get_account_id("u@lammers-krueger.de", "t@lammers-krueger.de") == 17


def test_get_account_id_no_row_is_none(monkeypatch):
    c, stub = _client(monkeypatch, lambda sql: _cp(stdout=""))
    assert c.get_account_id("u@lammers-krueger.de", "t@lammers-krueger.de") is None


def test_get_account_id_ambiguous_is_none(monkeypatch):
    c, stub = _client(monkeypatch, lambda sql: _cp(stdout="17\n18"))
    assert c.get_account_id("u@lammers-krueger.de", "t@lammers-krueger.de") is None


def test_get_account_id_escapes_quotes_in_email(monkeypatch):
    seen = {}

    def responder(sql):
        seen["sql"] = sql
        return _cp(stdout="")

    c, stub = _client(monkeypatch, responder)
    c.get_account_id("o'brien@lammers-krueger.de", "t@lammers-krueger.de")
    # the single quote must be doubled, never left to break out of the literal
    assert "'o''brien@lammers-krueger.de'" in seen["sql"]
    assert "o'brien" not in seen["sql"].replace("''", "")  # no lone quote


def test_sql_str_rejects_nul_byte():
    with pytest.raises(NextcloudMailDBError):
        NextcloudMailDB._sql_str("bad\x00value")
