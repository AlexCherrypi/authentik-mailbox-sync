"""Unit tests for the Dovecot ACL wrapper.

These exercise the pure parsing / folder-filtering logic by stubbing
``DovecotClient._exec`` so nothing shells out to ``docker``/``doveadm``.

Covers the three fixes:
  A1  list_folders excludes the *entire* Shared/Public namespace (not just the
      top-level folder), so ``acl set`` never fires on virtual shared folders.
  A2  get_rights_for_user uses the real ``doveadm acl get`` subcommand and
      parses its output (the old ``acl list`` didn't exist → always False).
  A3  DEFAULT_RIGHTS is the full collaborator set, explicitly without ``admin``.
"""
import subprocess

import pytest

from app.mailcow.dovecot import DEFAULT_RIGHTS, DovecotClient


def _cp(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class _StubExec:
    """Records doveadm invocations and returns canned CompletedProcess objects
    based on the doveadm subcommand (args[0])."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, *args, check=True):
        self.calls.append(list(args))
        proc = self.responses.get(args[0], _cp())
        if check and proc.returncode != 0:
            raise AssertionError(f"unexpected non-zero for checked call {args}")
        return proc


def _client(monkeypatch, responses):
    c = DovecotClient(container="dovecot-test")
    stub = _StubExec(responses)
    monkeypatch.setattr(c, "_exec", stub)
    return c, stub


# ---- A3: rights set --------------------------------------------------------

def test_default_rights_is_full_set_without_admin():
    assert "admin" not in DEFAULT_RIGHTS
    # everything a sharee needs to persist \Seen, move, delete, create folders
    for r in ("lookup", "read", "write", "write-seen", "write-deleted",
              "insert", "post", "expunge", "create", "delete"):
        assert r in DEFAULT_RIGHTS


# ---- A1: folder-leak -------------------------------------------------------

def test_list_folders_excludes_whole_shared_and_public_namespace(monkeypatch):
    listing = "\n".join([
        "INBOX",
        "INBOX/Projekte",
        "Sent",
        "Drafts",
        "Junk",
        "Trash",
        "Archive",
        "Shared",                                   # top-level (old code caught this)
        "Shared/info@lammers-krueger.de",           # leaf = info@… (old code MISSED)
        "Shared/info@lammers-krueger.de/INBOX",     # leaf = INBOX (old code MISSED)
        "Public",
        "Public/Announcements",
    ])
    c, _ = _client(monkeypatch, {"mailbox": _cp(stdout=listing)})
    folders = c.list_folders("hl@lammers-krueger.de")
    assert folders == ["INBOX", "INBOX/Projekte", "Sent", "Drafts",
                       "Junk", "Trash", "Archive"]
    assert not any(f.split("/")[0] in {"Shared", "Public"} for f in folders)


# ---- A2: probe on real subcommand -----------------------------------------

_ACL_GET = "\n".join([
    "ID                                Global  Rights",
    "anyone                                    lookup read",
    "user=cloud@lammers-krueger.de             lookup read write write-seen "
    "write-deleted insert post expunge create delete",
    "user=hl@lammers-krueger.de                lookup read",
])


def test_get_rights_parses_full_grant(monkeypatch):
    c, _ = _client(monkeypatch, {"acl": _cp(stdout=_ACL_GET)})
    rights = c.get_rights_for_user("rechnung@lammers-krueger.de",
                                   "cloud@lammers-krueger.de")
    assert rights == set(DEFAULT_RIGHTS)


def test_get_rights_parses_partial_grant(monkeypatch):
    c, _ = _client(monkeypatch, {"acl": _cp(stdout=_ACL_GET)})
    rights = c.get_rights_for_user("rechnung@lammers-krueger.de",
                                   "hl@lammers-krueger.de")
    assert rights == {"lookup", "read"}


def test_get_rights_absent_user_is_empty(monkeypatch):
    c, _ = _client(monkeypatch, {"acl": _cp(stdout=_ACL_GET)})
    assert c.get_rights_for_user("rechnung@lammers-krueger.de",
                                 "nobody@lammers-krueger.de") == set()


def test_get_rights_nonzero_rc_is_empty(monkeypatch):
    # e.g. mailbox has no INBOX / doveadm errors — must not raise, must be {}
    c, _ = _client(monkeypatch, {"acl": _cp(returncode=64, stderr="usage")})
    assert c.get_rights_for_user("x@lammers-krueger.de",
                                 "y@lammers-krueger.de") == set()


def test_get_rights_ignores_global_column(monkeypatch):
    out = "user=cloud@lammers-krueger.de   global  lookup read"
    c, _ = _client(monkeypatch, {"acl": _cp(stdout=out)})
    assert c.get_rights_for_user("mb@lammers-krueger.de",
                                 "cloud@lammers-krueger.de") == {"lookup", "read"}


def test_get_rights_no_substring_false_positive(monkeypatch):
    # "cloud@" must not match "cloud2@"
    out = "user=cloud2@lammers-krueger.de   lookup read write"
    c, _ = _client(monkeypatch, {"acl": _cp(stdout=out)})
    assert c.get_rights_for_user("mb@lammers-krueger.de",
                                 "cloud@lammers-krueger.de") == set()


def test_has_acl_for_user_is_bool_wrapper(monkeypatch):
    c, _ = _client(monkeypatch, {"acl": _cp(stdout=_ACL_GET)})
    assert c.has_acl_for_user("rechnung@lammers-krueger.de",
                              "cloud@lammers-krueger.de") is True
    assert c.has_acl_for_user("rechnung@lammers-krueger.de",
                              "nobody@lammers-krueger.de") is False


# ---- writes: grant / revoke build the right commands -----------------------

def test_grant_uses_default_rights_and_skips_system_folders(monkeypatch):
    listing = "INBOX\nSent\nShared/rechnung@lammers-krueger.de"
    c, stub = _client(monkeypatch, {
        "mailbox": _cp(stdout=listing),
        "acl": _cp(),  # acl set succeeds
    })
    c.grant("rechnung@lammers-krueger.de", "cloud@lammers-krueger.de")

    set_calls = [call for call in stub.calls if call[:2] == ["acl", "set"]]
    # only the two real folders, never the Shared/ pseudo-folder
    folders = [call[4] for call in set_calls]
    assert folders == ["INBOX", "Sent"]
    for call in set_calls:
        assert call == ["acl", "set", "-u", "rechnung@lammers-krueger.de",
                        call[4], "user=cloud@lammers-krueger.de",
                        *DEFAULT_RIGHTS]


def test_grant_accepts_explicit_rights(monkeypatch):
    c, stub = _client(monkeypatch, {
        "mailbox": _cp(stdout="INBOX"),
        "acl": _cp(),
    })
    c.grant("mb@lammers-krueger.de", "u@lammers-krueger.de",
            rights=("lookup", "read"))
    set_call = [call for call in stub.calls if call[:2] == ["acl", "set"]][0]
    assert set_call[-2:] == ["lookup", "read"]


def test_grant_logs_and_continues_on_failure(monkeypatch, caplog):
    listing = "INBOX\nSent"
    c = DovecotClient(container="dovecot-test")

    def failing_exec(*args, check=True):
        if args[0] == "mailbox":
            return _cp(stdout=listing)
        return _cp(returncode=1, stderr="boom")

    monkeypatch.setattr(c, "_exec", failing_exec)
    with caplog.at_level("WARNING"):
        c.grant("mb@lammers-krueger.de", "u@lammers-krueger.de")
    assert caplog.text.count("acl set failed") == 2  # both folders, no raise


def test_revoke_builds_delete_and_tolerates_not_found(monkeypatch):
    listing = "INBOX\nSent"
    c = DovecotClient(container="dovecot-test")

    def exec_(*args, check=True):
        if args[0] == "mailbox":
            return _cp(stdout=listing)
        return _cp(returncode=68, stderr="doveadm: No such ACL")

    monkeypatch.setattr(c, "_exec", exec_)
    # must not raise despite non-zero rc (not-found is tolerated)
    c.revoke("mb@lammers-krueger.de", "u@lammers-krueger.de")
