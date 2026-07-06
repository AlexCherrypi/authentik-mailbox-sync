"""Reconcile-side tests for the Dovecot ACL decision in ``_reconcile_sharing``.

The crux of fix A3's idempotency: the sweep must *upgrade* an existing
partial (lookup/read) grant to the full rights set rather than skip it as
"already present" — and, with the probe fixed (A2), the revoke branch must
fire again when access is removed.
"""
from app.mailcow.dovecot import DEFAULT_RIGHTS
from app.reconcile import _reconcile_sharing

USER = "cloud@lammers-krueger.de"
TARGET = "rechnung@lammers-krueger.de"
DOMAIN = "lammers-krueger.de"


class FakeDovecot:
    def __init__(self, current_rights):
        self.default_rights = tuple(DEFAULT_RIGHTS)
        self._current = set(current_rights)
        self.granted = []
        self.revoked = []

    def get_rights_for_user(self, target, user):
        return set(self._current)

    def grant(self, target, user):
        self.granted.append((target, user))

    def revoke(self, target, user):
        self.revoked.append((target, user))


class FakeMailcow:
    def __init__(self):
        self.sender_acl_edits = []

    def edit_mailbox_sender_acl(self, target, acl):
        self.sender_acl_edits.append((target, acl))


def _blank_summary():
    return {
        "errors": [],
        "sender_acl_added": [],
        "sender_acl_removed": [],
        "acl_granted": [],
        "acl_revoked": [],
        "sogo_delegate_from_set": False,
        "sogo_delegate_to_added": [],
        "sogo_delegate_to_removed": [],
    }


def _run(current_rights, want):
    dov = FakeDovecot(current_rights)
    summary = _blank_summary()
    _reconcile_sharing(
        USER,
        {TARGET} if want else set(),
        all_mailboxes=[{"username": USER}, {"username": TARGET}],
        mailcow=FakeMailcow(), mailcow_db=None, dovecot=dov, sogo=None,
        our_domain=DOMAIN, dry_run=False, summary=summary,
    )
    return dov, summary


def test_fresh_grant_fires_when_no_acl_present():
    dov, summary = _run(current_rights=set(), want=True)
    assert dov.granted == [(TARGET, USER)]
    assert summary["acl_granted"] == [TARGET]


def test_stale_partial_grant_is_upgraded():
    # This is the A3 regression guard: an old lookup/read grant must NOT be
    # treated as "already there" — the sweep has to re-grant to raise it to
    # the full rights set.
    dov, summary = _run(current_rights={"lookup", "read"}, want=True)
    assert dov.granted == [(TARGET, USER)]
    assert summary["acl_granted"] == [TARGET]


def test_full_grant_is_left_alone():
    dov, summary = _run(current_rights=set(DEFAULT_RIGHTS), want=True)
    assert dov.granted == []
    assert summary["acl_granted"] == []


def test_revoke_fires_when_access_removed():
    dov, summary = _run(current_rights={"lookup", "read"}, want=False)
    assert dov.revoked == [(TARGET, USER)]
    assert summary["acl_revoked"] == [TARGET]


def test_no_acl_and_not_wanted_is_noop():
    dov, summary = _run(current_rights=set(), want=False)
    assert dov.granted == []
    assert dov.revoked == []
