"""Reconcile-side tests for the Nextcloud Mail DB step (Sieve settings +
special-folder mapping enforcement).

Covers the two integration guarantees:
  - the step runs per managed target once ``sieve_provisioning`` is on, and is
    a strict no-op while it is off;
  - a failure in either sub-step is isolated (logged into ``summary["errors"]``)
    and never aborts the reconcile.
"""
from app.reconcile import _provision_nc_maildb, reconcile_user
from app.state import StateDB

DOMAIN = "lammers-krueger.de"
USER = f"u@{DOMAIN}"
SHARED = f"shared@{DOMAIN}"


# ---- fakes -----------------------------------------------------------------

class FakeNCMailDB:
    def __init__(self, account_ids=None, sieve_result=True,
                 mapping_result=("sent_mailbox_id",),
                 sieve_exc=None, mapping_exc=None, lookup_exc=None):
        self.account_ids = account_ids if account_ids is not None else {}
        self.sieve_result = sieve_result
        self.mapping_result = list(mapping_result)
        self.sieve_exc = sieve_exc
        self.mapping_exc = mapping_exc
        self.lookup_exc = lookup_exc
        self.lookups = []
        self.sieve_calls = []
        self.mapping_calls = []

    def get_account_id(self, user, target):
        self.lookups.append((user, target))
        if self.lookup_exc:
            raise self.lookup_exc
        return self.account_ids.get(target, 100)

    def ensure_sieve_settings(self, account_id, *, host, port, ssl_mode,
                              dry_run=False):
        self.sieve_calls.append((account_id, host, port, ssl_mode, dry_run))
        if self.sieve_exc:
            raise self.sieve_exc
        return self.sieve_result

    def enforce_special_folders(self, account_id, dry_run=False):
        self.mapping_calls.append((account_id, dry_run))
        if self.mapping_exc:
            raise self.mapping_exc
        return list(self.mapping_result)


class FakeMailcow:
    def __init__(self, mailboxes):
        self._mbs = mailboxes
        self._next_id = 1000
        self.sender_acl_edits = []

    def list_mailboxes(self):
        return [{"username": m} for m in self._mbs]

    def list_app_passwds(self, mailbox):
        return []

    def add_app_passwd(self, mailbox, app_name, password):
        self._next_id += 1
        return self._next_id

    def delete_app_passwd(self, ids):
        pass

    def edit_mailbox_sender_acl(self, mailbox, acl):
        self.sender_acl_edits.append((mailbox, acl))


class FakeNextcloud:
    def __init__(self, user_present=True):
        self.user_present = user_present
        self._next_id = 500

    def user_exists(self, user):
        return self.user_present

    def find_account_id(self, user, target):
        return None

    def create_mail_account(self, user, target, password, *args):
        self._next_id += 1
        return self._next_id

    def delete_mail_account(self, account_id):
        pass


# ---- blank summary for the direct-helper tests -----------------------------

def _summary():
    return {"errors": [], "nc_sieve_provisioned": [], "nc_mapping_enforced": []}


# ---- direct helper: account resolution & error isolation -------------------

def test_provision_skips_when_no_account():
    nc = FakeNCMailDB(account_ids={SHARED: None})
    summary = _summary()
    _provision_nc_maildb(
        USER, SHARED, nc_maildb=nc,
        sieve_host="mail." + DOMAIN, sieve_port=4190, sieve_ssl_mode="tls",
        dry_run=False, summary=summary,
    )
    assert nc.sieve_calls == []
    assert nc.mapping_calls == []
    assert summary["nc_sieve_provisioned"] == []
    assert summary["errors"] == []


def test_provision_runs_both_steps_and_records():
    nc = FakeNCMailDB(account_ids={SHARED: 77})
    summary = _summary()
    _provision_nc_maildb(
        USER, SHARED, nc_maildb=nc,
        sieve_host="mail." + DOMAIN, sieve_port=4190, sieve_ssl_mode="tls",
        dry_run=False, summary=summary,
    )
    assert nc.sieve_calls == [(77, "mail." + DOMAIN, 4190, "tls", False)]
    assert nc.mapping_calls == [(77, False)]
    assert summary["nc_sieve_provisioned"] == [SHARED]
    assert summary["nc_mapping_enforced"] == [f"{SHARED}:sent_mailbox_id"]


def test_provision_sieve_error_does_not_block_mapping():
    nc = FakeNCMailDB(account_ids={SHARED: 77},
                      sieve_exc=RuntimeError("sieve boom"))
    summary = _summary()
    _provision_nc_maildb(
        USER, SHARED, nc_maildb=nc,
        sieve_host="mail." + DOMAIN, sieve_port=4190, sieve_ssl_mode="tls",
        dry_run=False, summary=summary,
    )
    # mapping still ran despite the sieve failure
    assert nc.mapping_calls == [(77, False)]
    assert summary["nc_mapping_enforced"] == [f"{SHARED}:sent_mailbox_id"]
    assert any("sieve" in e for e in summary["errors"])
    assert summary["nc_sieve_provisioned"] == []


def test_provision_mapping_error_is_isolated():
    nc = FakeNCMailDB(account_ids={SHARED: 77},
                      mapping_exc=RuntimeError("mapping boom"))
    summary = _summary()
    _provision_nc_maildb(
        USER, SHARED, nc_maildb=nc,
        sieve_host="mail." + DOMAIN, sieve_port=4190, sieve_ssl_mode="tls",
        dry_run=False, summary=summary,
    )
    assert summary["nc_sieve_provisioned"] == [SHARED]
    assert any("mapping" in e for e in summary["errors"])


def test_provision_lookup_error_is_isolated():
    nc = FakeNCMailDB(lookup_exc=RuntimeError("psql down"))
    summary = _summary()
    _provision_nc_maildb(
        USER, SHARED, nc_maildb=nc,
        sieve_host="mail." + DOMAIN, sieve_port=4190, sieve_ssl_mode="tls",
        dry_run=False, summary=summary,
    )
    assert nc.sieve_calls == [] and nc.mapping_calls == []
    assert any("account lookup" in e for e in summary["errors"])


# ---- full reconcile integration --------------------------------------------

def _reconcile(tmp_path, *, sieve_provisioning, nc_maildb, dry_run=False):
    state = StateDB(str(tmp_path / "state.db"))
    mailcow = FakeMailcow([USER, SHARED])
    nextcloud = FakeNextcloud(user_present=True)
    payload = {"email": USER, "primary_email": USER, "shared_mailboxes": [SHARED]}
    summary = reconcile_user(
        payload,
        state=state, mailcow=mailcow, nextcloud=nextcloud,
        dovecot=None, memcached=None, mailcow_db=None, sogo=None,
        nc_maildb=nc_maildb,
        our_domain=DOMAIN,
        imap_host="mail." + DOMAIN, imap_port=993, imap_enc="ssl",
        smtp_host="mail." + DOMAIN, smtp_port=465, smtp_enc="ssl",
        sieve_provisioning=sieve_provisioning,
        sieve_host="mail." + DOMAIN, sieve_port=4190, sieve_ssl_mode="tls",
        dry_run=dry_run,
    )
    return summary


def test_reconcile_runs_nc_maildb_step_when_enabled(tmp_path):
    nc = FakeNCMailDB()
    summary = _reconcile(tmp_path, sieve_provisioning=True, nc_maildb=nc)

    # both managed targets (the user's own + the shared mailbox) got provisioned
    assert set(summary["added"]) == {USER, SHARED}
    assert {t for (u, t) in nc.lookups} == {USER, SHARED}
    assert len(nc.sieve_calls) == 2
    assert len(nc.mapping_calls) == 2
    assert set(summary["nc_sieve_provisioned"]) == {USER, SHARED}
    assert set(summary["nc_mapping_enforced"]) == {
        f"{USER}:sent_mailbox_id", f"{SHARED}:sent_mailbox_id"}


def test_reconcile_skips_nc_maildb_step_when_disabled(tmp_path):
    nc = FakeNCMailDB()
    summary = _reconcile(tmp_path, sieve_provisioning=False, nc_maildb=nc)

    assert nc.lookups == []
    assert nc.sieve_calls == []
    assert nc.mapping_calls == []
    assert summary["nc_sieve_provisioned"] == []
    assert summary["nc_mapping_enforced"] == []


def test_reconcile_nc_maildb_none_is_safe(tmp_path):
    # sieve on but no client wired -> no crash, no provisioning
    summary = _reconcile(tmp_path, sieve_provisioning=True, nc_maildb=None)
    assert summary["nc_sieve_provisioned"] == []
    assert summary["errors"] == []


def test_reconcile_dry_run_passes_flag_through(tmp_path):
    nc = FakeNCMailDB()
    summary = _reconcile(tmp_path, sieve_provisioning=True, nc_maildb=nc,
                         dry_run=True)
    # In dry-run the adds are still reported, and the provisioning step is
    # invoked with dry_run=True for each.
    assert summary["dry_run"] is True
    assert all(call[-1] is True for call in nc.sieve_calls)
    assert all(call[1] is True for call in nc.mapping_calls)
