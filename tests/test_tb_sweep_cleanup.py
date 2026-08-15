"""Invariant tests for the tb-setup sweep cleanup (T-009d, D-005).

These are the load-bearing tests of the whole feature: the two App-Password
lifecycles (authentik-sync ``authentik-sync:*`` and Thunderbird-setup
``tb-setup:*``) must never touch each other's credentials.
"""
from app.reconcile import (
    MARKER_PREFIX,
    TB_MARKER_PREFIX,
    adopt_from_markers,
    reconcile_user,
    tb_marker_for,
)
from app.state import StateDB

DOMAIN = "lammers-krueger.de"
USER = "cloud@lammers-krueger.de"
RECHNUNG = "rechnung@lammers-krueger.de"
INFO = "info@lammers-krueger.de"
DEVICE = "PC01~alex"


class FakeMailcow:
    def __init__(self, mailboxes, app_pwds=None):
        self._mbs = list(mailboxes)
        self._app_pwds = app_pwds or {}     # target -> [{"id":.., "name":..}]
        self.deleted = []                   # list of id-lists
        self.sender_acl_edits = []
        self._next = 3000

    def list_mailboxes(self):
        return [{"username": m} for m in self._mbs]

    def list_app_passwds(self, mailbox):
        return list(self._app_pwds.get(mailbox, []))

    def add_app_passwd(self, mailbox, name, pwd,
                       protocols=("imap_access", "smtp_access")):
        self._next += 1
        return self._next

    def delete_app_passwd(self, ids):
        self.deleted.append(list(ids))

    def edit_mailbox_sender_acl(self, target, acl):
        self.sender_acl_edits.append((target, list(acl)))


class FakeNextcloud:
    def __init__(self, user_exists=False):
        self._ue = user_exists
        self.deleted = []

    def user_exists(self, u):
        return self._ue

    def find_account_id(self, u, t):
        return None

    def create_mail_account(self, *a, **k):
        return 1

    def delete_mail_account(self, account_id):
        self.deleted.append(account_id)


def _db(tmp_path):
    return StateDB(str(tmp_path / "state.db"))


def _reconcile(state, mailcow, nextcloud, *, shared, tb_setup_cleanup,
               dry_run=False, user=USER):
    return reconcile_user(
        {"email": user, "primary_email": user, "shared_mailboxes": shared},
        state=state, mailcow=mailcow, nextcloud=nextcloud,
        our_domain=DOMAIN,
        imap_host="mail", imap_port=993, imap_enc="ssl",
        smtp_host="mail", smtp_port=587, smtp_enc="starttls",
        tb_setup_cleanup=tb_setup_cleanup, dry_run=dry_run,
    )


# ---- 1) revocation on lost entitlement ------------------------------------

def test_tb_pwd_removed_when_entitlement_gone(tmp_path):
    state = _db(tmp_path)
    state.tb_upsert(USER, RECHNUNG, DEVICE, mailcow_app_pwd_id=777)
    mc = FakeMailcow([USER, RECHNUNG])
    nc = FakeNextcloud(user_exists=False)

    summary = _reconcile(state, mc, nc, shared=[], tb_setup_cleanup=True)

    assert f"{RECHNUNG}:{DEVICE}" in summary["tb_setup_removed"]
    assert [777] in mc.deleted
    assert state.tb_get(USER, RECHNUNG, DEVICE) is None


def test_tb_pwd_kept_when_entitlement_present(tmp_path):
    state = _db(tmp_path)
    state.tb_upsert(USER, RECHNUNG, DEVICE, mailcow_app_pwd_id=777)
    mc = FakeMailcow([USER, RECHNUNG])
    nc = FakeNextcloud(user_exists=False)

    summary = _reconcile(state, mc, nc, shared=[RECHNUNG], tb_setup_cleanup=True)

    assert summary["tb_setup_removed"] == []
    assert [777] not in mc.deleted
    assert state.tb_get(USER, RECHNUNG, DEVICE).mailcow_app_pwd_id == 777


def test_cleanup_is_noop_when_disabled(tmp_path):
    state = _db(tmp_path)
    state.tb_upsert(USER, RECHNUNG, DEVICE, mailcow_app_pwd_id=777)
    mc = FakeMailcow([USER, RECHNUNG])
    nc = FakeNextcloud(user_exists=False)

    summary = _reconcile(state, mc, nc, shared=[], tb_setup_cleanup=False)

    assert summary["tb_setup_removed"] == []
    assert [777] not in mc.deleted
    assert state.tb_get(USER, RECHNUNG, DEVICE) is not None


# ---- 2) the two lifecycles never cross ------------------------------------

def test_authentik_sync_remove_does_not_touch_tb_pwd(tmp_path):
    # RECHNUNG carries BOTH an authentik-sync pwd (state id 100) and a
    # tb-setup pwd (state id 200). Entitlement is dropped; the endpoint is
    # DISABLED (tb_setup_cleanup=False), so only the authentik-sync remove
    # runs. It must delete ONLY id 100 and leave the tb-setup row alone.
    state = _db(tmp_path)
    state.upsert(USER, RECHNUNG, mailcow_app_pwd_id=100)          # authentik-sync
    state.tb_upsert(USER, RECHNUNG, DEVICE, mailcow_app_pwd_id=200)  # tb-setup
    mc = FakeMailcow([USER, RECHNUNG])
    nc = FakeNextcloud(user_exists=False)

    _reconcile(state, mc, nc, shared=[], tb_setup_cleanup=False)

    assert mc.deleted == [[100]]                                  # only the sync id
    assert state.get(USER, RECHNUNG) is None                      # sync row removed
    assert state.tb_get(USER, RECHNUNG, DEVICE).mailcow_app_pwd_id == 200


def test_tb_cleanup_does_not_touch_authentik_sync_pwd(tmp_path):
    # INFO is a live authentik-sync mailbox (state id 100, still entitled).
    # RECHNUNG has only a tb-setup pwd (state id 200) whose entitlement is
    # gone. The tb cleanup must delete ONLY id 200 and leave the sync row for
    # INFO untouched.
    state = _db(tmp_path)
    state.upsert(USER, INFO, mailcow_app_pwd_id=100)             # authentik-sync, live
    state.tb_upsert(USER, RECHNUNG, DEVICE, mailcow_app_pwd_id=200)
    mc = FakeMailcow([USER, INFO, RECHNUNG])
    nc = FakeNextcloud(user_exists=False)

    _reconcile(state, mc, nc, shared=[INFO], tb_setup_cleanup=True)

    assert mc.deleted == [[200]]                                  # only the tb id
    assert state.tb_get(USER, RECHNUNG, DEVICE) is None
    assert state.get(USER, INFO).mailcow_app_pwd_id == 100        # sync row intact


def test_adopt_from_markers_ignores_tb_setup_names(tmp_path):
    # adopt scans app-pwd names; it must adopt only authentik-sync:* and never
    # pull a tb-setup:* password into the authentik-sync state table.
    state = _db(tmp_path)
    sync_name = f"{MARKER_PREFIX}{USER}:{RECHNUNG}"
    tb_name = tb_marker_for(USER, RECHNUNG, DEVICE)
    assert tb_name.startswith(TB_MARKER_PREFIX)
    mc = FakeMailcow(
        [RECHNUNG],
        app_pwds={RECHNUNG: [
            {"id": 100, "name": sync_name},
            {"id": 200, "name": tb_name},
        ]},
    )
    nc = FakeNextcloud()

    adopted = adopt_from_markers(
        USER, mailcow=mc, nextcloud=nc, state=state, our_domain=DOMAIN,
    )

    ids = {r["mailcow_app_pwd_id"] for r in adopted}
    assert ids == {100}                                    # tb id 200 NOT adopted
    assert state.get(USER, RECHNUNG).mailcow_app_pwd_id == 100
    assert state.tb_all() == []                            # tb table untouched


# ---- 3) dry-run touches nothing -------------------------------------------

def test_dry_run_reports_but_deletes_nothing(tmp_path):
    state = _db(tmp_path)
    state.tb_upsert(USER, RECHNUNG, DEVICE, mailcow_app_pwd_id=777)
    mc = FakeMailcow([USER, RECHNUNG])
    nc = FakeNextcloud(user_exists=False)

    summary = _reconcile(state, mc, nc, shared=[], tb_setup_cleanup=True,
                         dry_run=True)

    assert f"{RECHNUNG}:{DEVICE}" in summary["tb_setup_removed"]   # reported
    assert mc.deleted == []                                        # but not deleted
    assert state.tb_get(USER, RECHNUNG, DEVICE).mailcow_app_pwd_id == 777
