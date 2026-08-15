"""CRUD tests for the tb_setup_pwds table (T-009d) and its strict separation
from the authentik-sync sync_mailboxes table."""
from app.state import StateDB, TbSetupRow

USER = "cloud@lammers-krueger.de"
T1 = "rechnung@lammers-krueger.de"
T2 = "info@lammers-krueger.de"
DEV1 = "PC01~alex"
DEV2 = "PC02~alex"


def _db(tmp_path) -> StateDB:
    return StateDB(str(tmp_path / "state.db"))


def test_upsert_and_get(tmp_path):
    db = _db(tmp_path)
    db.tb_upsert(USER, T1, DEV1, mailcow_app_pwd_id=101)
    row = db.tb_get(USER, T1, DEV1)
    assert isinstance(row, TbSetupRow)
    assert row.user_email == USER
    assert row.target_email == T1
    assert row.device == DEV1
    assert row.mailcow_app_pwd_id == 101


def test_get_missing_returns_none(tmp_path):
    db = _db(tmp_path)
    assert db.tb_get(USER, T1, DEV1) is None


def test_upsert_replaces_pwd_id(tmp_path):
    # A re-run mints a fresh password: the id must be REPLACED, not COALESCE'd.
    db = _db(tmp_path)
    db.tb_upsert(USER, T1, DEV1, mailcow_app_pwd_id=101)
    db.tb_upsert(USER, T1, DEV1, mailcow_app_pwd_id=202)
    assert db.tb_get(USER, T1, DEV1).mailcow_app_pwd_id == 202


def test_device_is_part_of_the_key(tmp_path):
    db = _db(tmp_path)
    db.tb_upsert(USER, T1, DEV1, mailcow_app_pwd_id=1)
    db.tb_upsert(USER, T1, DEV2, mailcow_app_pwd_id=2)
    assert db.tb_get(USER, T1, DEV1).mailcow_app_pwd_id == 1
    assert db.tb_get(USER, T1, DEV2).mailcow_app_pwd_id == 2
    assert len(db.tb_get_for_user(USER)) == 2


def test_get_for_user_and_all(tmp_path):
    db = _db(tmp_path)
    db.tb_upsert(USER, T1, DEV1, mailcow_app_pwd_id=1)
    db.tb_upsert(USER, T2, DEV1, mailcow_app_pwd_id=2)
    db.tb_upsert("other@lammers-krueger.de", T1, DEV1, mailcow_app_pwd_id=3)

    mine = db.tb_get_for_user(USER)
    assert {r.target_email for r in mine} == {T1, T2}

    everything = db.tb_all()
    assert len(everything) == 3


def test_delete(tmp_path):
    db = _db(tmp_path)
    db.tb_upsert(USER, T1, DEV1, mailcow_app_pwd_id=1)
    db.tb_delete(USER, T1, DEV1)
    assert db.tb_get(USER, T1, DEV1) is None


def test_tb_table_is_separate_from_sync_mailboxes(tmp_path):
    # The two tables share nothing: writing tb rows must not surface in the
    # authentik-sync CRUD, and vice versa.
    db = _db(tmp_path)
    db.tb_upsert(USER, T1, DEV1, mailcow_app_pwd_id=999)
    assert db.get(USER, T1) is None            # sync_mailboxes untouched
    assert db.get_for_user(USER) == []

    db.upsert(USER, T1, mailcow_app_pwd_id=42)  # authentik-sync row
    assert db.get(USER, T1).mailcow_app_pwd_id == 42
    # tb row still has ITS own id, unaffected by the sync_mailboxes write
    assert db.tb_get(USER, T1, DEV1).mailcow_app_pwd_id == 999
