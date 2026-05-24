"""Reconcile-Core: bring Mailcow + Nextcloud into agreement with the
Authentik view for one user.

Scope of this module (Task 004):
- App-Password lifecycle in Mailcow (create with marker prefix, delete by id)
- Nextcloud Mail account lifecycle (create with that password, delete by id)
- State-DB tracking
- Marker-based adoption when state is lost

NOT in scope here:
- sender_acl symmetric updates  (Task 005)
- Dovecot ACLs                  (Task 005)
- SOGo delegations              (Task 006)
- /reconcile-all sweep          (Task 008)
"""
import logging
import secrets
from typing import Optional

from .locks import per_key_lock
from .state import StateDB

log = logging.getLogger("sync.reconcile")

MARKER_PREFIX = "authentik-sync:"


def _generate_password() -> str:
    """Random 20-byte URL-safe token. Reroll if it would start with ``-``
    (some CLIs treat that as a flag and refuse to handle it as a value)."""
    while True:
        pwd = secrets.token_urlsafe(20)
        if not pwd.startswith("-"):
            return pwd


def _marker_for(user_email: str, target_email: str) -> str:
    return f"{MARKER_PREFIX}{user_email}:{target_email}"


def _looks_like_our_marker(name: str, user_email: str) -> Optional[str]:
    """Return the target email if *name* matches our marker for *user_email*,
    else None."""
    prefix = f"{MARKER_PREFIX}{user_email}:"
    if name and name.startswith(prefix):
        return name[len(prefix):]
    return None


def adopt_from_markers(
    user_email: str,
    *,
    mailcow,
    nextcloud,
    state: StateDB,
    our_domain: str,
    dry_run: bool = False,
) -> list[dict]:
    """Scan Mailcow app-passwords for our marker prefix and rebuild the
    state-DB rows for *user_email*. Used after a state-DB loss or as a
    "first time we see this user" recovery path.

    Returns a list of ``{user_email, target_email, mailcow_app_pwd_id,
    nc_account_id}`` dicts. In dry-run mode, no DB writes happen but the
    return value still shows what would be adopted."""
    rows: list[dict] = []
    for mb in mailcow.list_mailboxes():
        target = mb.get("username")
        if not target or not target.endswith("@" + our_domain):
            continue
        try:
            app_pwds = mailcow.list_app_passwds(target)
        except Exception:
            log.exception("adopt: list_app_passwds(%s) failed", target)
            continue
        for ap in app_pwds:
            if _looks_like_our_marker(ap.get("name"), user_email) != target:
                continue
            try:
                ap_id = int(ap["id"])
            except (KeyError, ValueError, TypeError):
                log.warning("adopt: app-pwd entry without usable id: %s", ap)
                continue
            nc_id = None
            try:
                nc_id = nextcloud.find_account_id(user_email, target)
            except Exception:
                log.exception("adopt: nextcloud lookup failed for %s/%s",
                              user_email, target)
            if not dry_run:
                state.upsert(user_email, target,
                             mailcow_app_pwd_id=ap_id, nc_account_id=nc_id)
            rows.append({
                "user_email": user_email,
                "target_email": target,
                "mailcow_app_pwd_id": ap_id,
                "nc_account_id": nc_id,
            })
    if rows:
        log.info("adopted %d targets for user=%s from markers", len(rows), user_email)
    return rows


def reconcile_user(
    payload: dict,
    *,
    state: StateDB,
    mailcow,
    nextcloud,
    dovecot=None,
    memcached=None,
    mailcow_db=None,
    sogo=None,
    our_domain: str,
    imap_host: str,
    imap_port: int,
    imap_enc: str,
    smtp_host: str,
    smtp_port: int,
    smtp_enc: str,
    dry_run: bool = False,
) -> dict:
    """Reconcile one user's mailbox claims against Mailcow + Nextcloud.

    Payload keys (we accept the union of the historical formats):
        - email          (required) — canonical user identifier
        - primary_email  (optional, defaults to email)
        - additional_emails OR shared_mailboxes (optional list)
    """
    user_email = (payload or {}).get("email")
    if not user_email:
        return {"error": "missing required field: email", "code": 400}

    primary = payload.get("primary_email") or user_email
    extra = payload.get("additional_emails") or payload.get("shared_mailboxes") or []

    desired_raw = {primary, *extra}
    desired = {e for e in desired_raw if isinstance(e, str) and e.endswith("@" + our_domain)}

    summary = {
        "user_email": user_email,
        "dry_run": dry_run,
        "desired": sorted(desired),
        "adopted": [],
        "added": [],
        "removed": [],
        "skipped_unknown_mailbox": [],
        "skipped_nc_user_missing": False,
        "sender_acl_added": [],
        "sender_acl_removed": [],
        "acl_granted": [],
        "acl_revoked": [],
        "sogo_delegate_from_set": False,
        "sogo_delegate_to_added": [],
        "sogo_delegate_to_removed": [],
        "memcached_flushed": False,
        "errors": [],
    }

    with per_key_lock(user_email):
        try:
            all_mailboxes = mailcow.list_mailboxes()
        except Exception as exc:
            summary["errors"].append(f"mailcow.list_mailboxes: {exc}")
            log.exception("list_mailboxes failed for user=%s", user_email)
            return summary

        existing_mbs = {mb["username"] for mb in all_mailboxes
                        if mb.get("username", "").endswith("@" + our_domain)}
        actionable = desired & existing_mbs
        unknown = desired - existing_mbs
        summary["skipped_unknown_mailbox"] = sorted(unknown)

        current_rows = state.get_for_user(user_email)
        if not current_rows:
            adopted = adopt_from_markers(
                user_email, mailcow=mailcow, nextcloud=nextcloud,
                state=state, our_domain=our_domain, dry_run=dry_run,
            )
            summary["adopted"] = [r["target_email"] for r in adopted]
            if dry_run:
                # State wasn't persisted; use adopted dicts for the diff
                current_targets = {r["target_email"] for r in adopted}
            else:
                current_rows = state.get_for_user(user_email)
                current_targets = {r.target_email for r in current_rows}
        else:
            current_targets = {r.target_email for r in current_rows}

        to_add = sorted(actionable - current_targets)
        to_remove = sorted(current_targets - actionable)

        # Adds need a working Nextcloud user — the App-Password + NC mail
        # account come as a pair (the App-Password only exists so the NC
        # mail account can authenticate against IMAP). When the user
        # hasn't logged into Nextcloud yet, NC has no user record for them,
        # so the create would always fail and we'd churn through
        # add-then-rollback for every target. Detect that once and skip
        # the loop. The sharing-side (sender_acl, Dovecot ACL, SOGo
        # delegations) still runs — those are Mailcow-only and let the
        # user reach the shared mailboxes via SOGo webmail right away.
        if to_add and not dry_run:
            try:
                nc_user_present = nextcloud.user_exists(user_email)
            except Exception as exc:
                log.warning("nextcloud.user_exists(%s) failed (%s); falling back "
                            "to attempting adds individually", user_email, exc)
                nc_user_present = True  # fall through to old behavior
            if not nc_user_present:
                log.info("NC user %s does not exist — skipping %d add(s); "
                         "will self-heal once the user first logs into Nextcloud",
                         user_email, len(to_add))
                summary["skipped_nc_user_missing"] = True
                to_add = []

        for target in to_add:
            try:
                _add_target(
                    user_email, target,
                    state=state, mailcow=mailcow, nextcloud=nextcloud,
                    imap_host=imap_host, imap_port=imap_port, imap_enc=imap_enc,
                    smtp_host=smtp_host, smtp_port=smtp_port, smtp_enc=smtp_enc,
                    dry_run=dry_run,
                )
                summary["added"].append(target)
            except Exception as exc:
                summary["errors"].append(f"add {target}: {exc}")
                log.exception("add %s for user %s failed", target, user_email)

        for target in to_remove:
            try:
                _remove_target(
                    user_email, target,
                    state=state, mailcow=mailcow, nextcloud=nextcloud,
                    dry_run=dry_run,
                )
                summary["removed"].append(target)
            except Exception as exc:
                summary["errors"].append(f"remove {target}: {exc}")
                log.exception("remove %s for user %s failed", target, user_email)

        # Sharing-side reconcile (sender_acl + Dovecot ACL) — independent of
        # app-pwd lifecycle. desired_shared excludes the user's own mailbox.
        desired_shared = actionable - {user_email}
        sharing_changed = _reconcile_sharing(
            user_email, desired_shared,
            all_mailboxes=all_mailboxes,
            mailcow=mailcow, mailcow_db=mailcow_db, dovecot=dovecot,
            sogo=sogo,
            our_domain=our_domain, dry_run=dry_run,
            summary=summary,
        )

        if memcached is not None and sharing_changed and not dry_run:
            if memcached.flush_all():
                summary["memcached_flushed"] = True

        if not dry_run:
            state.touch_user(user_email)

    return summary


def _reconcile_sharing(
    user_email: str,
    desired_shared: set[str],
    *,
    all_mailboxes: list[dict],
    mailcow,
    mailcow_db,
    dovecot,
    sogo,
    our_domain: str,
    dry_run: bool,
    summary: dict,
) -> bool:
    """Walk every LKS-domain mailbox (except the user's own) and bring its
    ``sender_acl`` + Dovecot ACLs into agreement with *desired_shared* for the
    *user_email* slice.

    Other entries in those ACLs (other users, manual entries) are not touched.

    Returns True if anything actually changed (used to decide if memcached
    needs flushing)."""
    changed = False

    # Read current sender_acl rows once (mailcow REST has no read endpoint, so
    # we hit the DB directly). Skip sender_acl handling entirely if no DB
    # client was configured.
    sender_acls: dict[str, set[str]] = {}
    if mailcow_db is not None:
        try:
            sender_acls = mailcow_db.get_all_sender_acls()
        except Exception as exc:
            summary["errors"].append(f"mailcow_db.get_all_sender_acls: {exc}")
            log.exception("get_all_sender_acls failed")

    # Read SOGo's current DelegateTo for every mailbox once (so per-mailbox
    # decisions don't each hit the DB). Empty dict if no SOGo client.
    sogo_delegate_to: dict[str, set[str]] = {}
    if sogo is not None:
        try:
            sogo_delegate_to = sogo.get_all_delegate_to()
        except Exception as exc:
            summary["errors"].append(f"sogo.get_all_delegate_to: {exc}")
            log.exception("get_all_delegate_to failed")

    # The user's own Mail.DelegateFrom + Mail.OtherUsersFolders should mirror
    # desired_shared. Compute the diff up front so per-mailbox loop only
    # handles DelegateTo on the *other* side.
    if sogo is not None:
        try:
            current_df = sogo.get_delegate_from(user_email)
            if current_df != desired_shared:
                log.info("sogo DelegateFrom %s: %s -> %s",
                         user_email, sorted(current_df), sorted(desired_shared))
                if not dry_run:
                    try:
                        sogo.set_user_delegate_from(user_email, desired_shared)
                    except Exception as exc:
                        summary["errors"].append(
                            f"sogo.set_user_delegate_from {user_email}: {exc}")
                    else:
                        summary["sogo_delegate_from_set"] = True
                        changed = True
                else:
                    summary["sogo_delegate_from_set"] = True
                    changed = True
        except Exception as exc:
            summary["errors"].append(f"sogo.get_delegate_from {user_email}: {exc}")
            log.exception("get_delegate_from failed")

    for mb in all_mailboxes:
        target = mb.get("username", "")
        if not target.endswith("@" + our_domain) or target == user_email:
            continue

        want = target in desired_shared
        current_acl = sender_acls.get(target, set())

        # --- sender_acl ---
        if want and user_email not in current_acl:
            log.info("sender_acl ADD: %s on %s (dry_run=%s)",
                     user_email, target, dry_run)
            if not dry_run:
                try:
                    new_acl = sorted(current_acl | {user_email})
                    mailcow.edit_mailbox_sender_acl(target, new_acl)
                except Exception as exc:
                    summary["errors"].append(f"sender_acl add {target}: {exc}")
                    continue
            summary["sender_acl_added"].append(target)
            changed = True
        elif (not want) and user_email in current_acl:
            log.info("sender_acl DEL: %s on %s (dry_run=%s)",
                     user_email, target, dry_run)
            if not dry_run:
                try:
                    new_acl = sorted(current_acl - {user_email})
                    mailcow.edit_mailbox_sender_acl(target, new_acl)
                except Exception as exc:
                    summary["errors"].append(f"sender_acl del {target}: {exc}")
                    continue
            summary["sender_acl_removed"].append(target)
            changed = True

        # --- Dovecot folder ACLs ---
        if dovecot is None:
            continue
        try:
            currently_has = dovecot.has_acl_for_user(target, user_email)
        except Exception as exc:
            summary["errors"].append(f"dovecot probe {target}: {exc}")
            log.exception("dovecot has_acl_for_user(%s, %s) failed",
                          target, user_email)
            continue

        if want and not currently_has:
            log.info("dovecot GRANT: %s on %s (dry_run=%s)",
                     user_email, target, dry_run)
            if not dry_run:
                try:
                    dovecot.grant(target, user_email)
                except Exception as exc:
                    summary["errors"].append(f"dovecot grant {target}: {exc}")
                    continue
            summary["acl_granted"].append(target)
            changed = True
        elif (not want) and currently_has:
            log.info("dovecot REVOKE: %s on %s (dry_run=%s)",
                     user_email, target, dry_run)
            if not dry_run:
                try:
                    dovecot.revoke(target, user_email)
                except Exception as exc:
                    summary["errors"].append(f"dovecot revoke {target}: {exc}")
                    continue
            summary["acl_revoked"].append(target)
            changed = True

        # --- SOGo Mail.DelegateTo on the shared mailbox's profile ---
        if sogo is None:
            continue
        current_dt = sogo_delegate_to.get(target, set())
        if want and user_email not in current_dt:
            log.info("sogo DelegateTo ADD: %s on %s (dry_run=%s)",
                     user_email, target, dry_run)
            if not dry_run:
                try:
                    sogo.add_user_to_mailbox_delegate_to(target, user_email)
                except Exception as exc:
                    summary["errors"].append(f"sogo DelegateTo add {target}: {exc}")
                    continue
            summary["sogo_delegate_to_added"].append(target)
            changed = True
        elif (not want) and user_email in current_dt:
            log.info("sogo DelegateTo DEL: %s on %s (dry_run=%s)",
                     user_email, target, dry_run)
            if not dry_run:
                try:
                    sogo.remove_user_from_mailbox_delegate_to(target, user_email)
                except Exception as exc:
                    summary["errors"].append(f"sogo DelegateTo del {target}: {exc}")
                    continue
            summary["sogo_delegate_to_removed"].append(target)
            changed = True

    return changed


def _add_target(
    user_email: str,
    target: str,
    *,
    state: StateDB,
    mailcow,
    nextcloud,
    imap_host: str,
    imap_port: int,
    imap_enc: str,
    smtp_host: str,
    smtp_port: int,
    smtp_enc: str,
    dry_run: bool,
) -> None:
    log.info("ADD user=%s target=%s dry_run=%s", user_email, target, dry_run)
    if dry_run:
        return
    password = _generate_password()
    app_name = _marker_for(user_email, target)
    pwd_id = mailcow.add_app_passwd(target, app_name, password)
    try:
        nc_id = nextcloud.create_mail_account(
            user_email, target, password,
            imap_host, imap_port, imap_enc,
            smtp_host, smtp_port, smtp_enc,
        )
    except Exception:
        # Roll back the Mailcow app-password so we don't leak it
        try:
            mailcow.delete_app_passwd([pwd_id])
        except Exception:
            log.exception("rollback delete_app_passwd %s failed", pwd_id)
        raise
    state.upsert(user_email, target,
                 mailcow_app_pwd_id=pwd_id, nc_account_id=nc_id)


def _remove_target(
    user_email: str,
    target: str,
    *,
    state: StateDB,
    mailcow,
    nextcloud,
    dry_run: bool,
) -> None:
    log.info("REMOVE user=%s target=%s dry_run=%s", user_email, target, dry_run)
    if dry_run:
        return
    row = state.get(user_email, target)
    if row is None:
        log.warning("remove called but no state row for user=%s target=%s",
                    user_email, target)
        return
    # Delete NC first so the user can't keep using the password we'd remove next.
    if row.nc_account_id is not None:
        try:
            nextcloud.delete_mail_account(row.nc_account_id)
        except Exception:
            log.exception("delete_mail_account(%s) failed", row.nc_account_id)
    if row.mailcow_app_pwd_id is not None:
        try:
            mailcow.delete_app_passwd([row.mailcow_app_pwd_id])
        except Exception:
            log.exception("delete_app_passwd(%s) failed", row.mailcow_app_pwd_id)
    state.delete(user_email, target)
