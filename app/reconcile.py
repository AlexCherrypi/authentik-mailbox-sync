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
        "errors": [],
    }

    with per_key_lock(user_email):
        try:
            existing_mbs = {mb["username"] for mb in mailcow.list_mailboxes()
                            if mb.get("username", "").endswith("@" + our_domain)}
        except Exception as exc:
            summary["errors"].append(f"mailcow.list_mailboxes: {exc}")
            log.exception("list_mailboxes failed for user=%s", user_email)
            return summary

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

        if not dry_run:
            state.touch_user(user_email)

    return summary


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
