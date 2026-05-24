"""Authentik Mailbox Sync — Flask entry point.

Endpoints:
- GET  /healthz       — liveness + dependency check (no auth)
- POST /reconcile     — single-user reconcile (X-Sync-Webhook-Token)
- POST /reconcile-all — full sweep (X-Sync-Admin-Token) — noop in this commit

Dry-run behaviour: ``SYNC_DRY_RUN=true`` env var or ``?dry_run=1`` query
param makes the service compute the diff and return what it would do without
touching Mailcow or Nextcloud. Defaults to OFF.
"""
import logging
import os
import sys

from flask import Flask, jsonify, request

from .auth import require_token
from .mailcow.api import MailcowClient
from .mailcow.db import MailcowDB
from .mailcow.dovecot import DovecotClient
from .mailcow.memcached import MemcachedClient
from .nextcloud.occ import NextcloudClient
from .reconcile import reconcile_user
from .sogo.prefs import SogoPrefs
from .state import StateDB

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sync")

app = Flask(__name__)

state = StateDB(os.environ["STATE_DB_PATH"])
mailcow = MailcowClient(
    base_url=os.environ["MAILCOW_API"],
    api_key=os.environ.get("MAILCOW_API_KEY", ""),
)
nextcloud = NextcloudClient(
    container=os.environ.get("NEXTCLOUD_CONTAINER", "nextcloud"),
)
dovecot = DovecotClient(
    container=os.environ.get("DOVECOT_CONTAINER", "dovecot-mailcow"),
)
memcached = MemcachedClient(
    host=os.environ.get("MEMCACHED_HOST")
         or os.environ.get("MEMCACHED_CONTAINER", "memcached-mailcow"),
    port=int(os.environ.get("MEMCACHED_PORT", "11211")),
)
mailcow_db = None
sogo = None
if all(os.environ.get(k) for k in ("MAILCOW_DB_HOST", "MAILCOW_DB_NAME",
                                    "MAILCOW_DB_USER", "MAILCOW_DB_PASSWORD")):
    mailcow_db = MailcowDB(
        host=os.environ["MAILCOW_DB_HOST"],
        user=os.environ["MAILCOW_DB_USER"],
        password=os.environ["MAILCOW_DB_PASSWORD"],
        database=os.environ["MAILCOW_DB_NAME"],
        port=int(os.environ.get("MAILCOW_DB_PORT", "3306")),
    )
    sogo = SogoPrefs(mailcow_db)


def _truthy(v: str) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def _dry_run() -> bool:
    return _truthy(request.args.get("dry_run", "")) or _truthy(
        os.environ.get("SYNC_DRY_RUN", "")
    )


@app.route("/healthz", methods=["GET"])
def healthz():
    out = {"status": "ok", "db": "ok", "mailcow_api": "unknown"}
    code = 200

    try:
        with state.conn() as c:
            c.execute("SELECT 1").fetchone()
    except Exception as exc:
        out["db"] = f"error: {exc}"
        out["status"] = "degraded"
        code = 503

    if os.environ.get("MAILCOW_API_KEY"):
        try:
            mailcow.list_mailboxes()
            out["mailcow_api"] = "reachable"
        except Exception as exc:
            out["mailcow_api"] = f"error: {exc}"
            out["status"] = "degraded"
            code = 503
    else:
        out["mailcow_api"] = "skipped (no API key configured)"

    return jsonify(out), code


@app.route("/reconcile", methods=["POST"])
@require_token("SYNC_WEBHOOK_SECRET")
def reconcile():
    payload = request.get_json(silent=True) or {}
    dry_run = _dry_run()
    log.info("reconcile user=%s dry_run=%s", payload.get("email"), dry_run)
    try:
        result = reconcile_user(
            payload,
            state=state,
            mailcow=mailcow,
            nextcloud=nextcloud,
            dovecot=dovecot,
            memcached=memcached,
            mailcow_db=mailcow_db,
            sogo=sogo,
            our_domain=os.environ["OUR_DOMAIN"],
            imap_host=os.environ["IMAP_HOST"],
            imap_port=int(os.environ.get("IMAP_PORT", "993")),
            imap_enc=os.environ.get("IMAP_ENCRYPTION", "ssl"),
            smtp_host=os.environ["SMTP_HOST"],
            smtp_port=int(os.environ.get("SMTP_PORT", "465")),
            smtp_enc=os.environ.get("SMTP_ENCRYPTION", "ssl"),
            dry_run=dry_run,
        )
    except Exception as exc:
        log.exception("reconcile crashed for user=%s", payload.get("email"))
        return jsonify({"error": str(exc)}), 500

    code = 207 if result.get("errors") else result.get("code", 200)
    return jsonify(result), code


@app.route("/reconcile-all", methods=["POST"])
@require_token("SYNC_ADMIN_TOKEN")
def reconcile_all():
    log.info("reconcile-all called — skeleton noop (sweep lands in task 008)")
    return jsonify({"status": "noop", "todo": "task-008"}), 200
