"""Authentik Mailbox Sync — Flask entry point.

Endpoints in Phase 1:
- GET  /healthz       — liveness + dependency check (no auth)
- POST /reconcile     — single-user webhook (X-Sync-Webhook-Token)
- POST /reconcile-all — full sweep, called by cron (X-Sync-Admin-Token)

Current state: skeleton. /reconcile and /reconcile-all return 200 noop —
the reconcile core lands in task 004 and the sweep in task 008.
"""
import logging
import os
import sys

from flask import Flask, jsonify

from .auth import require_token
from .mailcow.api import MailcowClient
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
    log.info("reconcile called — skeleton noop (logic lands in task 004)")
    return jsonify({"status": "noop", "todo": "task-004"}), 200


@app.route("/reconcile-all", methods=["POST"])
@require_token("SYNC_ADMIN_TOKEN")
def reconcile_all():
    log.info("reconcile-all called — skeleton noop (sweep lands in task 008)")
    return jsonify({"status": "noop", "todo": "task-008"}), 200
