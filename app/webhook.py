"""Authentik Mailbox Reconciler — Flask entry point.

Endpoints in Phase 1:
- GET  /healthz       — liveness + dependency check (no auth)
- POST /reconcile     — single-user webhook (HMAC-style token in Task 003)
- POST /reconcile-all — full sweep, called by TrueNAS cron (admin token in Task 008)

Current state: skeleton only. /reconcile and /reconcile-all return 200 noop.
"""
import logging
import os
import sys

from flask import Flask, jsonify

from .mailcow.api import MailcowClient
from .state import StateDB

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("reconciler")

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
def reconcile():
    log.info("reconcile called — skeleton noop (auth+logic land in tasks 003+004)")
    return jsonify({"status": "noop", "todo": "tasks-003-004"}), 200


@app.route("/reconcile-all", methods=["POST"])
def reconcile_all():
    log.info("reconcile-all called — skeleton noop (sweep lands in task 008)")
    return jsonify({"status": "noop", "todo": "task-008"}), 200
