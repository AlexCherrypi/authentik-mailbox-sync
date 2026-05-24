# authentik-mailbox-sync

A small reconciliation service that takes [Authentik](https://goauthentik.io)
group claims as the source of truth and applies them to [Mailcow](https://mailcow.email)
and [Nextcloud](https://nextcloud.com) — idempotent, with cleanup of objects it
created itself.

Replaces hand-rolled "create-only" webhook scripts that drift over time because
they never remove old App-Passwords, `sender_acl` entries, or NC-Mail accounts
when a user loses access to a shared mailbox.

## Status

Skeleton. The `/healthz` endpoint and the SQLite state store are in. The actual
reconcile logic, HMAC auth and periodic sweep land in follow-up commits.

## What it does (target shape, Phase 1)

For each user the Authentik webhook (or the periodic sweep) reports, the
service computes the desired state from group attributes and applies it:

| Subsystem            | Action                                                                   |
|----------------------|--------------------------------------------------------------------------|
| Mailcow API          | maintain `sender_acl` of every shared mailbox (add + remove symmetrically)|
| Mailcow App-Passwords| create with deterministic name `authentik-sync:<user>:<target>`, delete when no longer needed |
| Dovecot ACLs         | `doveadm acl set` / `delete` on shared mailbox folders for the user      |
| SOGo settings        | `Mail.DelegateFrom` / `DelegateTo` / `OtherUsersFolders` in `sogo_user_profile.c_settings` |
| Nextcloud Mail       | `occ mail:account:create` / `delete` with the App-Password from above    |

Everything the service creates carries a marker (`app_name` prefix for App-Passwords,
state-DB entry for NC-Mail) so it can be safely identified and removed later
without touching user-created objects.

## Endpoints

| Method | Path             | Auth                          | Purpose                                   |
|--------|------------------|-------------------------------|-------------------------------------------|
| GET    | `/healthz`       | none                          | Liveness + DB + Mailcow-API reachability  |
| POST   | `/reconcile`     | `X-Authentik-Webhook-Token`   | Reconcile one user (webhook payload)      |
| POST   | `/reconcile-all` | `X-Reconciler-Admin-Token`    | Full sweep — call from cron               |

## Layout

```
.
├── Dockerfile              # gunicorn, docker-cli, mysql-client
├── requirements.txt
├── .env.example            # copy to .env (mode 600) and fill in
└── app/
    ├── webhook.py          # Flask entrypoint
    ├── state.py            # SQLite state DB (WAL)
    ├── mailcow/            # Mailcow REST + Dovecot via docker exec
    ├── nextcloud/          # `occ mail:account:*` via docker exec
    ├── sogo/               # Direct DB writes to sogo_user_profile (see note)
    └── authentik/          # GET /api/v3/core/users/ for the sweep
```

## Why SOGo via direct DB writes

`sogo-tool user-preferences set settings <user> Mail …` is documented but
[doesn't work reliably in the Mailcow container layout](https://github.com/mailcow/mailcow-dockerized/issues/6355)
(`"Value for key Mail not found in settings"` even when the row exists). The
SOGo HTTP API that landed in 5.12.2 only has two endpoints (version + DAV
URLs) — no user-preferences. So the service writes `c_settings` directly,
with `SELECT … FOR UPDATE`, JSON read-modify-write, then a memcached flush so
SOGo picks up the change immediately.

## Configuration

Every Mailcow/Nextcloud/Authentik specific value is configured via environment
variables — see [`.env.example`](.env.example) for the complete list.

The container needs:

- A network path to `nginx-mailcow` (Mailcow REST API)
- A network path to `mysql-mailcow` (for SOGo settings)
- A network path to your Authentik install (for the sweep — outbound only)
- `/var/run/docker.sock` mounted read-only (for `docker exec` into the Dovecot,
  Memcached and Nextcloud containers)
- A persistent volume for `STATE_DB_PATH`

A reference `docker compose` is intentionally **not** part of this repository —
each deployment has its own networking, container names, and user/group
permissions, so the compose file lives next to the deployment.

## Building / Running

```bash
docker build -t authentik-mailbox-sync .
docker run --rm \
  --env-file .env \
  -v $(pwd)/state:/var/lib/sync \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -p 5000:5000 \
  authentik-mailbox-sync
```

## License

MIT — see [LICENSE](LICENSE).
