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
| Nextcloud Mail (Sieve)| set ManageSieve coordinates on each managed account (`oc_mail_accounts`) so server-side filters work — opt-in via `SIEVE_PROVISIONING` |
| Nextcloud Mail (folders)| enforce `sent`/`drafts`/`trash` mapping onto the account's local folders when it has drifted (e.g. a leftover `[Gmail]` tree) |

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

## Nextcloud Mail: Sieve + folder-mapping provisioning

The App-Passwords the service creates carry `sieve_access` alongside
`imap_access` / `smtp_access`, so the very same password authenticates
ManageSieve (Dovecot's Lua auth checks the `app_passwd.sieve_access` column on
port 4190). On top of that, two DB-level steps run per managed NC-Mail account
— both idempotent, both dry-run aware, both writing via
`docker exec <NC_DB_CONTAINER> psql`:

- **Sieve settings** — set `sieve_enabled=true` and the `sieve_host` /
  `sieve_port` / `sieve_ssl_mode` columns in `oc_mail_accounts`. `sieve_user`
  and `sieve_password` are left **NULL** on purpose: Nextcloud Mail 5.x then
  falls back to the account's already-encrypted IMAP credentials for the Sieve
  login, so the service never handles NC's crypto.
- **Special-folder mapping** — make sure `sent_mailbox_id` /
  `drafts_mailbox_id` / `trash_mailbox_id` point at the account's local
  `Sent` / `Drafts` / `Trash` folders. Only an existing *wrong* mapping (e.g.
  a leftover `[Gmail]` virtual folder) is repaired, and only when the local
  folder actually exists; a NULL mapping is left for Nextcloud's own
  autodetection on first sync.

Both steps are gated behind `SIEVE_PROVISIONING` (default **`false`**). Keep it
off until the ManageSieve port is reachable from Nextcloud, then flip it to
`true` — a deploy with the flag off is a strict no-op for these steps.

Host/port/mode are validated before they reach SQL (host charset, numeric port
in range, mode ∈ {`tls`,`ssl`,`none`}); the account id is always determined by
the service from `(user_id, email)` and coerced to `int`, never taken from
caller input.

## Configuration

Every Mailcow/Nextcloud/Authentik specific value is configured via environment
variables — see [`.env.example`](.env.example) for the complete list.

The container needs:

- A network path to `nginx-mailcow` (Mailcow REST API)
- A network path to `mysql-mailcow` (for SOGo settings)
- A network path to your Authentik install (for the sweep — outbound only)
- `/var/run/docker.sock` mounted read-only (for `docker exec` into the Dovecot,
  Memcached, Nextcloud and — when `SIEVE_PROVISIONING` is on — the Nextcloud
  database containers)
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
