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
| Dovecot ACLs         | `doveadm acl set` / `delete` on shared mailbox folders for the user; plus a defensive **self-entry guard** that removes any stray `user=<owner>` ACL on the owner's own mailbox |
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
| GET    | `/my-accounts`   | OIDC access-JWT (Bearer)      | Per-user mailbox provisioning for the Thunderbird setup tool (opt-in) |

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

## Dovecot ACL self-entry guard

During the sharing reconcile the service also removes any **self-entry** it
finds — a `user=<owner>` ACL row sitting on a folder of that same owner's
mailbox. Such an entry is always wrong: the owner already has implicit full
access, and a stale `user=<owner>` row (an old-import artefact — the service
never creates one) can silently flip the mailbox into read-only. For every
managed target the guard probes each folder with `doveadm acl get` first and
only issues `doveadm acl delete user=<owner>` where a self-entry actually
exists (idempotent, never a blind delete, dry-run aware). Removals surface in
the reconcile summary as `acl_self_entries_removed`.

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

## `GET /my-accounts` — Thunderbird setup tool (T-009d)

An OIDC-authenticated, per-user endpoint used by the *LK-Mail-Einrichtung*
Thunderbird setup tool. The tool logs the user in against Authentik (Auth Code +
PKCE) and calls this endpoint with the resulting **access-JWT** as a
`Authorization: Bearer` header. The token is validated **locally** against the
provider's JWKS (`app/oidc.py`: RS256, `iss`/`aud`/`exp`/`nbf`/`iat`); `aud` is
the client_id of the dedicated *mail-setup* provider, so tokens minted for any
other application are worthless here.

Identity and entitlements are read straight from the token claims (`email`,
`name`, `preferred_username`, and the `shared_mailboxes` claim, which mirrors the
AMS-internal aggregation). For each entitled mailbox that actually exists in
Mailcow the endpoint **mints a fresh App-Password** named
`tb-setup:<user>:<target>:<device>` and returns it once, in plaintext, in the
response — it is never logged or stored (only the Mailcow id is kept in state).

- **`device`** (required) — `?device=<id>` query param or `X-Device-Id` header;
  the tool sends `<hostname>~<winuser>` (D-008 scope). A re-run for the same
  `(user, target, device)` **replaces** the previous password (no sprawl).
- **Naming invariant** — tb-setup passwords use the `tb-setup:` prefix and
  **never** `authentik-sync:`. That keeps them out of the authentik-sync
  lifecycle: `adopt_from_markers` only adopts `authentik-sync:*`, and the
  authentik-sync remove path only deletes state-tracked ids. Enforced by tests
  in `tests/test_tb_sweep_cleanup.py`.
- **Salutation templates** (D-007) — the response carries the two variants
  (`firmenanrede`, `persoenliche_anrede`) read fresh per request from the
  JSON file at `SIGNATURES_CONFIG_PATH` (a mounted volume — see
  [`signatures.example.json`](signatures.example.json)). The `{{name}}`
  placeholder is delivered raw; the client substitutes the real display name.

Response shape:

```json
{
  "user": {"email": "...", "name": "...", "preferred_username": "..."},
  "accounts": [
    {"email": "...", "is_primary": true,
     "imap": {"host": "...", "port": 993, "security": "ssl"},
     "smtp": {"host": "...", "port": 587, "security": "starttls"},
     "username": "...", "app_password": "<plaintext, once>"}
  ],
  "skipped_unknown": ["claimed-but-no-mailbox@..."],
  "signatures": {"firmenanrede": {...}, "persoenliche_anrede": {...}}
}
```

**Revocation** (D-005): the `/reconcile-all` sweep deletes tb-setup passwords
whose `(user, target)` entitlement has been withdrawn, so removing a user from
the Authentik group revokes already-provisioned Thunderbird clients within one
sweep. Both the endpoint and this cleanup are gated behind
`MY_ACCOUNTS_ENABLED` (default **`false`**): a deploy with the flag off serves
no endpoint and never touches `tb_setup_pwds`.

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
