"""Nextcloud Mail DB provisioning: ManageSieve settings.

Nextcloud-AIO's Mail app keeps per-account config in the Postgres table
``oc_mail_accounts``. Neither ``occ`` nor a REST endpoint lets us set the
ManageSieve coordinates, so we write those columns directly via
``docker exec ... psql`` into the Nextcloud database container — exactly the
same "shell into the container" pattern the Dovecot (``doveadm``) and occ
wrappers already use. The DB container authenticates the local ``psql`` client
over its Unix socket (peer / trust auth), so no DB password is needed.

``ensure_sieve_settings`` points the account at the ManageSieve server. It is
idempotent (SELECT, diff, only UPDATE on drift) and dry-run aware.
``sieve_user`` and ``sieve_password`` are left NULL on purpose: Nextcloud Mail
5.x then falls back to the account's already-stored (encrypted) IMAP
credentials for the Sieve login, so we never have to touch Nextcloud's crypto.

Security note: the account id is always something *we* determine from
``(user_id, email)`` and coerce through ``int()`` before it ever reaches SQL;
the ManageSieve host/port/mode come from the environment but are validated
(host charset, numeric port, mode enum) before being interpolated, so a
hostile value raises instead of producing an injection. String literals we do
interpolate (user_id, email) go through ``_sql_str`` which doubles quotes;
PostgreSQL runs with ``standard_conforming_strings`` on, so that is sufficient.
"""
import logging
import re
import subprocess
from typing import Optional

log = logging.getLogger("sync.nextcloud.sieve")

# Hostname / IPv4 charset — deliberately strict: letters, digits, dot, dash,
# underscore only. Rejects quotes, semicolons, whitespace, backslashes, i.e.
# anything that could break out of the single-quoted SQL literal.
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

# ManageSieve TLS modes Nextcloud Mail accepts in ``sieve_ssl_mode``.
_VALID_SSL_MODES = ("none", "ssl", "tls")


class NextcloudMailDBError(RuntimeError):
    pass


class NextcloudMailDB:
    """Direct read/modify of ``oc_mail_accounts`` via
    ``docker exec <container> psql``.

    The container name / DB name / DB user are passed in from the service
    config so different deployments can point at different containers."""

    def __init__(self, container: str, db_name: str, db_user: str,
                 timeout: float = 15.0):
        self.container = container
        self.db_name = db_name
        self.db_user = db_user
        self.timeout = timeout

    # ---- low-level -------------------------------------------------------

    def _psql(self, sql: str, check: bool = True) -> subprocess.CompletedProcess:
        """Run *sql* in the NC DB container. ``-t`` tuples-only, ``-A``
        unaligned, ``-F '\\t'`` tab field separator → one output line per row,
        columns split by tab, NULL rendered as empty string."""
        cmd = [
            "docker", "exec", self.container,
            "psql", "-U", self.db_user, "-d", self.db_name,
            "-t", "-A", "-F", "\t", "-c", sql,
        ]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.timeout,
        )
        if check and proc.returncode != 0:
            raise NextcloudMailDBError(
                f"psql failed (rc={proc.returncode}): "
                f"stderr={proc.stderr.strip()[:500]}"
            )
        return proc

    @staticmethod
    def _rows(proc: subprocess.CompletedProcess) -> list[list[str]]:
        rows: list[list[str]] = []
        for line in proc.stdout.splitlines():
            if line == "":
                continue
            rows.append(line.split("\t"))
        return rows

    # ---- validation / quoting -------------------------------------------

    @staticmethod
    def _sql_str(value: str) -> str:
        """Single-quote *value* as a SQL string literal, doubling embedded
        quotes. Rejects NUL bytes outright."""
        s = str(value)
        if "\x00" in s:
            raise NextcloudMailDBError("NUL byte in SQL string literal")
        return "'" + s.replace("'", "''") + "'"

    @staticmethod
    def _validate_host(host: str) -> str:
        if not host or not _HOST_RE.match(host):
            raise NextcloudMailDBError(f"invalid SIEVE_HOST {host!r}")
        return host

    @staticmethod
    def _validate_port(port) -> int:
        try:
            p = int(port)
        except (TypeError, ValueError) as e:
            raise NextcloudMailDBError(f"invalid SIEVE_PORT {port!r}") from e
        if not (1 <= p <= 65535):
            raise NextcloudMailDBError(f"SIEVE_PORT out of range: {p}")
        return p

    @staticmethod
    def _validate_ssl_mode(mode: str) -> str:
        m = (mode or "").strip().lower()
        if m not in _VALID_SSL_MODES:
            raise NextcloudMailDBError(
                f"invalid SIEVE_SSL_MODE {mode!r} (allowed: {_VALID_SSL_MODES})"
            )
        return m

    # ---- account lookup --------------------------------------------------

    def get_account_id(self, user_id: str, email: str) -> Optional[int]:
        """Return the ``oc_mail_accounts.id`` for (*user_id*, *email*), or
        None if there is no unique match. This is our own determination of the
        id — callers rely on it being an int before it is used in any write."""
        sql = (
            "SELECT id FROM oc_mail_accounts "
            f"WHERE user_id = {self._sql_str(user_id)} "
            f"AND email = {self._sql_str(email)};"
        )
        proc = self._psql(sql, check=False)
        if proc.returncode != 0:
            log.warning("get_account_id(%s, %s) failed: %s",
                        user_id, email, proc.stderr.strip()[:200])
            return None
        rows = self._rows(proc)
        if len(rows) != 1:
            if len(rows) > 1:
                log.warning("get_account_id(%s, %s): %d rows, ambiguous — skipping",
                            user_id, email, len(rows))
            return None
        try:
            return int(rows[0][0])
        except (ValueError, IndexError):
            return None

    # ---- Feature 2: Sieve settings --------------------------------------

    def ensure_sieve_settings(self, account_id: int, *, host: str, port: int,
                              ssl_mode: str, dry_run: bool = False) -> bool:
        """Ensure the account's Sieve columns match the desired coordinates
        (enabled, host, port, ssl_mode) with ``sieve_user`` / ``sieve_password``
        left NULL. Idempotent: returns False when already correct, True when a
        change was made (or would be made in dry-run)."""
        aid = int(account_id)
        host = self._validate_host(host)
        port = self._validate_port(port)
        ssl_mode = self._validate_ssl_mode(ssl_mode)

        proc = self._psql(
            "SELECT sieve_enabled, sieve_host, sieve_port, sieve_ssl_mode, "
            f"sieve_user, sieve_password FROM oc_mail_accounts WHERE id = {aid};",
            check=False,
        )
        if proc.returncode != 0:
            raise NextcloudMailDBError(
                f"sieve SELECT for account {aid} failed: "
                f"{proc.stderr.strip()[:200]}"
            )
        rows = self._rows(proc)
        if not rows:
            log.info("ensure_sieve_settings: account id=%s not found — skipping", aid)
            return False

        cur = rows[0]
        # Pad short rows defensively (trailing NULLs already collapse to '').
        cur += [""] * (6 - len(cur))
        cur_enabled, cur_host, cur_port, cur_mode, cur_user, cur_pass = cur[:6]

        already = (
            cur_enabled == "t"
            and cur_host == host
            and cur_port == str(port)
            and cur_mode == ssl_mode
            and cur_user == ""
            and cur_pass == ""
        )
        if already:
            log.debug("sieve settings already correct for account id=%s", aid)
            return False

        log.info(
            "sieve settings SET account id=%s -> enabled=t host=%s port=%s "
            "ssl_mode=%s user=NULL pass=NULL (was enabled=%s host=%s port=%s "
            "ssl_mode=%s) (dry_run=%s)",
            aid, host, port, ssl_mode, cur_enabled or "NULL", cur_host or "NULL",
            cur_port or "NULL", cur_mode or "NULL", dry_run,
        )
        if dry_run:
            return True

        self._psql(
            "UPDATE oc_mail_accounts SET "
            "sieve_enabled = true, "
            f"sieve_host = {self._sql_str(host)}, "
            f"sieve_port = {port}, "
            f"sieve_ssl_mode = {self._sql_str(ssl_mode)}, "
            "sieve_user = NULL, sieve_password = NULL "
            f"WHERE id = {aid};"
        )
        return True
