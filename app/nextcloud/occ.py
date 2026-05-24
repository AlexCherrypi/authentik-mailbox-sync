"""Thin wrapper around Nextcloud Mail's ``occ mail:account:*`` commands.

Uses ``docker exec`` because Nextcloud-AIO doesn't expose a usable REST API
for Mail-App account management. The container name is passed in from the
service config so different deployments can point to different containers.
"""
import json
import logging
import subprocess
from typing import Optional

log = logging.getLogger("sync.nextcloud")


class NextcloudError(RuntimeError):
    pass


class NextcloudClient:
    def __init__(self, container: str, timeout: float = 15.0):
        self.container = container
        self.timeout = timeout

    def _exec(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["docker", "exec", self.container, "php", "occ", *args]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.timeout,
        )
        if check and proc.returncode != 0:
            raise NextcloudError(
                f"occ {' '.join(args)} failed (rc={proc.returncode}): "
                f"stderr={proc.stderr.strip()[:500]}"
            )
        return proc

    @staticmethod
    def _parse_json_lenient(out: str) -> list:
        """occ sometimes prints warnings on stdout before the JSON. Find the
        first ``[`` or ``{`` and parse from there."""
        for i, ch in enumerate(out):
            if ch in "[{":
                try:
                    return json.loads(out[i:])
                except json.JSONDecodeError:
                    break
        return []

    def list_mail_accounts(self, user_id: str) -> list[dict]:
        proc = self._exec("mail:account:export", user_id, "--output=json", check=False)
        if proc.returncode != 0:
            log.warning("mail:account:export %s failed (rc=%s): %s",
                        user_id, proc.returncode, proc.stderr.strip()[:200])
            return []
        accounts = self._parse_json_lenient(proc.stdout)
        return [a for a in accounts if isinstance(a, dict)]

    def find_account_id(self, user_id: str, email: str) -> Optional[int]:
        for acc in self.list_mail_accounts(user_id):
            if acc.get("email") == email:
                try:
                    return int(acc["id"])
                except (KeyError, ValueError, TypeError):
                    return None
        return None

    def create_mail_account(
        self,
        user_id: str,
        email: str,
        password: str,
        imap_host: str,
        imap_port: int,
        imap_enc: str,
        smtp_host: str,
        smtp_port: int,
        smtp_enc: str,
        display_name: Optional[str] = None,
    ) -> Optional[int]:
        """Create the account and return its id (None if create succeeded but
        id couldn't be re-read).

        ``occ mail:account:create`` is positional:
            <user_id> <name> <email>
            <imap_host> <imap_port> <imap_enc> <imap_user> <imap_pwd>
            <smtp_host> <smtp_port> <smtp_enc> <smtp_user> <smtp_pwd>
        """
        name = display_name or email
        self._exec(
            "mail:account:create",
            user_id, name, email,
            imap_host, str(imap_port), imap_enc, email, password,
            smtp_host, str(smtp_port), smtp_enc, email, password,
        )
        return self.find_account_id(user_id, email)

    def delete_mail_account(self, account_id: int) -> None:
        self._exec("mail:account:delete", str(int(account_id)))
