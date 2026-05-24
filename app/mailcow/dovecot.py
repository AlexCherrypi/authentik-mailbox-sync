"""Thin wrapper around ``docker exec ... doveadm`` for Dovecot ACL changes.

Mailcow's Dovecot doesn't expose an API for ACLs, so we shell into the
container. The container name is configurable so different deployments can
point to different containers."""
import logging
import subprocess
from typing import Iterable

log = logging.getLogger("sync.dovecot")

# Top-level container folder names that should never get per-user ACLs.
_SYSTEM_FOLDERS = {"Shared", "shared", "Public", "public"}

# Default rights granted to a shared user — lookup + read on the folder.
DEFAULT_RIGHTS: tuple[str, ...] = ("lookup", "read")


class DovecotError(RuntimeError):
    pass


class DovecotClient:
    def __init__(self, container: str, timeout: float = 30.0):
        self.container = container
        self.timeout = timeout

    def _exec(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["docker", "exec", self.container, "doveadm", *args]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=self.timeout,
        )
        if check and proc.returncode != 0:
            raise DovecotError(
                f"doveadm {' '.join(args)} failed (rc={proc.returncode}): "
                f"stderr={proc.stderr.strip()[:500]}"
            )
        return proc

    # ---- folders ---------------------------------------------------------

    def list_folders(self, mailbox: str) -> list[str]:
        """Return non-system folders for *mailbox*."""
        proc = self._exec("mailbox", "list", "-u", mailbox)
        folders = []
        for line in proc.stdout.strip().splitlines():
            f = line.strip()
            if not f:
                continue
            last = f.split("/")[-1]
            if last in _SYSTEM_FOLDERS:
                continue
            folders.append(f)
        return folders

    # ---- ACL probes ------------------------------------------------------

    def has_acl_for_user(self, mailbox: str, user: str) -> bool:
        """Cheap check: does *user* have any ACL on the mailbox INBOX?

        Used as a coarse "is sharing in place?" probe. The full grant/revoke
        operations always walk all folders, so this only decides whether we
        need to walk at all."""
        proc = self._exec("acl", "list", "-u", mailbox, "INBOX", check=False)
        if proc.returncode != 0:
            return False
        needle = f"user={user}"
        for line in proc.stdout.splitlines():
            if needle in line:
                return True
        return False

    # ---- ACL writes ------------------------------------------------------

    def grant(self, mailbox: str, user: str,
              rights: Iterable[str] = DEFAULT_RIGHTS) -> None:
        """Set *rights* for *user* on every non-system folder of *mailbox*."""
        for folder in self.list_folders(mailbox):
            args = ["acl", "set", "-u", mailbox, folder, f"user={user}", *rights]
            proc = self._exec(*args, check=False)
            if proc.returncode != 0:
                log.warning("doveadm acl set failed for %s/%s user=%s: %s",
                            mailbox, folder, user, proc.stderr.strip()[:200])

    def revoke(self, mailbox: str, user: str) -> None:
        """Remove all ACLs for *user* on every non-system folder of *mailbox*.

        Tolerates the "ACL does not exist" exit, which doveadm returns when
        nothing was set in the first place."""
        for folder in self.list_folders(mailbox):
            args = ["acl", "delete", "-u", mailbox, folder, f"user={user}"]
            proc = self._exec(*args, check=False)
            if proc.returncode != 0:
                # not-found is acceptable (idempotent revoke)
                stderr = proc.stderr.strip()
                if "no such" in stderr.lower() or "not found" in stderr.lower():
                    continue
                log.warning("doveadm acl delete failed for %s/%s user=%s: %s",
                            mailbox, folder, user, stderr[:200])
