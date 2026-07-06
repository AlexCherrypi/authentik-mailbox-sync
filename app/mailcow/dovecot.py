"""Thin wrapper around ``docker exec ... doveadm`` for Dovecot ACL changes.

Mailcow's Dovecot doesn't expose an API for ACLs, so we shell into the
container. The container name is configurable so different deployments can
point to different containers."""
import logging
import subprocess
from typing import Iterable, Optional

log = logging.getLogger("sync.dovecot")

# Container folder namespaces that must never get per-user ACLs. These are the
# *first* path component of a mailbox name: ``Shared`` and ``Public`` are
# virtual namespaces (a user's read-only view onto mailboxes owned by someone
# else) and have no local ACL file, so ``doveadm acl set`` on anything under
# them fails with "No local acl file path". The real, writable ACL lives on the
# owner's own folders (INBOX, Sent, …), which we address via ``-u <owner>``.
_SYSTEM_FOLDERS = {"Shared", "shared", "Public", "public"}

# Full set of Dovecot ACL rights we grant to a shared user — everything a
# collaborator needs to work the mailbox as their own (persist \Seen, move,
# delete, create folders) *except* ``admin`` (managing the ACLs themselves
# stays with the system / this reconciler). Order is irrelevant to doveadm.
DEFAULT_RIGHTS: tuple[str, ...] = (
    "lookup", "read", "write", "write-seen", "write-deleted",
    "insert", "post", "expunge", "create", "delete",
)

# Every ACL right name Dovecot may print, used to parse ``doveadm acl get``
# output (columns: ID, Global, Rights) robustly — anything that isn't a known
# right (e.g. a "global" flag in the Global column) is ignored.
_ALL_RIGHTS = {
    "lookup", "read", "write", "write-seen", "write-deleted",
    "insert", "post", "expunge", "create", "delete", "admin",
}


class DovecotError(RuntimeError):
    pass


class DovecotClient:
    def __init__(self, container: str, timeout: float = 30.0,
                 rights: Iterable[str] = DEFAULT_RIGHTS):
        self.container = container
        self.timeout = timeout
        # Single source of truth for "what a full grant looks like" — grant()
        # applies it and the reconciler compares against it to decide whether
        # an existing (possibly stale/partial) grant needs upgrading.
        self.default_rights: tuple[str, ...] = tuple(rights)

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
        """Return the mailbox's own (non-system) folders.

        Excludes the entire ``Shared/`` and ``Public/`` namespaces — a mailbox
        that is itself a sharee of others lists those virtual folders too, and
        setting an ACL on them is both impossible (no local ACL file) and
        wrong (the grant belongs on the owner side)."""
        proc = self._exec("mailbox", "list", "-u", mailbox)
        folders = []
        for line in proc.stdout.strip().splitlines():
            f = line.strip()
            if not f:
                continue
            first = f.split("/")[0]
            if first in _SYSTEM_FOLDERS:
                continue
            folders.append(f)
        return folders

    # ---- ACL probes ------------------------------------------------------

    def get_rights_for_user(self, mailbox: str, user: str) -> set[str]:
        """Return the ACL rights *user* currently holds on *mailbox* INBOX.

        Empty set if the user has no ACL (or the probe can't run). Used both
        as the "is sharing in place?" gate and to detect a stale/partial grant
        that needs upgrading to the full rights set. INBOX is a representative
        probe — the grant/revoke operations walk every folder."""
        proc = self._exec("acl", "get", "-u", mailbox, "INBOX", check=False)
        if proc.returncode != 0:
            return set()
        needle = f"user={user}"
        rights: set[str] = set()
        for line in proc.stdout.splitlines():
            parts = line.split()
            # Row shape: "<id> [global] <right> <right> …". Non-global per-user
            # ACLs leave the Global column blank, so it collapses under split().
            if parts and parts[0] == needle:
                rights |= set(parts[1:]) & _ALL_RIGHTS
        return rights

    def has_acl_for_user(self, mailbox: str, user: str) -> bool:
        """Coarse check: does *user* have *any* ACL on the mailbox INBOX?"""
        return bool(self.get_rights_for_user(mailbox, user))

    # ---- ACL writes ------------------------------------------------------

    def grant(self, mailbox: str, user: str,
              rights: Optional[Iterable[str]] = None) -> None:
        """Set *rights* (default: the full grant set) for *user* on every
        non-system folder of *mailbox*. Re-running upgrades an existing partial
        grant in place, since ``acl set`` replaces the user's rights."""
        use = tuple(rights) if rights is not None else self.default_rights
        for folder in self.list_folders(mailbox):
            args = ["acl", "set", "-u", mailbox, folder, f"user={user}", *use]
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
