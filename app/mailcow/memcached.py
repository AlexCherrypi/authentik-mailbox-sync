"""Minimal memcached client — only flush_all, which is all we need to
invalidate SOGo's user-settings cache after we mutate ``sogo_user_profile``
or change Dovecot ACLs.

Talks over TCP directly so we don't need a docker.sock round-trip. The
memcached container is resolvable on the mailcow-network we attach to."""
import logging
import socket

log = logging.getLogger("sync.memcached")


class MemcachedClient:
    def __init__(self, host: str, port: int = 11211, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def flush_all(self) -> bool:
        """Send ``flush_all`` to memcached. Returns True on success.
        Failures are logged but never raised — a stale SOGo cache is a
        less-bad outcome than a webhook 500."""
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(b"flush_all\r\n")
                # OK\r\n is the only expected response; ignore
                s.recv(1024)
            return True
        except Exception as exc:
            log.warning("memcached flush_all to %s:%s failed: %s",
                        self.host, self.port, exc)
            return False
