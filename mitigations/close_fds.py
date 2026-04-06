"""
mitigations/close_fds.py — Close all file descriptors inherited from the
parent before seccomp is installed.

Attack closed: inherited open socket / pipe FDs.
  If the parent process held open network connections, the child would inherit
  those FDs and could call os.write(sock_fd, ...) to exfiltrate data without
  ever calling socket() — bypassing the seccomp network deny list entirely.

Hook used: on_child_init (runs BEFORE seccomp, so os.listdir still works).
"""

from __future__ import annotations

import os

from mitigations import Mitigation


class CloseFDs(Mitigation):
    name = "close_inherited_fds"

    def on_child_init(self, write_fd: int) -> None:
        """Close every FD the parent left open except stdin/stdout/stderr and
        the result pipe."""
        keep = {0, 1, 2, write_fd}

        try:
            fds = [int(name) for name in os.listdir("/proc/self/fd")]
        except OSError:
            # /proc not available — best-effort: try a range of likely FDs.
            fds = list(range(3, 256))

        for fd in fds:
            if fd in keep:
                continue
            try:
                os.close(fd)
            except OSError:
                pass  # already closed or not a real FD — ignore
