"""
mitigations/block_signals.py — Block kill() and tgkill() in the child.

Attack closed: signal injection.
  The child knows the parent PID via os.getppid() and could send signals to
  it.  If the parent has a SIGUSR1 handler that makes network calls, for
  example, the child could trigger it — an indirect network bypass.
  Blocking kill/tgkill at the syscall level prevents this entirely.

Hook used: extra_blocked_syscalls (merged into the C seccomp deny list).
"""

from __future__ import annotations

from mitigations import Mitigation, syscall_nr


class BlockSignals(Mitigation):
    name = "block_signals"

    # Resolved once at import time; syscall_nr() uses libseccomp portably.
    _BLOCKED = [
        syscall_nr("kill"),
        syscall_nr("tgkill"),
        syscall_nr("tkill"),       # older variant, same intent
        syscall_nr("rt_sigqueueinfo"),
        syscall_nr("rt_tgsigqueueinfo"),
    ]

    def extra_blocked_syscalls(self) -> list[int]:
        return self._BLOCKED
