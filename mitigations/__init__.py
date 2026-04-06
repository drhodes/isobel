"""
mitigations/__init__.py — Mitigation base class, syscall-number helper, and
the ENABLED registry.

Adding a new mitigation:
  1. Create mitigations/my_fix.py implementing the hooks you need.
  2. Import it here and append an instance to ENABLED.

That's it. The nonet decorator iterates ENABLED automatically.
"""

from __future__ import annotations

import ctypes
from typing import Any

# ── Syscall-number helper ─────────────────────────────────────────────────────
# Resolves a syscall name to its number portably using libseccomp at runtime.

_libseccomp = ctypes.CDLL("libseccomp.so.2")
_libseccomp.seccomp_syscall_resolve_name.restype  = ctypes.c_int
_libseccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]


def syscall_nr(name: str) -> int:
    """Return the syscall number for *name* on this architecture."""
    nr = _libseccomp.seccomp_syscall_resolve_name(name.encode())
    if nr < 0:
        raise ValueError(f"[nonet] unknown syscall: {name!r}")
    return nr


# ── Base class ────────────────────────────────────────────────────────────────

class Mitigation:
    """
    Abstract base for a nonet sandbox mitigation.

    Each hook is optional — override only what your mitigation needs.
    The three hooks map to the three phases of every @nonet call:

      extra_blocked_syscalls()  →  fed into the C seccomp filter before it loads
      on_child_init(write_fd)   →  runs in the child BEFORE seccomp is installed
      on_parent_result(raw)     →  runs in the parent to deserialize the result
                                   (return None to pass control to the next one)
    """

    #: Human-readable identifier shown in debug output.
    name: str = ""

    def extra_blocked_syscalls(self) -> list[int]:
        """Return additional syscall numbers to add to the seccomp deny list."""
        return []

    def on_child_init(self, write_fd: int) -> None:
        """Called in the child process *before* seccomp is installed.

        Use this to set up any isolation that must happen before the filter
        locks things down (e.g., closing inherited file descriptors).
        """
        pass

    def on_parent_result(self, raw: bytes) -> tuple[str, Any] | None:
        """Called in the parent to deserialize the child's length-prefixed payload.

        Return a ``("ok", value)`` or ``("err", exc)`` tuple to override
        deserialization, or ``None`` to defer to the next mitigation / the
        built-in ``pickle.loads`` fallback.
        """
        return None


# ── Plugin registry ───────────────────────────────────────────────────────────
# Import concrete mitigations and list them here.  Order matters for
# on_parent_result: the first non-None return wins.

from mitigations.close_fds     import CloseFDs      # noqa: E402
from mitigations.block_signals import BlockSignals  # noqa: E402
from mitigations.safe_pickle   import SafePickle    # noqa: E402

ENABLED: list[Mitigation] = [
    CloseFDs(),
    BlockSignals(),
    SafePickle(),
]
