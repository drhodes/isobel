"""
nonet.py — a decorator that runs a function in a seccomp-restricted *child
process* that cannot make network calls, hardened by a chain of pluggable
mitigations.

Architecture
────────────
  parent (unrestricted)
    │
    ├─ fork()
    │
    └─► child process
          │  [for each mitigation] m.on_child_init(write_fd)
          │      e.g. close inherited FDs before the filter locks things
          │
          │  install_sandbox_filter(extra_syscalls, count)  ← C code
          │      • PR_SET_NO_NEW_PRIVS
          │      • seccomp-bpf: built-in blacklist + mitigation extras
          │
          ├─ run fn(*args, **kwargs)
          ├─ pickle result → pipe
          └─ _exit(0)

  parent:
    ├─ read pipe
    ├─ [for each mitigation] m.on_parent_result(raw) → first non-None wins
    │      e.g. RestrictedUnpickler blocks __reduce__ RCE
    └─ return value / re-raise exception

See mitigations/ for the plugin interface and the three built-in mitigations.
Building:
  make           # compiles nonet_sandbox.so
"""

import ctypes
import os
import pickle
import struct
from functools import wraps

# ── Load C sandbox helper ─────────────────────────────────────────────────────

_SO_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "nonet_sandbox.so")


def _load_sandbox_lib():
    try:
        lib = ctypes.CDLL(_SO_PATH)
        lib.install_sandbox_filter.restype  = ctypes.c_int
        lib.install_sandbox_filter.argtypes = [
            ctypes.POINTER(ctypes.c_int),   # extra_blocked[]
            ctypes.c_int,                   # extra_count
        ]
        return lib
    except OSError as exc:
        raise RuntimeError(
            f"[nonet] could not load {_SO_PATH}. Run `make` first."
        ) from exc


_sandbox_lib = _load_sandbox_lib()

# ── Mitigation chain ──────────────────────────────────────────────────────────

from mitigations import ENABLED  # noqa: E402  (after _sandbox_lib is ready)

# ── Pipe I/O helpers ──────────────────────────────────────────────────────────

def _write_msg(fd: int, data: bytes) -> None:
    os.write(fd, struct.pack(">I", len(data)) + data)


def _read_msg(fd: int) -> bytes:
    raw = b""
    while len(raw) < 4:
        chunk = os.read(fd, 4 - len(raw))
        if not chunk:
            raise EOFError("Child closed the pipe before sending a result")
        raw += chunk
    length = struct.unpack(">I", raw)[0]
    payload = b""
    while len(payload) < length:
        chunk = os.read(fd, length - len(payload))
        if not chunk:
            raise EOFError("Child closed the pipe mid-message")
        payload += chunk
    return payload

# ── Core decorator ────────────────────────────────────────────────────────────

def nonet(fn):
    """
    Decorator. Runs the wrapped function in a hardened child process.

    The child is isolated by:
      • A separate OS process (fork) — no shared Python heap
      • Per-mitigation setup before seccomp (e.g. close inherited FDs)
      • A C-applied seccomp-bpf filter covering network + exec + escalation
        plus any extra syscalls declared by mitigations (e.g. kill/tgkill)
      • Restricted unpickling in the parent (blocks __reduce__ RCE)

    Add or remove mitigations in mitigations/__init__.py → ENABLED.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        read_fd, write_fd = os.pipe()
        pid = os.fork()

        if pid == 0:
            # ── Child ──────────────────────────────────────────────────
            os.close(read_fd)

            # Phase 1: pre-seccomp mitigation hooks
            for m in ENABLED:
                m.on_child_init(write_fd)

            # Phase 2: collect extra deny-list syscalls from mitigations
            extra: list[int] = []
            for m in ENABLED:
                extra.extend(m.extra_blocked_syscalls())

            arr_t = ctypes.c_int * len(extra)
            arr   = arr_t(*extra) if extra else arr_t()
            ret   = _sandbox_lib.install_sandbox_filter(arr, len(extra))
            if ret != 0:
                os._exit(2)

            # Phase 3: run the user function
            try:
                result  = fn(*args, **kwargs)
                payload = pickle.dumps(("ok", result))
            except BaseException as exc:
                payload = pickle.dumps(("err", exc))

            try:
                _write_msg(write_fd, payload)
            except OSError:
                pass

            os.close(write_fd)
            os._exit(0)

        else:
            # ── Parent ─────────────────────────────────────────────────
            os.close(write_fd)

            try:
                raw = _read_msg(read_fd)
            except EOFError as exc:
                _, status = os.waitpid(pid, 0)
                raise RuntimeError(
                    f"[nonet] child exited (status {status}) without a result"
                ) from exc
            finally:
                os.close(read_fd)

            os.waitpid(pid, 0)

            # Phase 4: deserialize via mitigation chain, first non-None wins
            result = None
            for m in ENABLED:
                result = m.on_parent_result(raw)
                if result is not None:
                    break
            if result is None:
                result = pickle.loads(raw)

            tag, value = result
            if tag == "ok":
                return value
            raise value

    return wrapper


# ── quick demo ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import urllib.request

    @nonet
    def safe_compute():
        print("[safe_compute] doing math...")
        result = sum(i * i for i in range(1000))
        print(f"[safe_compute] result: {result}")
        return result

    @nonet
    def try_network():
        print("[try_network] attempting network call...")
        try:
            urllib.request.urlopen("http://1.1.1.1", timeout=3)
            print("[try_network] !! network call SUCCEEDED — sandbox failed !!")
        except OSError as e:
            print(f"[try_network] network call blocked as expected: {e}")

    print("=== nonet decorator demo ===\n")
    val = safe_compute()
    print(f"main received: {val}\n")
    try_network()
