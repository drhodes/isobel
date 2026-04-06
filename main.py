"""
nonet.py — a decorator that runs a function in a seccomp-restricted dedicated
worker process that cannot make network calls, hardened by a chain of
pluggable mitigations.

Architecture
────────────
  parent (unrestricted)
    │
    ├─ first call lazily forks one worker for the decorated function
    │
    ├─ later calls pickle (args, kwargs) → unix socket
    │
    └─ read pickled result / exception ← unix socket

  child worker
    │  [for each mitigation] m.on_child_init(comm_fd)
    │      e.g. close inherited FDs before the filter locks things
    │
    │  install_sandbox_filter(extra_syscalls, count)  ← C code
    │      • PR_SET_NO_NEW_PRIVS
    │      • seccomp-bpf: built-in blacklist + mitigation extras
    │
    └─ loop:
          ├─ unpickle (args, kwargs)
          ├─ run fn(*args, **kwargs)
          └─ pickle result back to the parent

Tradeoffs
─────────
  • the worker sees globals / closure state as it existed when the worker
    first started, not after later parent-side mutations
  • call arguments, return values, and raised exceptions must be pickleable

See mitigations/ for the plugin interface and the three built-in mitigations.
Building:
  make           # compiles nonet_sandbox.so
"""

import ctypes
import os
import pickle
import socket
import struct
import threading
import weakref
from dataclasses import dataclass, field
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
    payload = memoryview(struct.pack(">I", len(data)) + data)
    while payload:
        written = os.write(fd, payload)
        if written == 0:
            raise BrokenPipeError("[nonet] write returned 0 bytes")
        payload = payload[written:]


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


def _deserialize_result(raw: bytes):
    result = None
    for m in ENABLED:
        result = m.on_parent_result(raw)
        if result is not None:
            break
    if result is None:
        result = pickle.loads(raw)
    return result


def _close_fd(fd: int | None) -> None:
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


@dataclass(slots=True)
class _WorkerState:
    fn_name: str
    owner_pid: int = field(default_factory=os.getpid)
    pid: int | None = None
    fd: int | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


def _start_worker(fn, state: _WorkerState) -> None:
    parent_sock, child_sock = socket.socketpair()
    pid = os.fork()

    if pid == 0:
        parent_sock.close()
        comm_fd = child_sock.detach()
        try:
            for m in ENABLED:
                m.on_child_init(comm_fd)

            extra: list[int] = []
            for m in ENABLED:
                extra.extend(m.extra_blocked_syscalls())

            arr_t = ctypes.c_int * len(extra)
            arr = arr_t(*extra) if extra else arr_t()
            ret = _sandbox_lib.install_sandbox_filter(arr, len(extra))
            if ret != 0:
                os._exit(2)

            while True:
                try:
                    raw_request = _read_msg(comm_fd)
                except EOFError:
                    break

                try:
                    args, kwargs = pickle.loads(raw_request)
                    result = fn(*args, **kwargs)
                    payload = pickle.dumps(("ok", result))
                except BaseException as exc:
                    try:
                        payload = pickle.dumps(("err", exc))
                    except BaseException as pickle_exc:
                        payload = pickle.dumps(("err", pickle_exc))

                try:
                    _write_msg(comm_fd, payload)
                except OSError:
                    break
        finally:
            _close_fd(comm_fd)
            os._exit(0)

    child_sock.close()
    state.pid = pid
    state.fd = parent_sock.detach()
    state.owner_pid = os.getpid()


def _ensure_worker(fn, state: _WorkerState) -> None:
    current_pid = os.getpid()

    if state.owner_pid != current_pid:
        _close_fd(state.fd)
        state.pid = None
        state.fd = None
        state.owner_pid = current_pid

    if state.pid is not None:
        try:
            finished_pid, _ = os.waitpid(state.pid, os.WNOHANG)
        except ChildProcessError:
            finished_pid = state.pid
        if finished_pid == state.pid:
            _close_fd(state.fd)
            state.pid = None
            state.fd = None

    if state.pid is None:
        _start_worker(fn, state)


def _shutdown_worker(state: _WorkerState) -> None:
    current_pid = os.getpid()
    with state.lock:
        owner_pid = state.owner_pid
        pid = state.pid
        fd = state.fd
        state.owner_pid = current_pid
        state.pid = None
        state.fd = None

    _close_fd(fd)
    if pid is None or owner_pid != current_pid:
        return

    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _reap_worker(pid: int | None) -> None:
    if pid is None:
        return
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass

# ── Core decorator ────────────────────────────────────────────────────────────

def nonet(fn):
    """
    Decorator. Runs the wrapped function in a hardened dedicated worker process.

    The child is isolated by:
      • A separate OS process (fork) — no shared Python heap
      • Per-mitigation setup before seccomp (e.g. close inherited FDs)
      • A C-applied seccomp-bpf filter covering network + exec + escalation
        plus any extra syscalls declared by mitigations (e.g. kill/tgkill)
      • Restricted unpickling in the parent (blocks __reduce__ RCE)

    Add or remove mitigations in mitigations/__init__.py → ENABLED.
    """
    state = _WorkerState(fn_name=fn.__qualname__)

    @wraps(fn)
    def wrapper(*args, **kwargs):
        request = pickle.dumps((args, kwargs))
        last_error = None

        for _ in range(2):
            worker_pid = None
            failed_pid = None
            with state.lock:
                _ensure_worker(fn, state)
                worker_pid = state.pid
                worker_fd = state.fd
                assert worker_fd is not None

                try:
                    _write_msg(worker_fd, request)
                    raw = _read_msg(worker_fd)
                except (BrokenPipeError, EOFError, OSError) as exc:
                    last_error = exc
                    failed_pid = state.pid
                    _close_fd(state.fd)
                    state.pid = None
                    state.fd = None

            if failed_pid is not None:
                _reap_worker(failed_pid)
                continue

            result = _deserialize_result(raw)
            tag, value = result
            if tag == "ok":
                return value
            raise value

        _reap_worker(worker_pid)

        raise RuntimeError(
            f"[nonet] worker for {state.fn_name} exited without a result"
        ) from last_error

    wrapper._nonet_worker_finalizer = weakref.finalize(  # type: ignore[attr-defined]
        wrapper,
        _shutdown_worker,
        state,
    )
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
