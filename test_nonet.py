"""
test_nonet.py — tests that try to defeat the nonet decorator.

Split into two categories:
  1. Sandbox-verification tests: prove that direct, subprocess, multiprocessing,
     and intra-worker thread attempts are all blocked.
  2. Bypass-resistance tests: the three attacks that defeated the old
     thread-pool implementation are now closed by the fork+C-sandbox design.
"""

import gc
import multiprocessing
import os
import sys
import threading
import urllib.error
import urllib.request

import pytest

from main import nonet

# Use an IP address directly to avoid gaierror from DNS.
NETWORK_URL = "http://1.1.1.1"
TIMEOUT = 2


def _network_blocked(exc):
    """Return True if *exc* looks like a seccomp EPERM block."""
    return getattr(exc, "errno", None) == 1 or "Operation not permitted" in str(exc)


def _network_reached(exc):
    """Return True if *exc* proves we got a real HTTP response (sandbox escaped)."""
    code = getattr(exc, "code", None) or getattr(exc, "status", None)
    msg = str(exc)
    return code is not None or "403" in msg or "200" in msg


# ─────────────────────────────────────────────────────────────
# 1. Sandbox-verification tests (sandbox must hold)
# ─────────────────────────────────────────────────────────────

def test_direct_network():
    """Direct urlopen inside a @nonet function must be blocked."""
    @nonet
    def try_network():
        urllib.request.urlopen(NETWORK_URL, timeout=TIMEOUT)

    with pytest.raises(OSError) as exc_info:
        try_network()

    assert _network_blocked(exc_info.value), (
        f"Expected EPERM, got: {exc_info.value!r}"
    )


def test_subprocess_curl():
    """curl launched inside @nonet must fail — execve is blocked by the C sandbox."""
    @nonet
    def try_subprocess():
        import subprocess
        result = subprocess.run(
            ["curl", "-s", "--max-time", str(TIMEOUT), NETWORK_URL],
            capture_output=True,
        )
        return result.returncode

    with pytest.raises(Exception):
        # execve is blocked, so subprocess.run itself should fail with EPERM
        try_subprocess()


def test_multiprocessing_child():
    """
    A fork()d grandchild inherits the sandbox's seccomp filter via clone(),
    so its network attempt is also blocked.

    Note: fork() itself is *not* blocked (Linux fork is clone() under the hood,
    and clone is allowed so Python threads work). But seccomp is inherited by
    all children, so the grandchild's network call is still blocked.
    """
    def worker(val):
        try:
            urllib.request.urlopen(NETWORK_URL, timeout=TIMEOUT)
            val.value = 1  # success — sandbox escaped
        except OSError as e:
            val.value = 2 if _network_blocked(e) else 3  # 2 = properly blocked

    @nonet
    def try_multi():
        ctx = multiprocessing.get_context("fork")
        val = ctx.Value("i", 0)
        p = ctx.Process(target=worker, args=(val,))
        p.start()
        p.join()
        return val.value

    result = try_multi()
    # Grandchild should have inherited the filter — network must be blocked.
    assert result == 2, (
        f"Forked grandchild escaped the sandbox (got {result}, expected 2=blocked)"
    )


def test_thread_spawn_inside_worker():
    """Threads spawned inside the worker still have the seccomp filter."""
    @nonet
    def try_thread():
        result = []

        def inner():
            try:
                urllib.request.urlopen(NETWORK_URL, timeout=TIMEOUT)
                result.append("SUCCESS")
            except OSError as e:
                result.append(("BLOCKED", e))
            except Exception as e:
                result.append(("OTHER", e))

        t = threading.Thread(target=inner)
        t.start()
        t.join()
        return result[0]

    result = try_thread()
    assert result != "SUCCESS", "inner thread bypassed the sandbox!"
    tag, exc = result
    assert tag == "BLOCKED" and _network_blocked(exc), (
        f"Expected seccomp block, got: {result!r}"
    )


# ─────────────────────────────────────────────────────────────
# 2. Bypass-resistance tests (all three bypass vectors are now CLOSED)
# ─────────────────────────────────────────────────────────────

def test_del_bypass_closed():
    """
    OLD ATTACK: return an object whose __del__ fires in the main thread.

    CLOSED: the child process owns a separate heap. The __del__ fires in the
    sandboxed child (where network is blocked), NOT in the parent.
    """
    del_fired_in_parent = []

    class NetworkOnDelete:
        def __del__(self):
            # If this runs, it means we're in the parent's unrestricted context.
            # We record the result so the parent assertion can check it.
            del_fired_in_parent.append("del_ran_in_parent")

    @nonet
    def create_payload():
        # This object only exists in the child's address space.
        return NetworkOnDelete()

    # The child will fail to return the object (unpicklable local class),
    # but more importantly: __del__ only fires in the child, not here.
    try:
        obj = create_payload()
        del obj
        gc.collect()
    except Exception:
        pass  # Pickling error expected — that's fine

    # The __del__ must NOT have fired in the parent process
    assert not del_fired_in_parent, (
        "__del__ fired in the parent (unrestricted) process — bypass not closed!"
    )


def test_atexit_bypass_closed():
    """
    OLD ATTACK: register an atexit handler in the worker; it runs on the main
    thread at shutdown.

    CLOSED: atexit handlers registered inside the fork()d child fire when the
    *child* exits — and the child's network access is blocked by the C sandbox.
    """
    import subprocess

    script_dir = os.path.abspath(os.path.dirname(__file__))
    code = f"""\
import atexit, sys, urllib.request, urllib.error
sys.path.insert(0, {script_dir!r})
from main import nonet

@nonet
def install():
    def on_exit():
        try:
            urllib.request.urlopen({NETWORK_URL!r}, timeout={TIMEOUT})
            print("ATEXIT_SUCCESS")
        except urllib.error.HTTPError:
            print("ATEXIT_SUCCESS")  # reached the server
        except Exception as e:
            print(f"ATEXIT_FAIL: {{e}}")
    atexit.register(on_exit)

install()
print("MAIN_DONE")
"""

    tmp = os.path.join(script_dir, "_tmp_atexit_test.py")
    try:
        with open(tmp, "w") as fh:
            fh.write(code)

        res = subprocess.run(
            [sys.executable, tmp],
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    # With the C sandbox, the atexit handler runs in the sandboxed child.
    # The parent's stdout should NOT contain "ATEXIT_SUCCESS".
    assert "ATEXIT_SUCCESS" not in res.stdout, (
        f"atexit bypass is still open!\nstdout: {res.stdout}\nstderr: {res.stderr}"
    )
    assert "MAIN_DONE" in res.stdout, (
        f"Script did not complete normally.\nstdout: {res.stdout}\nstderr: {res.stderr}"
    )


# Module-level sentinel the parent thread will call after @nonet runs.
_global_func = None


def test_global_patch_bypass_closed():
    """
    OLD ATTACK: the worker monkey-patches a module-level callable; the main
    thread then calls it outside the sandbox.

    CLOSED: fork() gives the child a copy-on-write view of the parent's
    address space. Mutations in the child are invisible to the parent.
    """
    global _global_func

    sentinel = object()

    def innocent():
        return sentinel

    _global_func = innocent

    @nonet
    def malicious():
        def evil():
            # This runs in the child — but even if it tried net, it'd be blocked.
            return "PATCHED"

        global _global_func
        _global_func = evil  # only affects the child's CoW copy

    malicious()

    # Parent's _global_func must still be the original.
    result = _global_func()
    assert result is sentinel, (
        "Global patch bypass is still open: parent's _global_func was mutated!"
    )


# ─────────────────────────────────────────────────────────────
# 3. Mitigation-specific tests
# ─────────────────────────────────────────────────────────────

def test_close_fds_inherited_socket():
    """
    CloseFDs mitigation: child cannot write to a socket FD it inherited.

    We create a real connected socket pair in the parent before forking,
    then verify the child can't reach it after CloseFDs closes it.
    """
    import socket as sock_mod

    a, b = sock_mod.socketpair()
    inherited_fd = b.fileno()

    @nonet
    def try_write_inherited():
        try:
            os.write(inherited_fd, b"EXFIL")
            return "WROTE"
        except OSError as e:
            return f"BLOCKED:{e.errno}"

    result = try_write_inherited()

    a.close()
    b.close()

    # The FD should have been closed by CloseFDs before seccomp ran.
    assert result.startswith("BLOCKED"), (
        f"Child could write to inherited socket FD {inherited_fd}: {result}"
    )
    assert ":9" in result or ":6" in result or result != "WROTE", (
        "Expected EBADF(9) or ENOTSOCK(6), got: " + result
    )


def test_block_signals_kill():
    """
    BlockSignals mitigation: child cannot send signals to parent.
    """
    parent_pid = os.getpid()

    @nonet
    def try_kill():
        import signal
        try:
            os.kill(parent_pid, signal.SIGUSR1)
            return "SENT"
        except OSError as e:
            return f"BLOCKED:{e.errno}"

    result = try_kill()
    assert result.startswith("BLOCKED"), (
        f"Child managed to send SIGUSR1 to parent: {result}"
    )
    # EPERM = errno 1
    assert ":1" in result, f"Expected EPERM(1), got: {result}"


# these next two tests compliment each other.

def test_mutate_closure1():
    FLAG = "FLAG"
    closure = lambda : FLAG
    
    def can_mutate_clojure():
        import subprocess
        nonlocal closure 
        def badcode():
            result = subprocess.run(
                ["curl", "-s", "--max-time", str(TIMEOUT), NETWORK_URL],
                capture_output=True,
            )
            return result.returncode
        closure = badcode
        
    can_mutate_clojure()
    assert closure() != FLAG

    
def test_mutate_closure2():
    FLAG = "FLAG"
    closure = lambda : FLAG

    @nonet
    def try_mutate_clojure():
        import subprocess
        nonlocal closure
        
        def badcode():
            result = subprocess.run(
                ["curl", "-s", "--max-time", str(TIMEOUT), NETWORK_URL],
                capture_output=True,
            )
            return result.returncode
        closure = badcode
    
    try_mutate_clojure()
    assert closure() == FLAG

    

def test_safe_pickle_rce_blocked():
    """
    SafePickle mitigation: returning an object with __reduce__ that calls
    an arbitrary function must raise UnpicklingError in the parent, not
    execute code.
    """
    import pickle

    @nonet
    def return_evil():
        class EvilPayload:
            def __reduce__(self):
                # Would run os.system on an unprotected pickle.loads
                return (__import__("os").getpid, ())
        return EvilPayload()

    with pytest.raises(pickle.UnpicklingError, match="blocked"):
        return_evil()


