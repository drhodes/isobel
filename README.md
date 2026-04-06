# isobel

Highly experimental. Not audited.

`isobel` is a Linux-only python sandbox for running a single function call in a
separate dedicated worker process under a seccomp filter.

Primary goal: conveniently isolate library code to mitigate supply
chain exploits. If a dependency, plugin, or generated function tries
to open a socket, connect outbound, spawn a subprocess then the call
should fail inside the sandboxed child instead of reaching the
network.

## What it does

The `@nonet` decorator:

- lazily forks one dedicated child process per decorated function
- installs a C seccomp filter with a built-in deny list for networking,
  `execve`, `fork`, `vfork`, and selected escalation syscalls
- reuses that worker for later calls by sending pickled arguments over a local
  unix socket
- returns the result to the parent through the same control socket
- deserializes the result through a restricted unpickler

This is process isolation, not a generic policy engine. The parent process is
not sandboxed. Only the decorated call runs under the filter.

Because the worker is persistent, it sees module globals and closure state as
they existed when the worker first started, not after later parent-side
mutations. Arguments, return values, and raised exceptions must be pickleable.

## Phoning-home example

The intended use case is wrapping code you do not fully trust.

```python
import urllib.request
import nonet

@nonet
def score_payload(data: bytes) -> int:
    return sum(data) % 97

@nonet
def suspicious_hook() -> None:
    # This must not be able to call out.
    urllib.request.urlopen("http://1.1.1.1", timeout=2)

print(score_payload(b"abc"))

try:
    suspicious_hook()
except OSError as exc:
    print(type(exc).__name__, exc)
```

Expected result:

- `score_payload(...)` returns normally
- `suspicious_hook()` raises `OSError`
- on Linux, the error should typically include `EPERM` or `Operation not permitted`


## Build and test

Requirements:

- Linux
- `gcc`
- `libseccomp`
- Python 3.13+

Build the shared object:

```sh
make
```

Run the test suite:

```sh
make test
```

Run the microbenchmarks:

```sh
make benchmark
```

## Limits

- Linux only; relies on seccomp and `fork()`
- default policy is deny-listed syscalls, not full filesystem isolation
- code running before the decorator is entered is not covered
- worker state persists across calls and is isolated from later parent-side
  mutations
- call arguments, return values, and exceptions must be pickleable
- return values still cross a trust boundary, which is why restricted unpickling
  is part of the default chain
