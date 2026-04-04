import sys
print("starting debug", flush=True)

try:
    import pytest
    print("pytest imported", flush=True)
except Exception as e:
    print(f"error import pytest: {e}", flush=True)

import test_nonet
print("imported test_nonet", flush=True)

try:
    print("running direct network...", flush=True)
    test_nonet.test_direct_network()
    print("done direct network", flush=True)
except Exception as e:
    print("error in direct network:", e, flush=True)

print("done script", flush=True)
