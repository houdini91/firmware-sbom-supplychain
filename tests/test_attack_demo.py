#!/usr/bin/env python3
"""End-to-end test for the same-GUID trojan attack demo (scripts/attack-demo.sh).

The highest-value proof in the repo: it takes a REAL committed edk2 PE32 module,
byte-tampers ONE copy under the SAME FILE_GUID/name, runs the REAL byte-integrity
producer and the REAL OPA deploy gate, and asserts the security-relevant outcome:

    clean copy    -> byte-verified -> gate ALLOW
    trojaned copy -> MODIFIED      -> gate DENY  (reconcile-membership still PASSES)

Needs opa (from $OPA, ./bin/opa, or `opa` on PATH) + jq + python3. Run:
    OPA=/usr/local/bin/opa python3 tests/test_attack_demo.py
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

ok = True


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


def resolve_opa():
    for cand in (os.environ.get("OPA"), os.path.join(ROOT, "bin", "opa"), shutil.which("opa")):
        if cand and os.path.exists(cand) and os.access(cand, os.X_OK):
            return cand
    return None


opa = resolve_opa()
if opa is None:
    print("SKIP  attack-demo end-to-end (opa not found — set OPA=, or `make bin`)")
    print("ALL PASS (with 1 SKIPPED)")
    sys.exit(0)

env = dict(os.environ, OPA=opa)
r = subprocess.run(["bash", os.path.join(ROOT, "scripts", "attack-demo.sh")],
                   env=env, capture_output=True, text=True)
out = r.stdout + r.stderr
if r.returncode != 0:
    print(out)
check("attack-demo.sh runs clean end-to-end (exit 0 = every assertion held)", r.returncode == 0)
check("real producer flags the same-GUID byte swap MODIFIED", "⛔ MODIFIED DemoNetworkDxe" in out)
check("clean image is ALLOWed by the gate", "✅ ALLOW" in out)
check("trojaned image is DENIED by the gate", "⛔ DENY" in out)
check("the denial reason is byte-integrity MODIFIED (a same-GUID swap)",
      "module(s) MODIFIED" in out and "component-byte-integrity" in out)
check("reconcile-membership still PASSES on the swap (the gap byte-integrity closes)",
      "✅ reconcile-membership: every declared module observed" in out)

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
