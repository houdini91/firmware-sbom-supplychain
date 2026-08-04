#!/usr/bin/env python3
"""Unit tests for sbom-reconcile's membership classification (the logic that
decides clean vs blocked). Hermetic: a synthetic SBOM + a synthetic FMMT view,
no edk2/FMMT/image needed.

Run: python3 tests/test_reconcile.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "sbom_reconcile", os.path.join(HERE, "..", "producers", "reconcile", "sbom-reconcile.py"))
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

ok = True


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"   # declared + observed  -> validated
B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"   # declared, NOT observed -> missing
C = "cccccccc-cccc-cccc-cccc-cccccccccccc"   # observed, NAMED, undeclared -> suspicious
D = "dddddddd-dddd-dddd-dddd-dddddddddddd"   # observed, UNNAMED, undeclared -> structural
PAD = "ffffffff-ffff-ffff-ffff-ffffffffffff"

SBOM = {"components": [
    {"bom-ref": A, "name": "ModuleA", "type": "device-driver"},
    {"bom-ref": B, "name": "ModuleB", "type": "device-driver"},
    {"bom-ref": "libfoo", "name": "LibFoo", "type": "library"},   # libraries excluded from membership
]}

VIEW = "\n".join([
    "FvNameGuid: 11111111-1111-1111-1111-111111111111",
    "File: %s / ModuleA" % A,
    "File: %s / RogueModule" % C,
    "File: %s" % D,
    "File: %s / Ffs_pad" % PAD,   # padding -> ignored
])

# parse_fmmt
fv, ffs = rc.parse_fmmt(VIEW)
check("parse_fmmt: 1 FV, pad excluded, named+unnamed files kept",
      len(fv) == 1 and set(ffs) == {A, C, D} and ffs[A] == "ModuleA" and ffs[D] == "")

# reconcile classification
v = rc.reconcile(SBOM, VIEW)
s = v["summary"]
check("reconcile: A validated, B missing, C suspicious, D structural",
      [x for x in v["validated"]] == [A]
      and [m["guid"] for m in v["missing"]] == [B]
      and s["added_suspicious"] == 1 and s["added_structural"] == 1)
check("reconcile: libraries excluded from declared membership (declared_libraries=1)",
      s["declared_libraries"] == 1 and s["declared_modules"] == 2)
check("reconcile: NOT clean when a module is missing or a suspicious module is present",
      v["clean"] is False)

# a clean image: every declared module observed, nothing suspicious
CLEAN_VIEW = "\n".join([
    "FvNameGuid: 11111111-1111-1111-1111-111111111111",
    "File: %s / ModuleA" % A,
    "File: %s / ModuleB" % B,
    "File: %s" % D,   # unnamed structural is fine
])
vc = rc.reconcile(SBOM, CLEAN_VIEW)
check("reconcile: clean when all declared modules observed + no suspicious adds",
      vc["clean"] is True and vc["summary"]["missing"] == 0 and vc["summary"]["added_suspicious"] == 0)

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
