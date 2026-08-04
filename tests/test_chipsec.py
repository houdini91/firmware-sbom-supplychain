#!/usr/bin/env python3
"""Unit tests for the CHIPSEC predicate producer's critical_passed logic (the
security-relevant decision the gate's chipsec-posture report consumes). Hermetic.

Run: python3 tests/test_chipsec.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "chipsec_to_predicate", os.path.join(HERE, "..", "producers", "chipsec", "to-predicate.py"))
tp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tp)

ok = True


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


check("all applicable critical modules PASS -> critical_passed",
      tp.convert({"common.bios_wp": "PASSED", "common.smm": "PASSED", "common.spi_lock": "PASSED"})["critical_passed"] is True)

check("a critical module FAILED -> not critical_passed",
      tp.convert({"common.bios_wp": "PASSED", "common.smm": "FAILED"})["critical_passed"] is False)

check("no applicable critical module (all NOTAPPLICABLE) -> critical_passed False (non-vacuous)",
      tp.convert({"common.bios_wp": "NOTAPPLICABLE", "common.smm": "NOTAPPLICABLE"})["critical_passed"] is False)

check("a NON-critical FAILURE does not flip critical_passed",
      tp.convert({"common.bios_wp": "PASSED", "some.other.module": "FAILED"})["critical_passed"] is True)

check("comment/metadata keys (leading _) are skipped",
      all(r["module"] != "_comment" for r in tp.convert({"_comment": "x", "common.bios_wp": "PASSED"})["results"]))

check("chipsec.modules.* prefix normalized to the CRITICAL name",
      tp.convert({"chipsec.modules.common.bios_wp": "PASSED"})["critical_passed"] is True)

check("dict-shaped result ({result: ...}) is understood",
      tp.convert({"common.bios_wp": {"result": "PASSED"}})["critical_passed"] is True)

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
