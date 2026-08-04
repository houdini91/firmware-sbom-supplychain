#!/usr/bin/env python3
"""Unit tests for the pure derivations in the gate-input assembler.

These are exactly the transforms that were untestable while the assembler was
bash/jq (the reason for the port). Run: python3 tests/test_assemble.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "oss-lane"))
import assemble_gate_input as a  # noqa: E402

ok = True


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


# integrity (F6): empty hashes:[] and missing hashes are UNHASHED; libraries excluded
integ = a.integrity({"components": [
    {"type": "driver", "name": "Good", "hashes": [{"alg": "SHA-256", "content": "ab"}]},
    {"type": "driver", "name": "EmptyArr", "hashes": []},
    {"type": "driver", "name": "NoHash"},
    {"type": "library", "name": "LibIgnored"},
]})
check("integrity: empty/missing hashes flagged unhashed, libs excluded",
      integ["hashable_total"] == 3 and integ["hashed"] == 1 and set(integ["unhashed"]) == {"EmptyArr", "NoHash"})

# thirdparty (F7): empty purl/licenses flagged missing; first-party excluded
tp = a.thirdparty({"components": [
    {"name": "ok", "properties": [{"name": "edk2:vendored", "value": "true"}],
     "purl": "pkg:x/y@1", "licenses": [{"license": {"id": "MIT"}}]},
    {"name": "bad", "properties": [{"name": "edk2:vendored", "value": "true"}], "purl": "", "licenses": []},
    {"name": "firstparty"},
]})
check("thirdparty: empty purl/licenses -> missing; first-party excluded",
      tp["total"] == 2 and tp["missing"] == ["bad"])

# cve: missing/empty file -> []
check("cve: no file -> []", a.cve_findings("") == [])

# build_tools: 'latest'/unversioned+unhashed -> unpinned; signature flag threaded
bt = a.build_tools_derive([
    {"name": "pinned", "version": "1.2.3"},
    {"name": "loose", "version": "latest"},
    {"name": "bare"},
    {"name": "hashed-only", "hashes": [{"content": "x"}]},
], True)
check("build_tools: latest/unversioned+unhashed are unpinned",
      bt["present"] and set(bt["unpinned"]) == {"loose", "bare"} and bt["all_pinned"] is False and bt["signature_verified"] is True)

# dflt: jq `// default` — null and absent fall through, 0 stays
check("dflt: null->default, 0 stays, absent->default",
      a.dflt({"a": None}, "a", 1) == 1 and a.dflt({"a": 0}, "a", 1) == 0 and a.dflt({}, "b", 5) == 5)

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
