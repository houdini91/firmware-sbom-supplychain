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
    {"type": "driver", "name": "Dxe", "hashes": [{"content": "cd"}],
     "properties": [{"name": "edk2:moduleType", "value": "DXE_DRIVER"}]},
]})
check("integrity: empty/missing hashes flagged unhashed, libs excluded",
      integ["hashable_total"] == 4 and integ["hashed"] == 2 and set(integ["unhashed"]) == {"EmptyArr", "NoHash"})
check("integrity: dxe_class_total counts DXE-class module types (edk2:moduleType)",
      integ["dxe_class_total"] == 1)

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

# binary_hardening (R8): absent file -> ran=False (distinct from a clean run)
bh_absent = a.binary_hardening_fact("")
check("binary_hardening: no file -> ran=False, not a pass",
      bh_absent["ran"] is False and bh_absent["dxe_class_checked"] == 0)

# binary_hardening: real verdict shape -> derived counts (missing_nx from dxe_missing_nx length)
import json as _json  # noqa: E402
import tempfile as _tempfile  # noqa: E402
_fd, _p = _tempfile.mkstemp(suffix=".json")
with os.fdopen(_fd, "w") as _f:
    _json.dump({"dxe_class_checked": 106, "dxe_nx_compat": 104,
                "dxe_missing_nx": [{"name": "A"}, {"name": "B"}],
                "skipped": [{"name": "DxeSkip", "type": "DXE_DRIVER"}, {"name": "PeiSkip", "type": "PEIM"}],
                "errored": [{"name": "DxeErr", "type": "UEFI_DRIVER"}]}, _f)
bh = a.binary_hardening_fact(_p)
os.unlink(_p)
check("binary_hardening: missing_nx + errored + DXE-class-only unverifiable (non-DXE PeiSkip excluded)",
      bh["ran"] and bh["dxe_class_checked"] == 106 and bh["missing_nx_count"] == 2
      and bh["errored_count"] == 1 and bh["unverifiable"] == ["DxeErr", "DxeSkip"])

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
