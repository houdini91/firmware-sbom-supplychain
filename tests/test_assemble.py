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

# generation (CISA 2026): tools as a 1.5+ object with a name+version -> tool_present;
# lifecycles[].phase -> context_present. name-only (no version) is NOT a declared tool.
gen = a.generation({"metadata": {
    "tools": {"components": [{"type": "application", "name": "edk2 BuildReport (-Y SBOM)", "version": "1.0"}]},
    "lifecycles": [{"phase": "build"}]}})
check("generation: object-form tools (name+version) + lifecycle phase -> both present",
      gen["tool_present"] is True and gen["context_present"] is True)
gen_list = a.generation({"metadata": {"tools": [{"name": "syft", "version": "1.2"}]}})
check("generation: 1.4 list-form tools recognized; no lifecycles -> context absent",
      gen_list["tool_present"] is True and gen_list["context_present"] is False)
gen_bad = a.generation({"metadata": {"tools": {"components": [{"name": "nover"}]}, "lifecycles": [{}]}})
check("generation: tool without a version, and a phaseless lifecycle -> both absent (not vacuous)",
      gen_bad["tool_present"] is False and gen_bad["context_present"] is False)
check("generation: empty metadata -> both absent",
      a.generation({}) == {"tool_present": False, "context_present": False})

# cve_fact: NON-VACUITY scanned flag. No GRYPE_JSON -> scanned=False (not "clean"); a real
# grype file -> scanned=True. Distinguishes "scanned, found nothing" from "never scanned".
cf_none = a.cve_fact("")
check("cve_fact: no scan file -> scanned False, findings []",
      cf_none == {"scanned": False, "findings": []})
import tempfile as _tf, os as _os, json as _json
_fd, _gp = _tf.mkstemp(suffix=".json")
with _os.fdopen(_fd, "w") as _f:
    _json.dump({"matches": [{"vulnerability": {"id": "CVE-1", "severity": "High"},
                             "artifact": {"name": "x"}}]}, _f)
cf = a.cve_fact(_gp); _os.remove(_gp)
check("cve_fact: real grype file -> scanned True, finding parsed",
      cf["scanned"] is True and len(cf["findings"]) == 1 and cf["findings"][0]["id"] == "CVE-1")

# osf_conformance: bom-ref in GUID form -> guid_tag_id; edk2:sourceHash -> source_hash_present;
# libraries excluded. The reference SBOM carries no source hash (M-srchash UNMET by default).
osf = a.osf_conformance({"components": [
    {"type": "firmware", "bom-ref": "9622E42C-8E38-4a08-9E8F-54F784652F6B", "name": "AcpiTableDxe"},
    {"type": "firmware", "bom-ref": "not-a-guid", "name": "Weird",
     "properties": [{"name": "edk2:sourceHash", "value": "sha256:deadbeef"}]},
    {"type": "library", "bom-ref": "11111111-2222-3333-4444-555555555555", "name": "LibExcluded"}]})
check("osf: GUID-form bom-ref counts as a tag-id; non-GUID does not; libraries excluded",
      osf["modules_total"] == 2 and osf["guid_tag_id"] == 1)
check("osf: edk2:sourceHash carrier counts toward source_hash_present (M-srchash)",
      osf["source_hash_present"] == 1 and osf["evaluated"] is True)
check("osf: empty SBOM -> evaluated but zero modules (not vacuous)",
      a.osf_conformance({}) == {"evaluated": True, "modules_total": 0, "guid_tag_id": 0, "source_hash_present": 0})

# baseline_metadata: author/timestamp/supplier presence; timestamp accepts 'T' or space separator
bm = a.baseline_metadata({"metadata": {"authors": [{"name": "X"}], "timestamp": "2026-08-08T00:00:00Z",
                                       "supplier": {"name": "Y"}}})
check("baseline: author+timestamp+supplier all present", bm == {"author_present": True, "timestamp_present": True, "supplier_present": True})
check("baseline: space-separated timestamp still accepted (not over-strict)",
      a.baseline_metadata({"metadata": {"timestamp": "2026-08-08 00:00:00"}})["timestamp_present"] is True)
check("baseline: empty metadata -> all absent",
      a.baseline_metadata({}) == {"author_present": False, "timestamp_present": False, "supplier_present": False})

# dependency_facts: edges counted; dangling detected; present-but-edgeless distinguished; null-safe
df = a.dependency_facts({"components": [{"bom-ref": "A"}, {"bom-ref": "B"}],
                         "dependencies": [{"ref": "A", "dependsOn": ["B"]}, {"ref": "B", "dependsOn": ["MISSING"]}]})
check("dep: edges counted, dangling ref detected", df["edges"] == 2 and df["dangling_count"] == 1 and df["dangling"] == ["MISSING"])
check("dep: node-only graph -> present True but edges 0",
      a.dependency_facts({"components": [{"bom-ref": "A"}], "dependencies": [{"ref": "A"}]}) == {"present": True, "edges": 0, "dangling_count": 0, "dangling": [], "has_composition": False})
check("dep: components:null does not crash", a.dependency_facts({"components": None})["present"] is False)

# data_quality: malformed purl + empty license flagged; a charset-legal FAKE license id is NOT (honest ceiling)
dq = a.data_quality({"components": [
    {"name": "ok", "purl": "pkg:github/o/o@1", "licenses": [{"license": {"id": "MIT"}}]},
    {"name": "badpurl", "purl": "not-a-purl"},
    {"name": "emptylic", "licenses": [{"license": {"id": ""}}]}]})
check("dq: malformed purl flagged", dq["purl_invalid"] == 1 and "badpurl" in dq["bad_purls"][0])
check("dq: empty license id flagged", dq["license_invalid"] == 1 and "emptylic" in dq["bad_licenses"])
fake = a.data_quality({"components": [{"name": "f", "licenses": [{"license": {"id": "NOT-A-LICENSE"}}]}]})
check("dq: HONEST CEILING — charset-legal fake id 'NOT-A-LICENSE' is NOT flagged (shape check, not SPDX-list membership)",
      fake["license_invalid"] == 0)
check("dq: components:null does not crash", a.data_quality({"components": None})["license_checked"] == 0)

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
check("binary_hardening: missing_nx NAMES surfaced (sorted) so the gate can name them",
      bh["missing_nx"] == ["A", "B"])

# byte_integrity: MODIFIED module NAMES surfaced (sorted) so the gate can name what tampered
_fd2, _p2 = _tempfile.mkstemp(suffix=".json")
with os.fdopen(_fd2, "w") as _f:
    _json.dump({"checked": 3, "byte_verified": 1,
                "modified": [{"name": "Zeta"}, {"name": "Alpha"}],
                "skipped": [{"name": "SkipMod"}], "errored": []}, _f)
bi = a.byte_integrity_fact(_p2)
os.unlink(_p2)
check("byte_integrity: modified_count + NAMES (sorted) + unverifiable from skipped",
      bi["modified_count"] == 2 and bi["modified"] == ["Alpha", "Zeta"] and bi["unverifiable"] == ["SkipMod"])

# deploy_reconcile_fact — the D-anchor fail-closed path (finding #2). A PRESENT loose verdict must
# D-anchor ITSELF (predicate image_digest == the firmware anchor D); a verdict pointed at another /
# empty image is untrustworthy and fails closed to ABSENT (advisory), never a PASS. It also surfaces
# `declared` (coverage denominator) + `unverifiable` NAMES (skipped/errored) for the gate's
# exemption check. No bundle + no verdict -> absent (the leg is conditional).
_D = "sha256:7965c31705bb824133d173fb9afe64d649005df2d4fc8878274ef25162fb8f37"


def _dr_loose(verdict):
    _fd, _p = _tempfile.mkstemp(suffix=".json")
    with os.fdopen(_fd, "w") as _f:
        _json.dump(verdict, _f)
    try:
        return a.deploy_reconcile_fact(_p, None, _D)
    finally:
        os.unlink(_p)


_dr_base = {"declared": 122, "reconciled": 122, "matched": 122, "mismatched": [], "missing": [],
            "unexpected": [], "skipped": [{"name": "TeSkip"}], "errored": [{"name": "ErrMod"}]}
check("deploy_reconcile: no verdict + no bundle -> absent (ran=False), the conditional leg stays advisory",
      a.deploy_reconcile_fact(None, None, _D)["ran"] is False)
check("deploy_reconcile: a loose verdict D-anchored to D -> ran=True, surfaces declared + unverifiable NAMES",
      _dr_loose({**_dr_base, "image_digest": _D}) == {
          "ran": True, "declared": 122, "reconciled": 122, "matched": 122, "mismatch_count": 0,
          "missing_count": 0, "unexpected_count": 0, "skipped_count": 1,
          "mismatched": [], "missing": [], "unexpected": [], "unverifiable": ["ErrMod", "TeSkip"]})
check("deploy_reconcile: a loose verdict pointed at ANOTHER image (image_digest != D) fails closed to ABSENT (no PASS)",
      _dr_loose({**_dr_base, "image_digest": "sha256:" + "de" * 32})["ran"] is False)
check("deploy_reconcile: a loose verdict with EMPTY image_digest fails closed to ABSENT (cannot prove it is about image D)",
      _dr_loose({**_dr_base, "image_digest": ""})["ran"] is False)

# chipsec_subresults: the platform-posture facts read from chipsec.json results[]; absent module -> ABSENT
cs = a.chipsec_subresults({"results": [
    {"module": "common.secureboot.variables", "result": "PASSED"},
    {"module": "common.smm", "result": "passed"},
    {"module": "common.bios_wp", "result": "FAILED"},
    {"module": "common.bios_ts", "result": "NOTAPPLICABLE"},
]})
check("chipsec_subresults: secure_boot/smm/bios_wp/bios_ts surfaced (upper-cased), absent smrr -> ABSENT",
      cs == {"secure_boot": "PASSED", "smm": "PASSED", "bios_wp": "FAILED",
             "bios_ts": "NOTAPPLICABLE", "smrr": "ABSENT"})

# sbom_identity + component_supplier (Increment E)
idf = a.sbom_identity({"serialNumber": "urn:uuid:a4b5bfe8-34ca-4810-8985-856d63fde373",
                       "compositions": [{"aggregate": "incomplete"}]})
check("identity: urn:uuid serialNumber + aggregate -> both declared",
      idf["serial_present"] is True and idf["completeness_declared"] is True and idf["aggregate"] == "incomplete")
check("identity: non-uuid serialNumber -> serial absent (shape-checked)",
      a.sbom_identity({"serialNumber": "not-a-uuid"})["serial_present"] is False)
csup = a.component_supplier({"components": [{"name": "a", "supplier": {"name": "X"}}, {"name": "b"}]})
check("component_supplier: missing supplier flagged", csup["missing_count"] == 1 and csup["missing"] == ["b"])
check("component_supplier: components:null does not crash", a.component_supplier({"components": None})["total"] == 0)

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
