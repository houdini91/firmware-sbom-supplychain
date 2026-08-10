#!/usr/bin/env python3
"""Unit tests for the deploy-reconcile producer (Track A: CHIPSEC-fed deploy-time reconcile).

Two layers, mirroring the byte-integrity test's discipline:
  1) HERMETIC pure-logic tests on a SYNTHESIZED chipsec `uefi decode` tree — no pefile / no
     chipsec / no full OVMF needed. They cover the pieces that make this producer honest:
       * GUID-keying (two modules sharing a NAME but distinct FILE_GUIDs — the OVMF CpuMpPei
         collision — are kept apart);
       * the IMMEDIATE-parent FV-type derivation (the nested-FV trap the A3 prototype fixed:
         a module deep under an outer '.FV_FVIMAGE.dir' still takes its type from its own
         '<NN>_<guid>.FV_PEIM.dir', not the wrapper);
       * TE / non-PE sections are SKIPPED, never counted as verified;
       * BIDIRECTIONAL reconcile: a declared GUID with no extract -> MISSING; an extracted
         GUID absent from the SBOM -> UNEXPECTED; a byte change -> MISMATCH.
     These use DXE_DRIVER (direct-hash) modules so they run WITHOUT pefile.
  2) The 122/122 REFERENCE assertion against the real OVMF CHIPSEC extraction — run ONLY when
     pefile is installed AND the decode tree is reachable (env DEPLOY_RECONCILE_REF, or the A3
     scratch dir). Otherwise it SKIPS loudly (like the coSWID tests), never a silent green.

Run: python3 tests/test_deploy_reconcile.py     # hermetic tests always run
     DEPLOY_RECONCILE_REF=<decode-dir> <python-with-pefile> tests/test_deploy_reconcile.py
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
_spec = importlib.util.spec_from_file_location(
    "deploy_reconcile", os.path.join(ROOT, "producers", "chipsec", "deploy-reconcile.py"))
dr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dr)

ok = True
skipped = 0


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


# ---- helpers: synthesize a chipsec `uefi decode` tree + a matching CycloneDX SBOM ----
def _dash(guid32):
    g = guid32
    return "%s-%s-%s-%s-%s" % (g[0:8], g[8:12], g[12:16], g[16:20], g[20:32])


def _write_module(base, fv_type, guid32, fname, payload, idx=0, nested=False):
    """Write a module file into a '<idx>_<guid>.FV_TYPE.dir' (optionally under an outer
    '.FV_FVIMAGE.dir' wrapper, to exercise the immediate-parent derivation)."""
    parent = "%02d_%s.%s.dir" % (idx, _dash(guid32), fv_type)
    if nested:
        d = os.path.join(base, "FV", "00_%s.FV_FVIMAGE.dir" % _dash("a" * 32),
                         "01_S_FV_IMAGE.dir", parent)
    else:
        d = os.path.join(base, "FV", parent)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, fname), "wb") as f:
        f.write(payload)


def _sbom(entries):
    """entries: {guid32: (name, sha256hex)} -> a minimal CycloneDX file path."""
    comps = [{"type": "firmware", "name": n, "bom-ref": _dash(g),
              "hashes": [{"alg": "SHA-256", "content": h}]} for g, (n, h) in entries.items()]
    fd, p = tempfile.mkstemp(suffix=".cdx.json")
    with os.fdopen(fd, "w") as f:
        json.dump({"components": comps}, f)
    return p


PE = b"MZ" + b"\x90" * 62  # a 'direct' (DXE) module body — is_pe True, hashed as-is (no pefile)
TE = b"VZ" + b"\x00" * 62  # a TE image — is_pe False -> SKIP
GUID_A = "aa" * 16
GUID_B = "bb" * 16
GUID_TE = "cc" * 16
GUID_X = "dd" * 16          # extracted but NOT in the SBOM -> UNEXPECTED
GUID_MISS = "ee" * 16       # in the SBOM but never extracted -> MISSING
GUID_DUP = "ff" * 16        # second module NAMED like A but distinct GUID (collision guard)


def h(b):
    return hashlib.sha256(b).hexdigest()


# ---- 1) collect_modules: GUID/type derivation, nested-FV trap, TE detection ----
td = tempfile.mkdtemp()
_write_module(td, "FV_DRIVER", GUID_A, "ModA.efi", PE, idx=1)
_write_module(td, "FV_PEIM", GUID_B, "CpuMpPei.efi", PE, idx=2, nested=True)  # deep under FV_FVIMAGE
_write_module(td, "FV_PEIM", GUID_DUP, "CpuMpPei.efi", PE, idx=3, nested=True)  # SAME name, other GUID
_write_module(td, "FV_PEIM", GUID_TE, "ModTE.te", TE, idx=4)
mods = dr.collect_modules(td)
by_guid = {m["guid"]: m for m in mods}
check("collect_modules: finds all 4 module files", len(mods) == 4)
check("collect_modules: FV_DRIVER -> DXE_DRIVER (direct)", by_guid[GUID_A]["filetype"] == "DXE_DRIVER")
check("collect_modules: NESTED module takes type from its IMMEDIATE FV_PEIM parent, not the outer FV_FVIMAGE wrapper (nested-FV trap)",
      by_guid[GUID_B]["filetype"] == "PEIM")
check("collect_modules: two CpuMpPei with distinct GUIDs are kept apart (GUID-keyed, names collide)",
      GUID_B in by_guid and GUID_DUP in by_guid and by_guid[GUID_B]["name"] == by_guid[GUID_DUP]["name"] == "CpuMpPei")
check("collect_modules: a TE ('VZ') section is is_pe=False -> will be SKIPPED", by_guid[GUID_TE]["is_pe"] is False)

# ---- 2) reconcile: matched / mismatch / missing / unexpected / skip + clean flag ----
# A dedicated DXE_DRIVER (direct-hash) tree so the whole reconcile runs WITHOUT pefile:
#   GUID_A matches; GUID_MM declared with the WRONG hash -> MISMATCH; GUID_TE is a TE section
#   -> SKIP; GUID_MISS declared but never extracted -> MISSING; GUID_X extracted but NOT declared
#   -> UNEXPECTED.
GUID_MM = "12" * 16
td2 = tempfile.mkdtemp()
_write_module(td2, "FV_DRIVER", GUID_A, "ModA.efi", PE, idx=1)
_write_module(td2, "FV_DRIVER", GUID_MM, "ModMM.efi", PE, idx=2)   # bytes = PE, but declared hash differs
_write_module(td2, "FV_DRIVER", GUID_TE, "ModTE.te", TE, idx=3)    # TE -> skip
_write_module(td2, "FV_DRIVER", GUID_X, "ModX.efi", PE, idx=4)     # not declared -> unexpected
mods2 = dr.collect_modules(td2)
declared = dr.load_sbom_hashes(_sbom({
    GUID_A: ("ModA", h(PE)),
    GUID_MM: ("ModMM", h(PE + b"\x01")),  # declared != observed -> mismatch
    GUID_TE: ("ModTE", h(b"whatever")),   # extracted only as TE -> skip
    GUID_MISS: ("Gone", h(PE)),           # never extracted -> missing
}))
v = dr.reconcile(declared, mods2)
check("reconcile: GUID_A matches (direct hash, no pefile needed)",
      v["matched"] == 1 and v["matched_modules"][0]["guid"] == GUID_A)
check("reconcile: wrong-hash module -> 1 MISMATCH", len(v["mismatched"]) == 1 and v["mismatched"][0]["guid"] == GUID_MM)
check("reconcile: TE section -> 1 SKIP (never counted as matched)", len(v["skipped"]) == 1 and v["skipped"][0]["guid"] == GUID_TE)
check("reconcile: declared-but-unextracted -> 1 MISSING (tamper/dropped)", len(v["missing"]) == 1 and v["missing"][0]["guid"] == GUID_MISS)
check("reconcile: extracted-but-undeclared -> 1 UNEXPECTED (implant)", len(v["unexpected"]) == 1 and v["unexpected"][0]["guid"] == GUID_X)
check("reconcile: reconciled == matched + mismatched (the comparable set)", v["reconciled"] == 2)
check("reconcile: NOT clean while any mismatch/missing/unexpected stands", v["clean"] is False)
check("reconcile: predicateType is the stable-namespace deploy-reconcile v1",
      v["predicateType"] == "https://firmware-sbom-supplychain/deploy-reconcile/v1")
check("reconcile: evidenceGrade is 'verified' (reconciled from real extracted bytes)", v["evidenceGrade"] == "verified")

# an all-matching run is clean
v2 = dr.reconcile(dr.load_sbom_hashes(_sbom({GUID_A: ("ModA", h(PE))})),
                  [m for m in mods2 if m["guid"] == GUID_A])
check("reconcile: an all-matching extract (1/1) is clean -> exit-0 shape", v2["clean"] is True and v2["matched"] == 1)

# ---- 3) REFERENCE: the real OVMF CHIPSEC extraction reconciles 122/122 (needs pefile + tree) ----
ref = os.environ.get("DEPLOY_RECONCILE_REF")
_A3 = "/tmp/claude-1000/-home-mikey-mikey/59320455-965d-4554-a945-77eedd38cbac/scratchpad/chipsec-verify/run"
if not ref and os.path.isdir(os.path.join(_A3, "OVMF_CODE.fd.dir")):
    ref = os.path.join(_A3, "OVMF_CODE.fd.dir")
ref_sbom = os.path.join(ROOT, "inputs", "sbom.cdx.json")
if dr.bi.pefile is None:
    skipped += 1
    print("SKIP  122/122 OVMF reference reconcile (pefile not installed — the XIP un-rebase path "
          "cannot run; install pefile / run with the pefile venv). Hermetic tests above still ran.")
elif not (ref and os.path.isdir(ref) and os.path.isfile(ref_sbom)):
    skipped += 1
    print("SKIP  122/122 OVMF reference reconcile (decode tree not reachable — set DEPLOY_RECONCILE_REF "
          "to a `chipsec_util uefi decode <OVMF>.fd.dir`). Hermetic tests above still ran.")
else:
    efilist = os.path.join(os.path.dirname(ref), "efilist.json")
    rmods = dr.collect_modules(ref, efilist if os.path.isfile(efilist) else None)
    rv = dr.reconcile(dr.load_sbom_hashes(ref_sbom), rmods)
    check("reference: CHIPSEC-extracted OVMF reconciles 122/122 against the signed SBOM (A3 parity)",
          rv["matched"] == 122 and rv["reconciled"] == 122)
    check("reference: no mismatch / missing / unexpected on the clean reference image",
          not rv["mismatched"] and not rv["missing"] and not rv["unexpected"] and rv["clean"] is True)
    check("reference: 11 XIP modules took the un-rebase path, 111 the direct path (A3 split)",
          rv["verified_unrebase"] == 11 and rv["verified_direct"] == 111)

print("----")
if skipped:
    print("⚠  %d REFERENCE TEST GROUP(S) SKIPPED — the 122/122 OVMF reconcile did NOT run here "
          "(pefile and/or the CHIPSEC decode tree unavailable). The hermetic logic tests ran." % skipped)
print(("ALL PASS%s" % (" (with %d SKIPPED — see warning)" % skipped if skipped else "")) if ok else "FAILURES")
sys.exit(0 if ok else 1)
