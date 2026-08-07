#!/usr/bin/env python3
"""Unit test for the coSWID emit/ingest round-trip (producers/interop/coswid-*.py)
plus the PEI/XIP byte-integrity coverage that guards the BUG-1 fix.

Part A (needs python-uswid): a coSWID emitted from a CycloneDX SBOM via uswid's
NATIVE loader survives a CBOR round-trip carrying the module GUID + the declared
SHIPPED-BYTE SHA-256; a REAL source hash supplied via --source-hashes rides in
`colloquial-version`; ingest recovers the shipped-byte hash into a reconcile-ready
SBOM. Also asserts the documented spec-gap: python-uswid's evidence branch carries
NO hash field (the reason the device-measured hash stays a proposal, not a shipped
private format).

Part B (needs pefile + committed PE fixtures): a PEI/XIP module whose coSWID/SBOM
declares ONLY a hash (no module type) is still byte-verified, because byte-integrity
reads the module type from the CARVED FFS (the image) and un-rebases. This is the
case that BUG-1 got wrong: the old ingest stamped DXE_DRIVER on every module, so a
real PEI module took the DXE "direct" path and false-FAILed a clean image. The test
also asserts the negative (a direct compare of the rebased bytes would NOT match),
so the fix is proven, not just exercised.

Each part SKIPS cleanly when its dependency/fixtures are absent, so `make test`
stays hermetic. Run: python3 tests/test_coswid.py
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

ok = True
skipped = 0


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


def _load(modname, relpath):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Part A — coSWID emit/ingest round-trip (native uswid loader)
# ---------------------------------------------------------------------------
try:
    import uswid  # noqa: F401
    from uswid.evidence import uSwidEvidence
    _HAVE_USWID = True
except ImportError:
    _HAVE_USWID = False

if not _HAVE_USWID:
    skipped += 1
    print("SKIP  Part A: python-uswid not installed (pip install uswid) — coSWID round-trip skipped")
else:
    emit = _load("coswid_emit", "producers/interop/coswid-emit.py")
    ingest = _load("coswid_ingest", "producers/interop/coswid-ingest.py")

    GUID = "deadbeef-1111-2222-3333-444455556666"
    EVID = "3b" * 32   # pretend normalized shipped-byte hash (the CDX component hash)
    SRCH = "51" * 32   # pretend REAL source-file hash (supplied via --source-hashes)

    with tempfile.TemporaryDirectory() as td:
        in_sbom = os.path.join(td, "in.cdx.json")
        # `device-driver` type deliberately used: uswid 0.6.0's native loader can't
        # parse it — emit must sanitize it, exactly as on a real OVMF SBOM.
        json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                   "metadata": {"component": {"type": "firmware", "name": "t"}},
                   "components": [{"type": "device-driver", "name": "DemoMod", "bom-ref": GUID,
                                   "version": "1.0",
                                   "hashes": [{"alg": "SHA-256", "content": EVID}]}]},
                  open(in_sbom, "w"))
        json.dump({GUID: SRCH}, open(os.path.join(td, "src.json"), "w"))

        coswid = os.path.join(td, "DemoMod.coswid")
        sys.argv = ["emit", "--sbom", in_sbom, "--source-hashes", os.path.join(td, "src.json"),
                    "--out", coswid]
        emit.main()
        check("emit produced a coSWID CBOR blob (native loader, device-driver type sanitized)",
              os.path.getsize(coswid) > 0)

        out_sbom = os.path.join(td, "out.cdx.json")
        out_map = os.path.join(td, "map.json")
        sys.argv = ["ingest", "--load", coswid, "--out-sbom", out_sbom, "--out-map", out_map]
        ingest.main()

        got = json.load(open(out_sbom))
        comp = got["components"][0]
        check("ingest recovered the module GUID", comp["bom-ref"] == GUID)
        check("ingest SBOM carries the SHIPPED-BYTE hash (the CDX component hash)",
              comp["hashes"][0]["content"] == EVID)
        check("ingest SBOM declares HASH ONLY — no module type (byte-integrity gets type from the image)",
              not any(p.get("name") == "edk2:moduleType" for p in comp.get("properties", [])))

        hmap = json.load(open(out_map))
        check("real source hash rides in colloquial-version and survives the round-trip",
              hmap[GUID]["source"] == SRCH)
        check("shipped-byte hash recovered distinct from the source hash",
              hmap[GUID]["declared"] == EVID and hmap[GUID]["source"] != hmap[GUID]["declared"])

        # No source hash supplied -> NONE is emitted (no fabricated stand-in).
        no_src_coswid = os.path.join(td, "DemoMod2.coswid")
        sys.argv = ["emit", "--sbom", in_sbom, "--out", no_src_coswid]
        emit.main()
        sys.argv = ["ingest", "--load", no_src_coswid, "--out-sbom", os.path.join(td, "o2.json"),
                    "--out-map", os.path.join(td, "m2.json")]
        ingest.main()
        m2 = json.load(open(os.path.join(td, "m2.json")))
        check("no --source-hashes -> source hash is None (nothing fabricated)",
              m2[GUID]["source"] is None and m2[GUID]["declared"] == EVID)

    # The documented spec-gap and its resolution. Stock python-uswid's uSwidEvidence
    # carries only {date, device_id} — no hash field — which is *why* our shipped-byte
    # hash currently rides the payload branch and the device-measured hash stays a
    # proposal. Our upstream PR ("evidence: add an optional measured hash") closes that
    # gap. This assertion is forward-compatible: it documents the gap on a stock uswid
    # AND passes on a uswid that already has the fix, so landing our PR upstream does
    # not turn this test red.
    _evidence_has_hash = any(
        "hash" in a.lower() for a in dir(uSwidEvidence()) if not a.startswith("_")
    )
    if _evidence_has_hash:
        check("SPEC-GAP RESOLVED: this python-uswid's evidence branch now carries a hash "
              "field (our upstream PR) — device-measured hash can migrate off proposal",
              hasattr(uSwidEvidence(), "add_hash"))
    else:
        check("SPEC-GAP: stock python-uswid evidence branch carries NO hash field "
              "(device-hash stays a proposal; shipped-byte hash rides the payload)", True)


# ---------------------------------------------------------------------------
# Part B — PEI/XIP byte-integrity (guards the BUG-1 fix)
# ---------------------------------------------------------------------------
bi = _load("byte_integrity", "producers/reconcile/byte-integrity.py")
adb = _load("attack_demo_build", "scripts/attack_demo_build.py")

decl_p = os.path.join(HERE, "fixtures", "pe", "pcdpeim.declared.efi")     # base-0 declared
flash_p = os.path.join(HERE, "fixtures", "pe", "pcdpeim.inflash.pe32")    # rebased in-flash

if bi.pefile is None:
    skipped += 1
    print("SKIP  Part B: pefile not installed (pip install -r requirements.txt) — PEI/XIP un-rebase skipped")
elif not (os.path.isfile(decl_p) and os.path.isfile(flash_p)):
    skipped += 1
    print("SKIP  Part B: PE fixtures missing — PEI/XIP un-rebase skipped")
else:
    PEI_GUID = "deadbeef-1111-2222-3333-444455556666"
    declared_bytes = open(decl_p, "rb").read()
    inflash_bytes = open(flash_p, "rb").read()
    declared_hash = hashlib.sha256(declared_bytes).hexdigest()

    # Precondition: the rebased in-flash PE32 (what a "direct" compare would hash)
    # does NOT match the declared base-0 hash — so ONLY an un-rebase can verify it.
    check("PEI precondition: rebased in-flash bytes != declared base-0 hash (direct compare would fail)",
          hashlib.sha256(inflash_bytes).hexdigest() != declared_hash)

    with tempfile.TemporaryDirectory() as td:
        # ingested-style SBOM: declared HASH + GUID only, NO module type (as ingest now emits).
        sbom_p = os.path.join(td, "ingested.cdx.json")
        json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
                   "metadata": {"component": {"type": "firmware", "name": "coswid-ingested-firmware"}},
                   "components": [{"type": "application", "name": "PcdPeim", "bom-ref": PEI_GUID,
                                   "version": "1.0",
                                   "hashes": [{"alg": "SHA-256", "content": declared_hash}]}]},
                  open(sbom_p, "w"))
        # carve dir: a PEIM-typed (EFI_FV_FILETYPE 0x06) FFS around the rebased PE32.
        ffs_dir = os.path.join(td, "ffs")
        adb.write_ffs_dir(ffs_dir, PEI_GUID, inflash_bytes, ftype=0x06)

        out_v = os.path.join(td, "byte.json")
        sys.argv = ["byte-integrity", "--sbom", sbom_p, "--ffs-dir", ffs_dir, "-o", out_v]
        code = 0
        try:
            bi.main()
        except SystemExit as e:
            code = e.code or 0
        verdict = json.load(open(out_v))

        check("BUG-1 FIX: typeless-SBOM PEI module is byte-VERIFIED (type read from the FFS, un-rebased)",
              verdict["clean"] and code == 0)
        check("BUG-1 FIX: the PEI module was verified via method='un-rebase', not 'direct'",
              verdict["verified"] and verdict["verified"][0]["method"] == "un-rebase")


print("----")
if skipped:
    print("⚠  %d TEST GROUP(S) SKIPPED (missing python-uswid / pefile / fixtures). "
          "CI installs them and runs every group." % skipped)
print(("ALL PASS%s" % (" (with %d SKIPPED — see warning)" % skipped if skipped else "")) if ok else "FAILURES")

# --require-deps: fail (non-zero) if any group SKIPPED, so a run that is *meant*
# to cover the coSWID round-trip + PEI/XIP BUG-1 regression cannot pass green
# with those groups silently absent. Used by `make test-full` / CI.
if "--require-deps" in sys.argv and skipped:
    print("ERROR  --require-deps set but %d group(s) skipped: install python-uswid + "
          "pefile (and build PE fixtures) so every group runs." % skipped)
    sys.exit(2)
sys.exit(0 if ok else 1)
