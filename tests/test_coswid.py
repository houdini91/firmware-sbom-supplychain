#!/usr/bin/env python3
"""Unit test for the coSWID emit/ingest round-trip (producers/interop/coswid-*.py).

Proves WS-A + WS-B in isolation: a coSWID emitted with BOTH a source-file hash and
a normalized shipped-byte (evidence) hash survives a CBOR round-trip, and ingest
recovers the SHIPPED-BYTE hash into the reconcile-ready SBOM. Also asserts the
documented spec-gap: python-uswid's evidence branch carries NO hash field.

SKIPS cleanly (exit 0) when python-uswid is not importable, so `make test` stays
hermetic on hosts without it. Install to actually run: `pip install uswid`.

Run: python3 tests/test_coswid.py
"""
import importlib.util
import json
import os
import sys
import tempfile

try:
    import uswid  # noqa: F401
    from uswid.evidence import uSwidEvidence
except ImportError:
    print("SKIP  python-uswid not installed (pip install uswid) — coSWID round-trip test skipped")
    sys.exit(0)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load(modname, relpath):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


emit = _load("coswid_emit", "producers/interop/coswid-emit.py")
ingest = _load("coswid_ingest", "producers/interop/coswid-ingest.py")

ok = True


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


GUID = "deadbeef-1111-2222-3333-444455556666"
EVID = "3b" * 32   # pretend normalized shipped-byte hash
SRCH = "51" * 32   # pretend source-file hash

with tempfile.TemporaryDirectory() as td:
    in_sbom = os.path.join(td, "in.cdx.json")
    json.dump({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
               "metadata": {"component": {"type": "firmware", "name": "t"}},
               "components": [{"type": "application", "name": "DemoMod", "bom-ref": GUID,
                               "version": "1.0",
                               "properties": [{"name": "edk2:moduleType", "value": "DXE_DRIVER"}],
                               "hashes": [{"alg": "SHA-256", "content": EVID}]}]},
              open(in_sbom, "w"))
    json.dump({GUID: SRCH}, open(os.path.join(td, "src.json"), "w"))

    coswid = os.path.join(td, "DemoMod.coswid")
    sys.argv = ["emit", "--sbom", in_sbom, "--source-hashes", os.path.join(td, "src.json"),
                "--out", coswid]
    emit.main()
    check("emit produced a coSWID CBOR blob", os.path.getsize(coswid) > 0)

    out_sbom = os.path.join(td, "out.cdx.json")
    out_map = os.path.join(td, "map.json")
    sys.argv = ["ingest", "--load", coswid, "--out-sbom", out_sbom, "--out-map", out_map]
    ingest.main()

    got = json.load(open(out_sbom))
    comp = got["components"][0]
    check("ingest recovered the module GUID", comp["bom-ref"] == GUID)
    check("ingest SBOM carries the SHIPPED-BYTE (evidence) hash, not the source hash",
          comp["hashes"][0]["content"] == EVID)

    hmap = json.load(open(out_map))
    check("both hashes survive the round-trip (source + evidence distinct)",
          hmap[GUID]["source"] == SRCH and hmap[GUID]["evidence"] == EVID)

# The documented spec-gap: uSwidEvidence has no hash field (only date/device_id).
check("SPEC-GAP: python-uswid evidence branch carries NO hash field",
      not any("hash" in a.lower() for a in dir(uSwidEvidence()) if not a.startswith("_")))

print("----")
print("ALL PASS" if ok else "FAILURES")
sys.exit(0 if ok else 1)
