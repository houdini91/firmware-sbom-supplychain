#!/usr/bin/env python3
"""coswid_demo_build — staging + fact-folding for the coSWID verification demo.

File plumbing ONLY. Every security decision is made by the REAL tools the demo
harness (scripts/coswid-demo.sh) then runs:
  * producers/interop/coswid-emit.py / coswid-ingest.py  (python-uswid coSWID I/O)
  * producers/reconcile/sbom-reconcile.py                (membership)
  * producers/reconcile/byte-integrity.py                (shipped-byte compare)
  * oss-lane/gate.sh + policy/firmware.rego              (the deploy decision + VSA)

Reuses attack_demo_build (the same real committed edk2 PE32 fixture + the same
minimal-real EFI_FFS builder) so the coSWID demo and the attack demo share one
staging path.

Subcommands
  stage <workdir>
      Write:
        input-sbom.cdx.json   1-module CDX; component SHA-256 = the module's
                              NORMALIZED SHIPPED-BYTE hash (coswid-emit's evidence input).
        source-hashes.json    {guid: sha256} — a real SHA-256 over a demo source
                              stand-in file (edk2 source is not in this repo).
        clean/<guid>.ffs      real FFS around the known-good PE32.
        tampered/<guid>.ffs   SAME GUID/name, one code byte flipped (the same-GUID swap).
        fmmt-view.txt         synthetic FMMT -v view listing the module (membership input).
  gate-input <reconcile-verdict> <byte-integrity-verdict> <out>
      Fold BOTH real producer verdicts into a gate input (base = clean fixture,
      scaled to this 1-module firmware), so every OTHER verifier legitimately passes
      and the ONLY things under test are membership (still PASS on a same-GUID swap)
      and byte-integrity (FLIPS on the swap).
"""
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load(modname, relpath):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


adb = _load("attack_demo_build", "scripts/attack_demo_build.py")
asm = _load("assemble_gate_input", "oss-lane/assemble_gate_input.py")

DEMO_GUID = adb.DEMO_GUID
DEMO_NAME = adb.DEMO_NAME
GOOD_MODULE = adb.GOOD_MODULE
TAMPER_OFFSET = adb.TAMPER_OFFSET
TAMPER_XOR = adb.TAMPER_XOR

# A demo source stand-in so the OSF source-file hash is a REAL SHA-256 of a REAL file
# (not edk2's actual .c/.h — that tree is not in this repo).
DEMO_SOURCE = ("// %s — demo source stand-in for the coSWID source-file hash.\n"
               "// The real OSF payload hash is SHA-256 over the module's .c/.h set;\n"
               "// edk2 source is not vendored here, so this file stands in for it.\n"
               % DEMO_NAME).encode()


def cmd_stage(workdir):
    if not os.path.isfile(GOOD_MODULE):
        sys.exit("coswid_demo_build: missing committed fixture %s" % GOOD_MODULE)
    good = open(GOOD_MODULE, "rb").read()
    evidence = hashlib.sha256(good).hexdigest()          # normalized shipped-byte hash

    tampered = bytearray(good)
    before = tampered[TAMPER_OFFSET]
    tampered[TAMPER_OFFSET] ^= TAMPER_XOR
    after = tampered[TAMPER_OFFSET]

    os.makedirs(workdir, exist_ok=True)
    # input CDX for coswid-emit: component SHA-256 = the evidence (shipped-byte) hash
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "firmware", "name": "coswid-demo-1module"}},
            "components": [{"type": "application", "name": DEMO_NAME, "bom-ref": DEMO_GUID,
                            "version": "1.0",
                            "properties": [{"name": "edk2:moduleType", "value": "DXE_DRIVER"}],
                            "hashes": [{"alg": "SHA-256", "content": evidence}]}]}
    json.dump(sbom, open(os.path.join(workdir, "input-sbom.cdx.json"), "w"), indent=2)

    src_hash = hashlib.sha256(DEMO_SOURCE).hexdigest()
    json.dump({DEMO_GUID: src_hash}, open(os.path.join(workdir, "source-hashes.json"), "w"), indent=2)

    adb.write_ffs_dir(os.path.join(workdir, "clean"), DEMO_GUID, good)
    adb.write_ffs_dir(os.path.join(workdir, "tampered"), DEMO_GUID, bytes(tampered))

    # synthetic FMMT -v view: the module IS present (same GUID for clean & tampered),
    # so membership PASSES in both cases — only the bytes differ.
    fmmt = ("FvNameGuid: 8c8ce578-8a3d-4f1c-9935-896185c32dd3\n"
            "  File: %s / %s\n" % (DEMO_GUID.upper(), DEMO_NAME))
    open(os.path.join(workdir, "fmmt-view.txt"), "w").write(fmmt)

    print("staged coSWID demo in %s" % workdir)
    print("  module         : %s  (GUID %s, DXE_DRIVER)" % (DEMO_NAME, DEMO_GUID))
    print("  evidence hash  : %s…  (normalized shipped-byte SHA-256 of the real PE32)" % evidence[:16])
    print("  source hash    : %s…  (SHA-256 of a demo source stand-in — not edk2 source)" % src_hash[:16])
    print("  TAMPER         : flipped 1 byte at PE offset 0x%04X: 0x%02X -> 0x%02X  (SAME GUID/name)"
          % (TAMPER_OFFSET, before, after))


def _reconcile_fact(verdict_path):
    """Fold sbom-reconcile.py's REAL verdict into the gate reconcile fact —
    the exact mapping oss-lane/assemble_gate_input.py uses."""
    d = json.load(open(verdict_path))
    s = d.get("summary", {})
    return {"clean": d.get("clean", False),
            "missing": d.get("missing", []), "added": d.get("added", []), "modified": d.get("modified", []),
            "declared": s.get("declared_modules", 0), "matched": s.get("validated", 0),
            "missing_count": s.get("missing", 0), "undeclared_observed": s.get("added_suspicious", 0)}


def cmd_gate_input(reconcile_v, byte_v, out_path):
    base = json.load(open(os.path.join(ROOT, "oss-lane", "fixtures", "clean.json")))
    base["sbom"]["integrity"] = {"hashable_total": 1, "hashed": 1, "unhashed": [], "dxe_class_total": 1}
    base["binary_hardening"] = {"ran": True, "dxe_class_checked": 1, "dxe_nx_compat": 1,
                                "missing_nx_count": 0, "errored_count": 0, "unverifiable": []}
    base["reconcile"] = _reconcile_fact(reconcile_v)            # REAL membership verdict
    base["byte_integrity"] = asm.byte_integrity_fact(byte_v)    # REAL byte-integrity verdict (real assembler)
    json.dump(base, open(out_path, "w"), indent=2)
    print("gate input -> %s  (reconcile.clean=%s, byte_integrity=%s)"
          % (out_path, base["reconcile"]["clean"], json.dumps(base["byte_integrity"])))


def main(argv):
    if len(argv) >= 3 and argv[1] == "stage":
        return cmd_stage(argv[2])
    if len(argv) >= 5 and argv[1] == "gate-input":
        return cmd_gate_input(argv[2], argv[3], argv[4])
    sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
