#!/usr/bin/env python3
"""attack_demo_build — stage the "same-GUID trojan" attack demo from committed fixtures.

Support code for `make attack-demo` (scripts/attack-demo.sh). It does the file
plumbing ONLY — building the inputs and folding the producer's verdict into a gate
input. The security decisions are made by the REAL tools the harness then runs:
  * producers/reconcile/byte-integrity.py  (the PE32 carve + SHA-256 compare)
  * oss-lane/gate.sh + policy/firmware.rego (the deploy decision)

Subcommands
  stage <workdir>            build clean/ + tampered/ FFS dirs and a 1-module demo
                             SBOM from a committed real PE32 module; print the tamper.
  gate-input <verdict> <out> fold a byte-integrity verdict into a gate input (reusing
                             the REAL oss-lane assembler's byte_integrity_fact()).

Known-good module: tests/fixtures/pe/pcdpeim.declared.efi — a genuine edk2 PE32
(GenFw-normalized). The demo registers it in a tiny SBOM as a DXE driver so the
producer hashes it directly (method="direct", no pefile/un-rebase needed), builds a
real FFS around it, then ships a 1-byte-patched copy under the SAME FILE_GUID/name —
the same-GUID swap reconcile-membership cannot see but byte-integrity does.
"""
import hashlib
import importlib.util
import json
import os
import struct
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# A fixed demo identity. The bytes are a real module; the GUID/name are the demo's.
DEMO_GUID = "deadbeef-1111-2222-3333-444455556666"
DEMO_NAME = "DemoNetworkDxe"
GOOD_MODULE = os.path.join(ROOT, "tests", "fixtures", "pe", "pcdpeim.declared.efi")
# A byte deep inside the PE body (not the MZ/PE headers): a subtle in-code trojan,
# exactly the kind of change a same-GUID swap hides and membership never sees.
TAMPER_OFFSET = 0x1000
TAMPER_XOR = 0x01


def guid_nodash(guid):
    return guid.replace("-", "").lower()


def build_ffs(guid, pe_bytes, ftype=0x07):
    """A minimal-but-real EFI_FFS_FILE (24-byte header + one EFI_SECTION_PE32) —
    exactly the shape `FMMT -e` emits and that ffs.pe32_from_ffs walks. `ftype` is
    the EFI_FV_FILETYPE byte (0x07=DRIVER default; 0x06=PEIM etc.), which the
    verification side reads back (ffs.ffs_module_type) to pick direct vs un-rebase."""
    name16 = uuid.UUID(guid).bytes_le          # EFI mixed-endian GUID
    sec_size = 4 + len(pe_bytes)               # common section header (3B size + 1B type) + payload
    section = bytes([sec_size & 0xFF, (sec_size >> 8) & 0xFF, (sec_size >> 16) & 0xFF, 0x10]) + pe_bytes
    ffs_size = 24 + len(section)
    header = (name16                            # Name (GUID)           [0x00..0x0F]
              + b"\xAA\xAA"                      # IntegrityCheck        [0x10..0x11]
              + bytes([ftype & 0xFF, 0x00])     # Type, Attributes=0 (bit0 LARGE_FILE clear) [0x12,0x13]
              + bytes([ffs_size & 0xFF, (ffs_size >> 8) & 0xFF, (ffs_size >> 16) & 0xFF])  # Size [0x14..0x16]
              + bytes([0x00]))                  # State                 [0x17]
    return header + section


def write_ffs_dir(path, guid, pe_bytes, ftype=0x07):
    os.makedirs(path, exist_ok=True)
    dst = os.path.join(path, guid_nodash(guid) + ".ffs")
    with open(dst, "wb") as f:
        f.write(build_ffs(guid, pe_bytes, ftype))
    return dst


def write_sbom(path, guid, name, declared_hash):
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "firmware", "name": "demo-firmware-1module"}},
        "components": [{
            "type": "application", "name": name, "bom-ref": guid,
            "properties": [{"name": "edk2:moduleType", "value": "DXE_DRIVER"}],
            "hashes": [{"alg": "SHA-256", "content": declared_hash}],
        }],
    }
    with open(path, "w") as f:
        json.dump(sbom, f, indent=2)


def cmd_stage(workdir):
    if not os.path.isfile(GOOD_MODULE):
        sys.exit("attack_demo_build: missing committed fixture %s" % GOOD_MODULE)
    good = open(GOOD_MODULE, "rb").read()
    declared = hashlib.sha256(good).hexdigest()

    tampered = bytearray(good)
    before = tampered[TAMPER_OFFSET]
    tampered[TAMPER_OFFSET] ^= TAMPER_XOR
    after = tampered[TAMPER_OFFSET]
    tampered_hash = hashlib.sha256(bytes(tampered)).hexdigest()

    os.makedirs(workdir, exist_ok=True)
    write_sbom(os.path.join(workdir, "demo-sbom.cdx.json"), DEMO_GUID, DEMO_NAME, declared)
    write_ffs_dir(os.path.join(workdir, "clean"), DEMO_GUID, good)
    write_ffs_dir(os.path.join(workdir, "tampered"), DEMO_GUID, bytes(tampered))

    print("staged same-GUID trojan demo in %s" % workdir)
    print("  module          : %s  (GUID %s)" % (DEMO_NAME, DEMO_GUID))
    print("  known-good bytes : %s  (%d bytes, from %s)"
          % (declared[:16] + "…", len(good), os.path.relpath(GOOD_MODULE, ROOT)))
    print("  TAMPER           : flipped 1 byte at PE offset 0x%04X: 0x%02X -> 0x%02X  (SAME GUID/name)"
          % (TAMPER_OFFSET, before, after))
    print("  tampered bytes   : %s  (declared hash unchanged in the SBOM — that's the point)"
          % (tampered_hash[:16] + "…"))


def _byte_integrity_fact(verdict_path):
    spec = importlib.util.spec_from_file_location(
        "assemble_gate_input", os.path.join(ROOT, "oss-lane", "assemble_gate_input.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.byte_integrity_fact(verdict_path)


def cmd_gate_input(verdict_path, out_path):
    """Fold the REAL producer's verdict into a gate input. Base = the clean fixture,
    but scaled to this 1-module demo firmware (integrity + reconcile counts = 1) so
    every OTHER verifier report legitimately passes — isolating the ONE thing under
    test: byte-integrity. reconcile-membership PASSES (the swapped module has the same
    GUID, so it is 'present'); only component-byte-integrity flips."""
    base = json.load(open(os.path.join(ROOT, "oss-lane", "fixtures", "clean.json")))
    base["sbom"]["integrity"] = {"hashable_total": 1, "hashed": 1, "unhashed": [], "dxe_class_total": 1}
    base["reconcile"] = {"clean": True, "missing": [], "added": [], "modified": [],
                         "declared": 1, "matched": 1, "missing_count": 0, "undeclared_observed": 0}
    base["binary_hardening"] = {"ran": True, "dxe_class_checked": 1, "dxe_nx_compat": 1,
                                "missing_nx_count": 0, "errored_count": 0, "unverifiable": []}
    base["byte_integrity"] = _byte_integrity_fact(verdict_path)
    with open(out_path, "w") as f:
        json.dump(base, f, indent=2)
    print("gate input written to %s (byte_integrity fact from the real assembler: %s)"
          % (out_path, json.dumps(base["byte_integrity"])))


def main(argv):
    if len(argv) >= 3 and argv[1] == "stage":
        return cmd_stage(argv[2])
    if len(argv) >= 4 and argv[1] == "gate-input":
        return cmd_gate_input(argv[2], argv[3])
    sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
