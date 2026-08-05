#!/usr/bin/env python3
"""binary-hardening — report the exploit-mitigation posture DECLARED by each
shipped module's PE32 header (R8, supply-chain hardening evidence).

For every module in the SBOM we carve its shipped PE32 out of the deployed image
(the same extraction byte-integrity uses) and read the mitigation bits the linker
recorded:

  * NX_COMPAT       (DllCharacteristics 0x0100) — image tolerates W^X / DEP: the DXE
                     memory-protection policy may mark its data pages non-executable.
  * DYNAMIC_BASE    (0x0040) — relocatable (ASLR-capable *if* the loader randomizes).
  * HIGH_ENTROPY_VA (0x0020) — 64-bit high-entropy ASLR opt-in.
  * GUARD_CF        (0x4000) — Control-Flow Guard metadata present.
  * relocs present  (FILE_HEADER 0x0001 IMAGE_FILE_RELOCS_STRIPPED clear) — the module
                     kept its relocation table (required to be relocated at all).

HONESTY — what this is and is NOT (read before mapping it to a control):
  This reports the posture the module *declares in its header*. On UEFI the flag is a
  necessary precondition, not proof of runtime enforcement: NX is actually applied by
  the DXE image-protection policy (PcdImageProtectionPolicy / PcdDxeNxMemoryProtection
  Policy), and edk2 does NOT randomize load addresses, so DYNAMIC_BASE means
  "relocatable", not "randomized". So this lane is EVIDENCE of a build-hardening
  posture / a regression tripwire, not a claim that the platform enforces the
  mitigation at runtime. The verdict below asserts only the defensible part.

  binary-hardening.py --sbom sbom.cdx.json --image OVMF.fd --edk2 <tree> \
                      [--modules A,B | --guids g1,g2] [-o hardening.json]

Needs pefile. Exit 0 iff the verdict is clean (see `_clean` below).
"""
import argparse
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ffs import pe32_from_ffs, fmmt_extract, fmmt_py_path, iter_sbom_modules  # noqa: E402

try:
    import pefile
except ImportError:
    pefile = None

# DXE-class executables are the modules the DXE image-protection policy governs, so
# NX-compatibility is a meaningful expectation for them. PEI/SEC run before that
# policy exists (XIP, identity-mapped) — we report their flags but do not require NX.
DXE_CLASS = {"DXE_DRIVER", "DXE_RUNTIME_DRIVER", "DXE_SAL_DRIVER", "UEFI_DRIVER",
             "UEFI_APPLICATION", "DXE_CORE", "SMM_CORE", "DXE_SMM_DRIVER", "MM_STANDALONE"}

DLLCHAR = {"nx_compat": 0x0100, "dynamic_base": 0x0040, "high_entropy_va": 0x0020,
           "guard_cf": 0x4000, "force_integrity": 0x0080}
MACHINE = {0x8664: "x64", 0x014c: "ia32", 0xAA64: "aarch64", 0x01c2: "arm", 0x5064: "riscv64"}


def posture(pe_bytes):
    """Parse a PE32/PE32+ image and return its declared mitigation posture."""
    pe = pefile.PE(data=pe_bytes, fast_load=True)
    dll = pe.OPTIONAL_HEADER.DllCharacteristics
    out = {k: bool(dll & bit) for k, bit in DLLCHAR.items()}
    out["relocs_present"] = not bool(pe.FILE_HEADER.Characteristics & 0x0001)  # !RELOCS_STRIPPED
    out["machine"] = MACHINE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    out["pe_plus"] = pe.OPTIONAL_HEADER.Magic == 0x20b
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--image", required=True, help="the firmware image (.fd)")
    ap.add_argument("--edk2", required=True, help="edk2 tree (for FMMT extraction)")
    ap.add_argument("--modules", help="comma-separated module names (default: all with a GUID)")
    ap.add_argument("--guids", help="comma-separated FILE_GUIDs")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if pefile is None:
        sys.exit("binary-hardening: pefile is required (pip install pefile)")
    for label, p in (("sbom", a.sbom), ("image", a.image)):
        if not os.path.isfile(p):
            sys.exit("binary-hardening: --%s not found: %s" % (label, p))
    fmmt_py = fmmt_py_path(a.edk2)
    if not fmmt_py:
        sys.exit("binary-hardening: FMMT.py not found under --edk2 (%s)" % a.edk2)

    modules = {g: (n, t) for g, n, t in iter_sbom_modules(a.sbom)}
    if a.guids:
        want = {g.replace("-", "").lower() for g in a.guids.split(",")}
        modules = {g: v for g, v in modules.items() if g in want}
    elif a.modules:
        want = {m.strip() for m in a.modules.split(",")}
        modules = {g: v for g, v in modules.items() if v[0] in want}

    checked, skipped, errored = [], [], []
    with tempfile.TemporaryDirectory() as td:
        for guid, (name, mtype) in sorted(modules.items(), key=lambda kv: kv[1][0] or ""):
            try:
                dst = os.path.join(td, guid + ".ffs")
                if not fmmt_extract(fmmt_py, a.edk2, a.image, guid, dst):
                    skipped.append({"name": name, "guid": guid, "type": mtype, "reason": "not extractable from image"})
                    continue
                with open(dst, "rb") as f:
                    pe = pe32_from_ffs(f.read())
                if pe is None:
                    skipped.append({"name": name, "guid": guid, "type": mtype, "reason": "no PE32 section (TE / compressed)"})
                    continue
                rec = {"name": name, "guid": guid, "type": mtype, **posture(pe)}
                checked.append(rec)
            except Exception as e:  # noqa: BLE001 — fail closed, record, keep going
                errored.append({"name": name, "guid": guid, "type": mtype, "error": str(e)[:200]})

    dxe = [m for m in checked if m["type"] in DXE_CLASS]
    dxe_nx = [m for m in dxe if m["nx_compat"]]
    by_flag = {k: sum(1 for m in checked if m.get(k)) for k in list(DLLCHAR) + ["relocs_present"]}
    # Verdict — assert only the defensible, non-vacuous part: every DXE-class module
    # the image-protection policy governs declares NX_COMPAT (so W^X can be enforced),
    # and there IS at least one such module (never vacuously true on an empty set).
    dxe_nx_covered = len(dxe) > 0 and len(dxe_nx) == len(dxe)
    verdict = {
        "tool": "binary-hardening",
        "granularity": "module/PE32-DllCharacteristics",
        "checked": len(checked),
        # coverage denominator (transparency): declared DXE-class modules in scope.
        # The gate binds against the assembler's SBOM-derived count, not this, so a
        # tampered verdict cannot fake its own coverage.
        "dxe_class_declared": sum(1 for _n, _t in modules.values() if _t in DXE_CLASS),
        "dxe_class_checked": len(dxe),
        "dxe_nx_compat": len(dxe_nx),
        "by_flag": by_flag,
        "dxe_missing_nx": [{"name": m["name"], "guid": m["guid"], "type": m["type"]}
                           for m in dxe if not m["nx_compat"]],
        "modules": checked,
        "skipped": skipped,
        "errored": errored,
        # clean = every DXE-class module is NX-compatible (W^X-ready) and the set is
        # non-empty. A missing-NX DXE driver is a hardening regression -> not clean.
        "clean": dxe_nx_covered and len(errored) == 0,
    }
    out = json.dumps(verdict, indent=2)
    if a.out:
        with open(a.out, "w") as f:
            f.write(out + "\n")
        print("binary-hardening: checked=%d dxe_class=%d dxe_nx_compat=%d skipped=%d errored=%d -> %s"
              % (len(checked), len(dxe), len(dxe_nx), len(skipped), len(errored), a.out))
    else:
        print(out)
    for m in verdict["dxe_missing_nx"]:
        sys.stderr.write("  ⚠ DXE module without NX_COMPAT: %s (%s)\n" % (m["name"], m["type"]))
    sys.exit(0 if verdict["clean"] else 1)


if __name__ == "__main__":
    main()
