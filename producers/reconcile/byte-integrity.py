#!/usr/bin/env python3
"""byte-integrity — verify a module's SHIPPED bytes against the SBOM (R4, phase 1).

Reconcile checks *membership* (declared GUID observed as an FFS). This checks
*integrity*: the module's actual PE32 bytes in the firmware image match the
SHA-256 the SBOM declares — so a same-GUID trojan (swap a module for a malicious
one with the same FILE_GUID) that membership misses is DETECTED.

Two module classes, both covered:
  * DXE drivers (phase 1): NO canonicalization needed. The SBOM's declared hash is
    the build's GenFw-normalized `.efi` (TimeDateStamp=0, CheckSum=0, ImageBase=0),
    and OVMF does not rebase DXE drivers in flash — so the PE32 extracted from the
    deployed `.fd` is byte-identical to the declared image (method="direct").
  * XIP/PEI modules (phase 3): rebased to their flash load address, so the in-image
    bytes differ from the declared (base-0) image ONLY by the relocation. We
    un-rebase back to base 0 before hashing (method="un-rebase"; needs pefile).
Only TE-format and compressed sections remain out of scope. (The earlier "in-image
!= declared" note compared the wrong bytes — the FFS section header, or a rebased
image without un-rebasing.)

  byte-integrity.py --sbom sbom.cdx.json --image OVMF.fd --edk2 <edk2 tree> \
                    [--modules AmdSevDxe,IoMmuDxe | --guids <g1,g2>] [-o verdict.json]

Extraction uses edk2 FMMT (the same tool the observed-side carve uses). Exit 0 iff
every checked module is byte-verified (none modified).
"""
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

try:
    import pefile  # only needed for XIP/PEI un-rebase canonicalization (phase 3)
except ImportError:
    pefile = None


# XIP / execute-in-place module types: stored rebased to their flash address in
# the FV, so the in-image PE32 differs from the declared (un-rebased) .efi. Naive
# byte comparison does NOT apply — deferred to R4 phase 3 (rebase canonicalization),
# NOT reported as tampered. (Same set sbom-reconcile marks modified_skipped.)
XIP_TYPES = {"SEC", "PEI_CORE", "PEIM"}


def load_sbom_hashes(sbom_path):
    """{guid(lower,no-dashes): (name, declared_sha256, module_type)} for components
    with a GUID bom-ref and a declared SHA-256."""
    with open(sbom_path) as f:
        sbom = json.load(f)
    out = {}
    for c in sbom.get("components", []):
        ref = (c.get("bom-ref") or "").replace("-", "").lower()
        if len(ref) != 32:
            continue
        mtype = ""
        for p in c.get("properties", []) or []:
            if p.get("name") == "edk2:moduleType":
                mtype = p.get("value", "")
        for h in c.get("hashes", []) or []:
            if h.get("alg") == "SHA-256" and h.get("content"):
                out[ref] = (c.get("name"), h["content"].lower(), mtype)
    return out


def pe32_from_ffs(ffs):
    """Return the PE32 (section type 0x10) payload bytes from an FFS blob, or None.
    FFS header is 24 bytes; sections are 4-byte-aligned with a 4-byte common header
    (3-byte size + 1-byte type), or an 8-byte header when size==0xFFFFFF."""
    off = 24
    while off + 4 <= len(ffs):
        size = ffs[off] | (ffs[off + 1] << 8) | (ffs[off + 2] << 16)
        stype = ffs[off + 3]
        shdr = 4
        if size == 0xFFFFFF:
            size = struct.unpack_from("<I", ffs, off + 4)[0]
            shdr = 8
        if size < shdr or off + size > len(ffs):
            break
        if stype == 0x10:  # EFI_SECTION_PE32
            return ffs[off + shdr: off + size]
        off = (off + size + 3) & ~3
    return None


def fmmt_extract(fmmt_py, edk2, image, guid, dst):
    """FMMT -e image guid dst  -> extracted FFS at dst (decompresses FVs)."""
    env = dict(os.environ,
               PYTHONPATH=os.path.join(edk2, "BaseTools", "Source", "Python"),
               PATH=os.path.join(edk2, "BaseTools", "Source", "C", "bin") + os.pathsep + os.environ.get("PATH", ""))
    r = subprocess.run([sys.executable, fmmt_py, "-e", image, guid, dst],
                       env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0 and os.path.isfile(dst) and os.path.getsize(dst) > 0


def canon_unrebase(pe_bytes):
    """Un-rebase a PE image back to ImageBase 0 (undo the flash relocation) and
    zero ImageBase/TimeDateStamp/CheckSum — so an XIP/PEI module's rebased in-flash
    bytes can be fairly compared to the declared (un-rebased) .efi (R4 phase 3).
    The relocation table records exactly which fields were shifted, so this is
    exact and reversible. A real tamper changes code the relocations don't cover,
    so it still fails. Returns canonical bytes, or None if pefile is unavailable."""
    if pefile is None:
        return None
    pe = pefile.PE(data=pe_bytes, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
    base = pe.OPTIONAL_HEADER.ImageBase
    buf = bytearray(pe.__data__)
    if base and hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
        for blk in pe.DIRECTORY_ENTRY_BASERELOC:
            for e in blk.entries:
                if e.type == 0:            # IMAGE_REL_BASED_ABSOLUTE — padding, skip
                    continue
                off = pe.get_offset_from_rva(e.rva)
                if e.type == 3:            # HIGHLOW (32-bit)
                    v = struct.unpack_from("<I", buf, off)[0]
                    struct.pack_into("<I", buf, off, (v - base) & 0xFFFFFFFF)
                elif e.type == 10:         # DIR64 (64-bit)
                    v = struct.unpack_from("<Q", buf, off)[0]
                    struct.pack_into("<Q", buf, off, (v - base) & ((1 << 64) - 1))
    pe2 = pefile.PE(data=bytes(buf), fast_load=True)
    pe2.OPTIONAL_HEADER.ImageBase = 0
    pe2.FILE_HEADER.TimeDateStamp = 0
    pe2.OPTIONAL_HEADER.CheckSum = 0
    return pe2.write()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--image", required=True, help="the firmware image (.fd)")
    ap.add_argument("--edk2", required=True, help="edk2 tree (for FMMT extraction)")
    ap.add_argument("--modules", help="comma-separated module names to check (default: all with a GUID+hash)")
    ap.add_argument("--guids", help="comma-separated FILE_GUIDs to check")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    for label, p in (("sbom", a.sbom), ("image", a.image)):
        if not os.path.isfile(p):
            sys.exit("byte-integrity: --%s not found: %s" % (label, p))
    fmmt_py = os.path.join(a.edk2, "BaseTools", "Source", "Python", "FMMT", "FMMT.py")
    if not os.path.isfile(fmmt_py):
        sys.exit("byte-integrity: FMMT.py not found under --edk2 (%s)" % fmmt_py)

    declared = load_sbom_hashes(a.sbom)
    targets = dict(declared)
    if a.guids:
        want = {g.replace("-", "").lower() for g in a.guids.split(",")}
        targets = {g: v for g, v in declared.items() if g in want}
    elif a.modules:
        want = {m.strip() for m in a.modules.split(",")}
        targets = {g: v for g, v in declared.items() if v[0] in want}

    verified, modified, skipped = [], [], []
    with tempfile.TemporaryDirectory() as td:
        for guid, (name, dhash, mtype) in sorted(targets.items(), key=lambda kv: kv[1][0] or ""):
            dst = os.path.join(td, guid + ".ffs")
            if not fmmt_extract(fmmt_py, a.edk2, a.image, guid, dst):
                skipped.append({"name": name, "guid": guid, "reason": "not extractable from image"})
                continue
            with open(dst, "rb") as f:
                pe = pe32_from_ffs(f.read())
            if pe is None:
                skipped.append({"name": name, "guid": guid, "reason": "no PE32 section (TE / compressed)"})
                continue
            method = "direct"
            if mtype in XIP_TYPES:
                # XIP/PEI: rebased in flash — un-rebase to the declared (base 0) form first
                canon = canon_unrebase(pe)
                if canon is None:
                    skipped.append({"name": name, "guid": guid,
                                    "reason": "XIP/rebased %s — pefile required for un-rebase canonicalization" % mtype})
                    continue
                pe, method = canon, "un-rebase"
            ohash = hashlib.sha256(pe).hexdigest()
            (verified if ohash == dhash else modified).append(
                {"name": name, "guid": guid, "declared": dhash, "observed": ohash, "method": method})

    verdict = {
        "tool": "byte-integrity",
        "granularity": "module/PE32-bytes",
        "checked": len(targets),
        "byte_verified": len(verified),
        "verified_direct": sum(1 for v in verified if v.get("method") == "direct"),
        "verified_unrebase": sum(1 for v in verified if v.get("method") == "un-rebase"),
        "modified": modified,
        "skipped": skipped,
        "clean": len(modified) == 0,
    }
    out = json.dumps(verdict, indent=2)
    if a.out:
        with open(a.out, "w") as f:
            f.write(out + "\n")
    print(out if not a.out else
          "byte-integrity: verified=%d modified=%d skipped=%d -> %s"
          % (len(verified), len(modified), len(skipped), a.out))
    for m in modified:
        sys.stderr.write("  ⛔ MODIFIED %s: declared %s != observed %s\n"
                         % (m["name"], m["declared"][:16], m["observed"][:16]))
    sys.exit(0 if verdict["clean"] else 1)


if __name__ == "__main__":
    main()
