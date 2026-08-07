#!/usr/bin/env python3
"""ffs — shared UEFI firmware-image carving helpers.

Used by both `byte-integrity.py` (does the shipped PE32 match its declared hash?)
and `binary-hardening.py` (what exploit-mitigation posture do those PE32 images
declare?). Keeping the FFS/section walk and the FMMT extraction in one place means
the two producers carve the deployed image identically — a divergence here would
make the two lanes disagree about *which bytes* a module even is.
"""
import json
import os
import struct
import subprocess
import sys


# EFI_FV_FILETYPE (PI spec, EFI_FFS_FILE_HEADER.Type at offset 0x12) -> the
# module-type label byte-integrity branches on. This is read from the FFS the image
# was CARVED INTO — i.e. from the shipped image itself, not from any declaration in
# the SBOM/coSWID. The SEC/PEI_CORE/PEIM types are XIP (execute-in-place): stored
# rebased to their flash load address, so they must be un-rebased before hashing;
# everything else is compared directly. Deriving the type here (from the image) is
# what makes a declaration-carried type unnecessary — and prevents the class of bug
# where a typeless coSWID makes every module look like a DXE driver.
FFS_FILETYPE = {
    0x03: "SEC",
    0x04: "PEI_CORE",
    0x05: "DXE_CORE",
    0x06: "PEIM",
    0x07: "DXE_DRIVER",
    0x08: "COMBINED_PEIM_DRIVER",
    0x09: "APPLICATION",
    0x0A: "SMM",
    0x0D: "SMM_CORE",
}


def ffs_module_type(ffs):
    """The module type read from the FFS file header's EFI_FV_FILETYPE byte (offset
    0x12) of the carved image blob — NOT from any SBOM/coSWID declaration. Returns a
    module-type string ('PEIM', 'DXE_DRIVER', ...) or '' if the blob is too short or
    the type byte is unrecognized (treated conservatively as non-XIP -> direct)."""
    if len(ffs) <= 0x12:
        return ""
    return FFS_FILETYPE.get(ffs[0x12], "")


def pe32_from_ffs(ffs):
    """Return the PE32 (section type 0x10) payload bytes from an FFS blob, or None.
    FFS header is 24 bytes (EFI_FFS_FILE_HEADER), or 32 bytes when the
    FFS_ATTRIB_LARGE_FILE bit (0x01) is set (EFI_FFS_FILE_HEADER2 adds an 8-byte
    ExtendedSize). Sections are 4-byte-aligned with a 4-byte common header
    (3-byte size + 1-byte type), or an 8-byte header when size==0xFFFFFF."""
    if len(ffs) < 24:
        return None
    off = 32 if (ffs[0x13] & 0x01) else 24   # ffs[0x13] = Attributes; bit0 = LARGE_FILE
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


def fmmt_py_path(edk2):
    """Path to FMMT.py under an edk2 tree (or None if absent)."""
    p = os.path.join(edk2, "BaseTools", "Source", "Python", "FMMT", "FMMT.py")
    return p if os.path.isfile(p) else None


def iter_sbom_modules(sbom_path, include_libraries=False):
    """Yield (guid[lower,no-dashes], name, module_type) for every CycloneDX
    component that carries a 32-hex GUID bom-ref. module_type is the edk2:moduleType
    property or "" when absent.

    By default libraries (edk2:isLibrary=True / type=library) are skipped: they are
    linked into their parent module and never ship as a standalone FFS, so carving
    them from the image would just yield 188 phantom "skips". This keeps the examined
    set equal to byte-integrity's real-module population (the 122 modules with a PE32).
    Pass include_libraries=True to yield them anyway."""
    with open(sbom_path) as f:
        sbom = json.load(f)
    for c in sbom.get("components", []):
        ref = (c.get("bom-ref") or "").replace("-", "").lower()
        if len(ref) != 32:
            continue
        props = {p.get("name"): p.get("value") for p in (c.get("properties") or [])}
        is_lib = props.get("edk2:isLibrary") == "True" or c.get("type") == "library"
        if is_lib and not include_libraries:
            continue
        yield ref, c.get("name"), props.get("edk2:moduleType", "")
