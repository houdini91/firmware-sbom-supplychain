#!/usr/bin/env python3
"""Unit tests for the byte-integrity producer's pure logic (R4).

Covers the two intricate pieces that had no coverage: the FFS section walker
(pe32_from_ffs, incl. the large-file header) and the un-rebase canonicalization
(canon_unrebase — round-trip identity + tamper detection). No FMMT/edk2/full-OVMF
needed: FFS blobs are synthesized; the canon tests use two small committed PE
fixtures (a declared base-0 PEI module and its rebased in-flash form).

Run: python3 tests/test_byte_integrity.py
"""
import hashlib
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "byte_integrity", os.path.join(HERE, "..", "producers", "reconcile", "byte-integrity.py"))
bi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bi)

ok = True
skipped = 0  # crux test groups that did NOT run (e.g. pefile missing) — surfaced loudly below


def check(name, cond):
    global ok
    ok = ok and cond
    print(("PASS  " if cond else "FAIL  ") + name)


def _section(stype, payload):
    size = 4 + len(payload)
    return bytes([size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF, stype]) + payload


def _ffs(section_bytes, large=False):
    hdr = bytearray(32 if large else 24)
    hdr[0x13] = 0x01 if large else 0x00   # Attributes; bit0 = FFS_ATTRIB_LARGE_FILE
    return bytes(hdr) + section_bytes


# --- pe32_from_ffs (the FFS section walker) ---
pe = b"MZ" + b"\x00" * 40
check("pe32_from_ffs: extracts a PE32 (0x10) section payload after the 24-byte header",
      bi.pe32_from_ffs(_ffs(_section(0x10, pe))) == pe)
check("pe32_from_ffs: honors the 32-byte large-file header (F7)",
      bi.pe32_from_ffs(_ffs(_section(0x10, pe), large=True)) == pe)
check("pe32_from_ffs: a TE-only (0x12) FFS has no PE32 -> None (skipped, not verified)",
      bi.pe32_from_ffs(_ffs(_section(0x12, b"\x00" * 20))) is None)
check("pe32_from_ffs: too-short blob -> None (no crash)", bi.pe32_from_ffs(b"\x00" * 8) is None)

# --- canon_unrebase (the un-rebase crux) ---
decl_p = os.path.join(HERE, "fixtures", "pe", "pcdpeim.declared.efi")
flash_p = os.path.join(HERE, "fixtures", "pe", "pcdpeim.inflash.pe32")
if bi.pefile is None:
    skipped += 1
    print("SKIP  canon_unrebase tests (pefile not installed — pip install -r requirements.txt)")
elif not (os.path.isfile(decl_p) and os.path.isfile(flash_p)):
    skipped += 1
    print("SKIP  canon_unrebase tests (fixtures missing)")
else:
    declared = open(decl_p, "rb").read()
    inflash = open(flash_p, "rb").read()
    canon = bytes(bi.canon_unrebase(inflash))
    check("canon_unrebase: un-rebasing the in-flash PEI module reproduces the declared bytes exactly",
          hashlib.sha256(canon).hexdigest() == hashlib.sha256(declared).hexdigest())
    # tamper: flip one code byte in the in-flash image -> canon must NOT match declared
    tampered = bytearray(inflash)
    tampered[0x1500] ^= 0x01
    canon_t = bytes(bi.canon_unrebase(bytes(tampered)))
    check("canon_unrebase: a 1-byte code tamper still diverges after un-rebase (no false pass)",
          hashlib.sha256(canon_t).hexdigest() != hashlib.sha256(declared).hexdigest())

    # no-reloc path (regression guard): a rebased PEIM with NO relocation table
    # (StatusCodeHandlerPei, ImageBase 0x8452c0, no .reloc) has no relocations to
    # reverse, so header-normalization alone must reproduce its declared base-0 hash.
    # This path previously failed closed (raised) and undercounted byte-integrity.
    nr_p = os.path.join(HERE, "fixtures", "pe", "statuscodehandlerpei.inflash.pe32")
    if os.path.isfile(nr_p):
        nr_inflash = open(nr_p, "rb").read()
        nr_declared = "9c525cfdf169d508f4fbb6ba8634fe68b3e084eb070e9f411d98a56baaaa5df8"
        check("canon_unrebase: a rebased no-reloc-table PEIM canonicalizes to its declared base-0 hash",
              hashlib.sha256(bytes(bi.canon_unrebase(nr_inflash))).hexdigest() == nr_declared)
        nr_t = bytearray(nr_inflash); nr_t[-64] ^= 0x01
        check("canon_unrebase: a code tamper in a no-reloc module still diverges (no false pass)",
              hashlib.sha256(bytes(bi.canon_unrebase(bytes(nr_t)))).hexdigest() != nr_declared)

print("----")
if skipped:
    print("⚠  %d CRUX TEST GROUP(S) SKIPPED — the byte-integrity un-rebase guard did NOT run here "
          "(install pefile: pip install -r requirements.txt). CI installs it and runs it." % skipped)
print(("ALL PASS%s" % (" (with %d SKIPPED — see warning)" % skipped if skipped else "")) if ok else "FAILURES")
sys.exit(0 if ok else 1)
