#!/usr/bin/env python3
"""deploy-reconcile — CHIPSEC-fed DEPLOY-TIME byte reconcile against the signed SBOM (Track A).

byte-integrity (producers/reconcile/byte-integrity.py) answers the *admission-time*
question — "do the module bytes in the `.fd` file at rest match the SBOM's declared
hash?" — by carving the image with edk2 FMMT. This producer answers the *deploy-time*
question — "do the module bytes CHIPSEC extracts from the deployed image / live flash
match that same signed, build-born SBOM?" — using CHIPSEC as a **second, independent
carver**. Same SBOM baseline, extended from "at rest" to "on silicon", catching
post-admission / flash-time drift the at-rest gate cannot see (ADR 0001).

It is deliberately a THIN reuse of the proven primitive (A3):
  * REUSES `canon_unrebase`, `load_sbom_hashes`, `XIP_TYPES` from byte-integrity.py,
    UNCHANGED — the normalizer that made CHIPSEC-extracted bytes reproduce the SBOM's
    declared per-module SHA-256 on the OVMF reference (122/122).
  * The module TYPE is read from CHIPSEC's FV filetype directory — the **immediate**
    parent of the `.efi` (the nested-FV trap: an outer compressed DXEFV/PEIFV carries
    its own `.FV_FVIMAGE.dir`, which a whole-path match would wrongly grab and mislabel
    every nested PEI module as non-XIP). It is NEVER read from the SBOM/coSWID, so a
    typeless coSWID cannot force the wrong compare (byte-integrity's BUG-1 hardening).
  * Keyed by **FILE_GUID**, not name — names collide (two CpuMpPei, two CpuDxe with
    distinct GUIDs in OVMF), the GUID does not.

Reconcile is **bidirectional + GUID-bound**:
  * a SBOM GUID with no cleanly-extracted CHIPSEC PE  -> MISSING (tamper / dropped module);
  * a CHIPSEC GUID absent from the SBOM              -> UNEXPECTED (an implant);
  * bytes present but differ from the declared hash  -> MISMATCH (a same-GUID swap).
TE-format sections and anything CHIPSEC cannot cleanly extract to a normalizable PE are
SKIPPED — surfaced honestly, NEVER counted as verified (parity with byte-integrity's skip).

Input is EITHER a directory produced by `chipsec_util uefi decode <image>` (an FV-mirrored
tree of per-module `.efi` bytes), OR an `--image` that this script decodes itself when a
`chipsec_util` is reachable. evidenceGrade = `verified` — reconciled from real extracted bytes.

  deploy-reconcile.py --sbom sbom.cdx.json --decode-dir <img>.fd.dir [--efilist efilist.json] [-o verdict.json]
  deploy-reconcile.py --sbom sbom.cdx.json --image OVMF_CODE.fd [--chipsec-util <path>] [-o verdict.json]

The verdict JSON carries a stable-namespace, signed-able predicateType
`https://firmware-sbom-supplychain/deploy-reconcile/v1` (wrap.sh wraps it into a
D-anchored in-toto Statement). Exit 0 iff the reconcile is clean (>=1 module matched,
and no mismatch / missing / unexpected / error).
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile

# --- REUSE the proven normalizer from byte-integrity.py, imported (not reimplemented) ---
# (A3 proved these reproduce the SBOM's declared per-module hash from CHIPSEC-extracted bytes.)
_RECON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reconcile")
sys.path.insert(0, os.path.abspath(_RECON))  # so byte-integrity's own `from ffs import ...` resolves
_spec = importlib.util.spec_from_file_location("byte_integrity", os.path.join(_RECON, "byte-integrity.py"))
bi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bi)
canon_unrebase = bi.canon_unrebase
load_sbom_hashes = bi.load_sbom_hashes
XIP_TYPES = bi.XIP_TYPES

PREDICATE_TYPE = "https://firmware-sbom-supplychain/deploy-reconcile/v1"

# CHIPSEC's FV filetype-dir label -> byte-integrity's XIP_TYPES label, so the XIP/direct
# branch is IDENTICAL to byte-integrity's (which reads the EFI_FV_FILETYPE byte off the FFS).
FV_TO_FILETYPE = {
    "FV_SECURITY_CORE": "SEC", "FV_PEI_CORE": "PEI_CORE", "FV_PEIM": "PEIM",
    "FV_DXE_CORE": "DXE_CORE", "FV_DRIVER": "DXE_DRIVER",
    "FV_APPLICATION": "APPLICATION", "FV_FREEFORM": "FREEFORM",
}
# The module's TRUE filetype is the IMMEDIATE parent dir of the module file:
# '<NN>_<file_guid>.FV_TYPE.dir'. Matching the basename of the CONTAINING dir only avoids
# the nested-FV trap (grabbing an outer wrapper FV's '..FV_FVIMAGE.dir').
FV_DIR_RE = re.compile(r"^[0-9]+_([0-9a-fA-F-]{36})\.(FV_[A-Z_]+)\.dir$")


def _norm_guid(g):
    return (g or "").replace("-", "").lower()


def collect_modules(decode_dir, efilist_path=None):
    """Walk a `chipsec_util uefi decode` tree. -> list of module dicts
    {guid, name, filetype, fv_type, path, raw, asfound, is_pe}. GUID + FV type come from the
    IMMEDIATE parent '<NN>_<guid>.FV_TYPE.dir' segment; efilist.json (keyed by CHIPSEC's
    as-found sha256) is an OPTIONAL cross-check for name/guid. A module file that is not a PE
    (TE 'VZ' magic, or anything without an 'MZ' header) is flagged is_pe=False -> SKIP."""
    efilist = {}
    if efilist_path and os.path.isfile(efilist_path):
        try:
            efilist = json.load(open(efilist_path))
        except (ValueError, OSError):
            efilist = {}
    mods = []
    for root, _dirs, files in os.walk(decode_dir):
        m = FV_DIR_RE.match(os.path.basename(root))
        if not m:
            continue  # only files sitting DIRECTLY in a '<NN>_<guid>.FV_TYPE.dir' are modules
        dir_guid = _norm_guid(m.group(1))
        fv_type = m.group(2)
        for fn in files:
            if not (fn.endswith(".efi") or fn.endswith(".te")):
                continue
            path = os.path.join(root, fn)
            with open(path, "rb") as f:
                raw = f.read()
            asfound = hashlib.sha256(raw).hexdigest()
            meta = efilist.get(asfound, {})
            guid = _norm_guid(meta.get("guid")) or dir_guid
            mods.append({
                "guid": guid, "name": meta.get("name") or fn.rsplit(".", 1)[0],
                "filetype": FV_TO_FILETYPE.get(fv_type, ""), "fv_type": fv_type,
                "path": path, "raw": raw, "asfound": asfound,
                # a normalizable PE has the 'MZ' DOS header; TE images ('VZ') and non-PE
                # blobs do not — those are SKIPPED, never hashed as if they were the PE.
                "is_pe": raw[:2] == b"MZ",
            })
    return mods


def normalize(mod):
    """byte-integrity's EXACT decision: XIP -> canon_unrebase(raw), else hash raw directly.
    Returns (normalized_sha256, method). Raises on a malformed/unsupported reloc (fail closed)."""
    raw = mod["raw"]
    if mod["filetype"] in XIP_TYPES:
        canon = canon_unrebase(raw)  # the reused repo normalizer, UNCHANGED
        if canon is None:
            raise RuntimeError("pefile unavailable — cannot un-rebase XIP module %s" % mod["filetype"])
        return hashlib.sha256(canon).hexdigest(), "un-rebase"
    return hashlib.sha256(raw).hexdigest(), "direct"


def reconcile(declared, mods, image_digest=""):
    """Bidirectional, GUID-bound reconcile of CHIPSEC-extracted modules vs the SBOM's declared
    per-module hashes. declared: {guid: (name, sha256)}; mods: collect_modules() output."""
    matched, mismatched, skipped, errored, unexpected = [], [], [], [], []
    seen = set()  # SBOM GUIDs observed with a comparable PE (matched or mismatched)

    for md in sorted(mods, key=lambda m: (m["name"] or "", m["guid"])):
        guid = md["guid"]
        dname, dhash = declared.get(guid, (None, None))
        if dhash is None:
            # CHIPSEC extracted a module the SBOM does not declare -> UNEXPECTED (implant).
            unexpected.append({"name": md["name"], "guid": guid, "fv_type": md["fv_type"]})
            continue
        if not md["is_pe"]:
            # a TE / non-PE section CHIPSEC could not extract as a normalizable PE -> SKIP
            # (surfaced, NEVER counted as verified).
            skipped.append({"name": dname or md["name"], "guid": guid,
                            "reason": "no normalizable PE32 (TE / non-PE section)"})
            continue
        try:
            observed, method = normalize(md)
        except Exception as e:  # noqa: BLE001 — fail closed, record, keep going
            errored.append({"name": dname or md["name"], "guid": guid, "error": str(e)[:200]})
            continue
        seen.add(guid)
        (matched if observed == dhash else mismatched).append(
            {"name": dname or md["name"], "guid": guid, "declared": dhash,
             "observed": observed, "method": method})

    # SBOM-declared GUIDs never observed with a comparable PE in the extract -> MISSING
    # (a declared module dropped / tampered away). A GUID that WAS seen but only as a
    # skip/error is reported under that head, not double-counted as missing.
    accounted = seen | {s["guid"] for s in skipped} | {e["guid"] for e in errored}
    missing = [{"name": name, "guid": guid}
               for guid, (name, _h) in sorted(declared.items(), key=lambda kv: kv[1][0] or "")
               if guid not in accounted]

    reconciled = len(matched) + len(mismatched)  # the comparable set
    clean = (len(matched) > 0 and not mismatched and not missing
             and not unexpected and not errored)
    return {
        "tool": "deploy-reconcile",
        "predicateType": PREDICATE_TYPE,
        "source": "chipsec-uefi-decode",
        "granularity": "module/PE32-bytes (CHIPSEC-extracted, GUID-bound, bidirectional)",
        "image_digest": image_digest,
        "declared": len(declared),
        "reconciled": reconciled,
        "matched": len(matched),
        "verified_direct": sum(1 for v in matched if v["method"] == "direct"),
        "verified_unrebase": sum(1 for v in matched if v["method"] == "un-rebase"),
        # FULL per-module manifest — enumerated, not just counted, so an auditor sees exactly what
        # reconciled / did not.
        "matched_modules": [{"name": v["name"], "guid": v["guid"], "method": v["method"]} for v in matched],
        "mismatched": mismatched,
        "missing": missing,
        "unexpected": unexpected,
        "skipped": skipped,
        "errored": errored,
        "evidenceGrade": "verified",  # reconciled from real CHIPSEC-extracted bytes
        "clean": clean,
    }


def run_decode(image, chipsec_util, workdir):
    """Run `chipsec_util uefi decode <image>` in workdir; return the decode-dir path (or exit)."""
    tool = chipsec_util or "chipsec_util"
    img_copy = os.path.join(workdir, os.path.basename(image))
    with open(image, "rb") as s, open(img_copy, "wb") as d:
        d.write(s.read())
    try:
        subprocess.run([tool, "uefi", "decode", img_copy], cwd=workdir,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        sys.exit("deploy-reconcile: `chipsec_util uefi decode` failed (%s). Install CHIPSEC and pass "
                 "--chipsec-util <path>, or pre-run decode and pass --decode-dir." % (str(e)[:120]))
    decode_dir = img_copy + ".dir"
    if not os.path.isdir(decode_dir):
        sys.exit("deploy-reconcile: expected decode tree not found at %s" % decode_dir)
    return decode_dir


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--decode-dir", dest="decode_dir",
                    help="a `chipsec_util uefi decode <image>` output tree (per-module .efi bytes)")
    ap.add_argument("--image", help="a firmware image to decode with CHIPSEC ourselves (needs chipsec_util)")
    ap.add_argument("--chipsec-util", dest="chipsec_util", help="path to chipsec_util (default: on PATH)")
    ap.add_argument("--efilist", help="optional CHIPSEC efilist.json (name/guid cross-check)")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    if not os.path.isfile(a.sbom):
        sys.exit("deploy-reconcile: --sbom not found: %s" % a.sbom)
    if not a.decode_dir and not a.image:
        sys.exit("deploy-reconcile: supply --decode-dir (a chipsec decode tree) or --image (we decode it)")

    image_digest = ""
    if a.image and os.path.isfile(a.image):
        with open(a.image, "rb") as f:
            image_digest = "sha256:" + hashlib.sha256(f.read()).hexdigest()

    declared = load_sbom_hashes(a.sbom)  # {guid: (name, declared_sha256)} — REUSED loader

    with tempfile.TemporaryDirectory() as td:
        decode_dir = a.decode_dir
        if not decode_dir:
            decode_dir = run_decode(a.image, a.chipsec_util, td)
        if not os.path.isdir(decode_dir):
            sys.exit("deploy-reconcile: --decode-dir not a directory: %s" % decode_dir)
        mods = collect_modules(decode_dir, a.efilist)
        verdict = reconcile(declared, mods, image_digest)

    out = json.dumps(verdict, indent=2)
    if a.out:
        with open(a.out, "w") as f:
            f.write(out + "\n")
        print("deploy-reconcile: matched=%d/%d mismatched=%d missing=%d unexpected=%d skipped=%d -> %s"
              % (verdict["matched"], verdict["reconciled"], len(verdict["mismatched"]),
                 len(verdict["missing"]), len(verdict["unexpected"]), len(verdict["skipped"]), a.out))
    else:
        print(out)
    for m in verdict["mismatched"]:
        sys.stderr.write("  ⛔ MISMATCH %s: declared %s != observed %s (on-device byte swap)\n"
                         % (m["name"], m["declared"][:16], m["observed"][:16]))
    for m in verdict["missing"]:
        sys.stderr.write("  ⛔ MISSING %s (%s): declared in SBOM, not extractable by CHIPSEC\n"
                         % (m["name"], m["guid"][:12]))
    for u in verdict["unexpected"]:
        sys.stderr.write("  ⛔ UNEXPECTED %s (%s): extracted by CHIPSEC, not in the SBOM\n"
                         % (u["name"], u["guid"][:12]))
    sys.exit(0 if verdict["clean"] else 1)


if __name__ == "__main__":
    main()
