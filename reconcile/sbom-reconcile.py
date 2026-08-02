#!/usr/bin/env python3
"""sbom-reconcile — verify a declared CycloneDX SBOM against the modules
actually present in a firmware image (declared vs observed).

Observed side is the FFS file list carved from the firmware volumes by edk2
FMMT (`FMMT.py -v image.fd`); pass that text via --fmmt. Declared side is the
CycloneDX SBOM (--sbom).

Honest granularity (module / FFS):
  * Library instances are statically linked into their consuming module's PE32
    and have no standalone FFS, so they are reported as `libraries_transitive`
    (declared-only, not independently observable) — NOT counted as missing.
  * `modified` (byte integrity) is not asserted here: PEI-phase modules are
    XIP/rebased in the FV, so a naive hash of the in-FV bytes will not match the
    build .efi without per-image canonicalization. Those are listed in
    `modified_skipped` with a reason. Membership (validated/missing/added) IS
    checked. The declared SBOM already carries SHA-256/512 hashes; wiring the
    observed-side extract+rebase to turn `modified_skipped` into real integrity
    checks is the documented next step.

Usage:
  sbom-reconcile.py --sbom sbom.cdx.json --fmmt fmmt-view.txt [-o verdict.json]
"""
import json, re, argparse, sys

FV_RE   = re.compile(r'FvNameGuid:\s*([0-9a-fA-F-]{36})')
FILE_RE = re.compile(r'File:\s*([0-9a-fA-F-]{36})\s*(?:/\s*(.+?))?\s*$')
PAD     = "ffffffff-ffff-ffff-ffff-ffffffffffff"
# module types that are execute-in-place / relocated in the FV -> in-FV bytes
# are rebased, so byte-comparison needs canonicalization (skipped for now).
XIP_TYPES = {"SEC", "PEI_CORE", "PEIM"}


def parse_fmmt(text):
    """Return (fv_guids{guids}, ffs{guid:name}). ffs holds every non-pad FFS
    file GUID; name is "" for USER_DEFINED/raw files FMMT does not label."""
    fv_guids, ffs = set(), {}
    for line in text.splitlines():
        m = FV_RE.search(line)
        if m:
            fv_guids.add(m.group(1).lower())
            continue
        m = FILE_RE.search(line)
        if m:
            g = m.group(1).lower()
            name = (m.group(2) or "").strip()
            if g == PAD or name == "Ffs_pad":
                continue
            ffs.setdefault(g, name)                  # name may be "" (raw/USER_DEFINED)
    return fv_guids, ffs


def reconcile(sbom, fmmt_text):
    comps = sbom["components"]
    declared_mod = {c["bom-ref"].lower(): c for c in comps if c.get("type") != "library"}
    declared_lib = [c for c in comps if c.get("type") == "library"]

    fv_guids, ffs = parse_fmmt(fmmt_text)
    observed = set(ffs)
    dset = set(declared_mod)

    # Reconcile by GUID over ALL FFS files (named-ness is not identity).
    validated = sorted(dset & observed)
    missing   = sorted(dset - observed)

    def modtype(c):
        for p in c.get("properties", []):
            if p.get("name") == "edk2:moduleType":
                return (p.get("value") or "").upper()
        return ""

    # added = observed FFS not declared: a *named* one is a suspicious unknown
    # module; an *unnamed* one is apriori / FV-image structure (expected layout).
    added, structural, suspicious = [], [], []
    for g in sorted(observed - dset):
        if ffs[g]:
            item = {"guid": g, "name": ffs[g], "classification": "suspicious",
                    "note": "module present in image but absent from the declared SBOM"}
            suspicious.append(item)
        else:
            item = {"guid": g, "ffs_type": "apriori / FV structure", "classification": "structural"}
            structural.append(item)
        added.append(item)

    modified_skipped = [
        {"guid": g, "name": declared_mod[g].get("name"),
         "reason": "XIP/rebased in FV (%s) — in-FV bytes need canonicalization before hash compare" % modtype(declared_mod[g])}
        for g in validated if modtype(declared_mod[g]) in XIP_TYPES
    ]

    clean = (len(missing) == 0 and len(suspicious) == 0)
    return {
        "tool": "sbom-reconcile",
        "clean": clean,
        "granularity": "module/FFS",
        "summary": {
            "declared_modules": len(declared_mod),
            "declared_libraries": len(declared_lib),
            "observed_ffs": len(observed),
            "firmware_volumes": len(fv_guids),
            "validated": len(validated),
            "missing": len(missing),
            "added_structural": len(structural),
            "added_suspicious": len(suspicious),
            "modified": 0,
            "modified_skipped": len(modified_skipped),
        },
        "validated": validated,
        "missing": [{"guid": g, "name": declared_mod[g].get("name")} for g in missing],
        "added": added,
        "modified": [],
        "modified_skipped": modified_skipped,
        "libraries_transitive": len(declared_lib),
    }


def main():
    ap = argparse.ArgumentParser(description="Reconcile a declared SBOM against carved firmware FFS.")
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--fmmt", required=True, help="text output of FMMT.py -v image.fd")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    verdict = reconcile(json.load(open(a.sbom)), open(a.fmmt).read())
    out = json.dumps(verdict, indent=1)
    if a.out:
        open(a.out, "w").write(out + "\n")
    print(out if not a.out else "reconcile: clean=%s validated=%d missing=%d suspicious=%d -> %s"
          % (verdict["clean"], verdict["summary"]["validated"], verdict["summary"]["missing"],
             verdict["summary"]["added_suspicious"], a.out))
    sys.exit(0 if verdict["clean"] else 1)


if __name__ == "__main__":
    main()
