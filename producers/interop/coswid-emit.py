#!/usr/bin/env python3
"""coswid-emit (WS-A) — emit a coSWID from a CycloneDX SBOM using python-uswid's
NATIVE CycloneDX loader.

This is a thin wrapper around `uSwidFormatCycloneDX().load()` (hughsie/python-uswid).
That loader already does the load-bearing mapping for us: each component's
`bom-ref` becomes the coSWID `tag-id`, and each CycloneDX hash becomes a coSWID
`payload` hash. So the module GUID identity and the NORMALIZED SHIPPED-BYTE SHA-256
(which the CycloneDX component carries) survive into the coSWID for free — no
hand-rolled component walk, no hand-rolled CBOR, and nothing a downstream
`uswid --load sbom.cdx.json --save x.uswid` wouldn't also produce.

What this wrapper adds over the bare loader, and ONLY this:
  * Filters to the modules we can reconcile: a 32-hex FILE_GUID tag-id AND a
    declared SHA-256 (libraries / PURL submodules with no GUID+hash are skipped).
  * Normalizes CycloneDX component `type` values uswid 0.6.0 can't parse
    (e.g. `device-driver`) so a real edk2/OVMF SBOM loads instead of crashing.
  * Sets a single `tag-creator` entity (we are the party that produced the tag).
    We do NOT assert `software-creator` — we did not author the upstream edk2/
    TianoCore/Intel modules, so claiming authorship of them would be false.
  * OPTIONALLY records a REAL source-file hash in `colloquial-version` when one is
    supplied via --source-hashes (that is where the ecosystem carries a source/tree
    hash). No source hash is invented: if none is supplied, none is emitted.

The reconcilable hash is the shipped-byte SHA-256 the CycloneDX component already
carries; it rides through as the native coSWID payload hash and is what
coswid-ingest recovers. (A separately-carried device-measured "evidence" hash is a
verification-profile PROPOSAL, not something we ship as a private format — see
CONFORMANCE.md; python-uswid's `uSwidEvidence` has no hash field to hold it.)

All CBOR/coSWID serialization is done by python-uswid — no hand-rolled CBOR.
Install: `python3 -m venv v && v/bin/pip install uswid`, then run under that venv.

Usage:
  coswid-emit.py --sbom sbom.cdx.json [--guids g1,g2] [--source-hashes src.json]
                 --out module.coswid            # single tag  (.coswid, for PE embed)
  coswid-emit.py --sbom sbom.cdx.json --out all.uswid           # container (.uswid)
"""
import argparse
import json
import os
import sys

try:
    from uswid import (uSwidEntity, uSwidEntityRole, uSwidHashAlg, uSwidContainer)
    from uswid.format_cyclonedx import uSwidFormatCycloneDX
    from uswid.format_coswid import uSwidFormatCoswid
    from uswid.format_uswid import uSwidFormatUswid
except ImportError:
    sys.exit("coswid-emit: python-uswid not importable — run under a venv with `pip install uswid`")

# uSwidComponentType only knows these; a CycloneDX `type` outside the set makes
# uswid 0.6.0's loader raise KeyError (e.g. `device-driver` on a real OVMF SBOM).
_USWID_KNOWN_TYPES = {"firmware", "application", "library"}


def sanitize_types(sbom):
    """Remap CycloneDX component `type` values python-uswid 0.6.0 can't parse to
    `firmware`, so its native loader ingests a real edk2/OVMF SBOM instead of
    crashing (KeyError: 'DEVICE-DRIVER'). Only the coarse CDX type is touched — the
    GUID, hashes, name and version (all we use) are untouched."""
    def fix(c):
        if c.get("type") not in _USWID_KNOWN_TYPES:
            c["type"] = "firmware"
    for c in sbom.get("components", []):
        fix(c)
    meta = sbom.get("metadata", {}).get("component")
    if meta:
        fix(meta)
    return sbom


def sha256_payload(component):
    """The component's declared SHA-256 (the shipped-byte hash), from the native
    coSWID payload the loader built from the CycloneDX hash. Enum compare, not a
    fragile str() match."""
    for p in component.payloads:
        for h in p.hashes:
            if h.alg_id == uSwidHashAlg.SHA256 and h.value:
                return h.value.lower()
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True, help="CycloneDX SBOM; component SHA-256 = normalized shipped-byte hash")
    ap.add_argument("--source-hashes", help="JSON {guid: sha256} of REAL source-file hashes (optional; -> colloquial-version)")
    ap.add_argument("--guids", help="comma-separated FILE_GUIDs to emit (default: all with a GUID+SHA-256)")
    ap.add_argument("--out", required=True, help="output .coswid (single tag) or .uswid (container)")
    a = ap.parse_args()

    if not os.path.isfile(a.sbom):
        sys.exit("coswid-emit: --sbom not found: %s" % a.sbom)
    with open(a.sbom) as f:
        sbom = json.load(f)
    src_map = {}
    if a.source_hashes:
        with open(a.source_hashes) as f:
            src_map = {k.replace("-", "").lower(): v.lower() for k, v in json.load(f).items()}
    want = None
    if a.guids:
        want = {g.replace("-", "").lower() for g in a.guids.split(",")}

    # NATIVE loader: bom-ref -> tag_id, each CycloneDX hash -> a coSWID payload hash.
    container = uSwidFormatCycloneDX().load(json.dumps(sanitize_types(sbom)).encode())

    comps, with_src = [], []
    for c in container:
        ref = (c.tag_id or "").replace("-", "").lower()
        if len(ref) != 32:            # keep only real FILE_GUID modules (drops metadata/PURL)
            continue
        if want is not None and ref not in want:
            continue
        if not sha256_payload(c):     # must carry the reconcilable shipped-byte hash
            continue
        c.software_version = c.software_version or "0"
        # tag-creator ONLY — we produced the tag, we did NOT author the upstream
        # module. Deliberately assert NO software-creator (claiming Oats authored
        # TianoCore/Intel modules would be false); uswid --validate will honestly
        # note "No SoftwareCreator", which is the truthful state.
        c._entities.clear()   # drop any loader-added entity so no false claim rides along
        c.add_entity(uSwidEntity(name="Oats Solutions", regid="oatssolutions.tech",
                                 roles=[uSwidEntityRole.TAG_CREATOR]))
        # a REAL source-file hash, if supplied, goes where the ecosystem carries it
        # (colloquial-version). Never fabricated: omitted entirely when not supplied.
        if ref in src_map:
            c.colloquial_version = src_map[ref]
            with_src.append(c.software_name)
        comps.append(c)

    if not comps:
        sys.exit("coswid-emit: no components with a GUID + SHA-256 matched")

    out = uSwidContainer(comps)
    ext = a.out.rsplit(".", 1)[-1].lower()
    if ext == "uswid":
        blob = uSwidFormatUswid().save(out)
    elif ext in ("coswid", "cbor"):
        if len(comps) != 1:
            sys.exit("coswid-emit: .coswid is a single tag — %d components matched; select one with --guids "
                     "or use a .uswid container" % len(comps))
        blob = uSwidFormatCoswid().save(out)
    else:
        sys.exit("coswid-emit: --out must end .coswid (single tag) or .uswid (container)")
    with open(a.out, "wb") as f:
        f.write(blob)

    print("coswid-emit: %d module(s) -> %s (%d bytes)" % (len(comps), a.out, len(blob)))
    for c in comps:
        print("  %-22s shipped-byte=%s…  source=%s"
              % (c.software_name, sha256_payload(c)[:16],
                 (c.colloquial_version[:16] + "…") if c.colloquial_version else "<none supplied>"))
    if len(comps) != len(with_src):
        sys.stderr.write("  note: no source-file hash emitted for %d module(s) "
                         "(none fabricated; pass --source-hashes for a real one)\n"
                         % (len(comps) - len(with_src)))


if __name__ == "__main__":
    main()
