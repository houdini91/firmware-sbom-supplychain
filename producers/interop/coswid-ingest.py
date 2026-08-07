#!/usr/bin/env python3
"""coswid-ingest (WS-B) — ingest an embedded coSWID and recover the per-module
hashes the reconcile lane needs.

Reads a coSWID/uSWID container OR a PE/COFF binary with an embedded `.sbom`
section (the OSF on-firmware format), and for every module recovers:
  * the OSF SOURCE-FILE hash  (payload fs-name `<module>.src`)
  * our NORMALIZED SHIPPED-BYTE hash (payload fs-name `<module>.efi`)  <- the one
    byte-integrity.py reconciles the dumped bytes against.

It writes a CycloneDX SBOM whose per-component SHA-256 is the SHIPPED-BYTE
(evidence) hash — exactly the shape `sbom-reconcile.py` (membership) and
`byte-integrity.py` (byte compare) already consume. This closes the loop:
emit -> embed -> dump -> INGEST -> reconcile.

Honest note it prints: with ONLY the `.src` (source) hash — all that real embedded
firmware coSWIDs carry today — you canNOT verify the dumped bytes; the `.efi`
(shipped-byte) hash is what makes the reconcile possible.

All parsing done by python-uswid (no hand-rolled CBOR). PE extraction needs objcopy.

Usage:
  coswid-ingest.py --load module.coswid   --out-sbom ingested.cdx.json [--out-map h.json]
  coswid-ingest.py --load carrier.efi     --out-sbom ingested.cdx.json --objcopy /usr/bin/objcopy
"""
import argparse
import json
import os
import sys

try:
    from uswid.format_coswid import uSwidFormatCoswid
    from uswid.format_uswid import uSwidFormatUswid
    from uswid.format_pe import uSwidFormatPe
except ImportError:
    sys.exit("coswid-ingest: python-uswid not importable — run under a venv with `pip install uswid`")

SRC_SUFFIX = ".src"
EFI_SUFFIX = ".efi"


def load_container(path, objcopy):
    blob = open(path, "rb").read()
    ext = path.rsplit(".", 1)[-1].lower()
    if ext in ("efi", "exe", "o"):
        fmt = uSwidFormatPe(filepath=path)
        fmt.objcopy = objcopy   # objcopy path is an attribute, not a ctor arg
        return fmt.load(blob, path=path)
    if ext == "uswid":
        return uSwidFormatUswid().load(blob)
    # default: coSWID CBOR (also tolerates .cbor)
    return uSwidFormatCoswid().load(blob)


def payload_hash(component, suffix):
    for p in component.payloads:
        if p.name and p.name.endswith(suffix):
            for h in p.hashes:
                if str(h.alg_id) == "sha256":
                    return h.value.lower()
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--load", required=True, help="module.coswid / all.uswid / carrier.efi")
    ap.add_argument("--objcopy", default="/usr/bin/objcopy", help="objcopy for PE .sbom extraction")
    ap.add_argument("--out-sbom", required=True, help="CycloneDX SBOM (component SHA-256 = shipped-byte hash)")
    ap.add_argument("--out-map", help="optional JSON {guid: {source, evidence, name, moduleType}}")
    a = ap.parse_args()

    if not os.path.isfile(a.load):
        sys.exit("coswid-ingest: --load not found: %s" % a.load)
    container = load_container(a.load, a.objcopy)

    components, hmap, no_evidence = [], {}, []
    for c in container:
        guid = c.tag_id
        name = c.software_name or guid
        source = payload_hash(c, SRC_SUFFIX)
        evidence = payload_hash(c, EFI_SUFFIX)
        hmap[guid] = {"name": name, "source": source, "evidence": evidence,
                      "moduleType": "DXE_DRIVER"}
        if not evidence:
            no_evidence.append(name)
            continue
        components.append({
            "type": "application", "name": name, "bom-ref": guid,
            "version": c.software_version or "0",
            "properties": [{"name": "edk2:moduleType", "value": "DXE_DRIVER"}],
            # the reconcile lane's declared hash = the SHIPPED-BYTE (evidence) hash
            "hashes": [{"alg": "SHA-256", "content": evidence}],
        })

    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "firmware", "name": "coswid-ingested-firmware"}},
            "components": components}
    with open(a.out_sbom, "w") as f:
        json.dump(sbom, f, indent=2)
    if a.out_map:
        with open(a.out_map, "w") as f:
            json.dump(hmap, f, indent=2)

    print("coswid-ingest: %d module(s) from %s -> %s" % (len(components), os.path.basename(a.load), a.out_sbom))
    for guid, v in hmap.items():
        print("  %-22s source=%-8s evidence=%s"
              % (v["name"], (v["source"] or "<none>")[:8], (v["evidence"] or "<NONE — can't reconcile>")[:16]))
    if no_evidence:
        sys.stderr.write("  ⚠ no shipped-byte (evidence) hash for: %s — membership only, bytes unverifiable\n"
                         % ", ".join(no_evidence))


if __name__ == "__main__":
    main()
