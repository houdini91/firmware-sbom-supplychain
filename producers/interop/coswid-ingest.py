#!/usr/bin/env python3
"""coswid-ingest (WS-B) — ingest an embedded coSWID and recover the per-module
declared hash the reconcile lane needs.

Reads a coSWID/uSWID container OR a PE/COFF binary with an embedded `.sbom`
section (the OSF on-firmware format), and for every module recovers:
  * the declared SHIPPED-BYTE SHA-256 — the native coSWID payload hash (which the
    emit side carried straight through from the CycloneDX component). This is the
    hash `byte-integrity.py` reconciles the dumped bytes against.
  * the source-file hash, if present, from `colloquial-version` (provenance only;
    NOT used for the byte reconcile).

It writes a CycloneDX SBOM whose per-component SHA-256 is that declared hash —
exactly the shape `sbom-reconcile.py` (membership) and `byte-integrity.py` (byte
compare) already consume. This closes the loop: emit -> embed -> dump -> INGEST ->
reconcile.

The SBOM it writes deliberately carries the declared HASH and GUID ONLY — no module
type. byte-integrity derives each module's type (DXE vs XIP/PEI) from the carved
image itself, so a typeless coSWID cannot mis-drive the byte comparison.

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
    from uswid import uSwidHashAlg
    from uswid.format_coswid import uSwidFormatCoswid
    from uswid.format_uswid import uSwidFormatUswid
    from uswid.format_pe import uSwidFormatPe
except ImportError:
    sys.exit("coswid-ingest: python-uswid not importable — run under a venv with `pip install uswid`")


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


def declared_sha256(component):
    """The module's declared SHIPPED-BYTE SHA-256 — the native coSWID payload hash.
    Enum compare (h.alg_id == uSwidHashAlg.SHA256), not a fragile str() match."""
    for p in component.payloads:
        for h in p.hashes:
            if h.alg_id == uSwidHashAlg.SHA256 and h.value:
                return h.value.lower()
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--load", required=True, help="module.coswid / all.uswid / carrier.efi")
    ap.add_argument("--objcopy", default="/usr/bin/objcopy", help="objcopy for PE .sbom extraction")
    ap.add_argument("--out-sbom", required=True, help="CycloneDX SBOM (component SHA-256 = shipped-byte hash)")
    ap.add_argument("--out-map", help="optional JSON {guid: {name, source, declared}}")
    a = ap.parse_args()

    if not os.path.isfile(a.load):
        sys.exit("coswid-ingest: --load not found: %s" % a.load)
    container = load_container(a.load, a.objcopy)

    components, hmap, no_hash = [], {}, []
    for c in container:
        guid = c.tag_id
        name = c.software_name or guid
        declared = declared_sha256(c)
        source = c.colloquial_version.lower() if c.colloquial_version else None
        hmap[guid] = {"name": name, "source": source, "declared": declared}
        if not declared:
            no_hash.append(name)
            continue
        components.append({
            "type": "application", "name": name, "bom-ref": guid,
            "version": c.software_version or "0",
            # declared hash ONLY — no module type; byte-integrity gets the type from
            # the carved image, so a typeless coSWID cannot mis-drive the compare.
            "hashes": [{"alg": "SHA-256", "content": declared}],
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
        print("  %-22s source=%-8s declared(shipped-byte)=%s"
              % (v["name"], (v["source"] or "<none>")[:8], (v["declared"] or "<NONE — can't reconcile>")[:16]))
    if no_hash:
        sys.stderr.write("  ⚠ no declared shipped-byte hash for: %s — membership only, bytes unverifiable\n"
                         % ", ".join(no_hash))


if __name__ == "__main__":
    main()
