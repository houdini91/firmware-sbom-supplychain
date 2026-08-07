#!/usr/bin/env python3
"""coswid-emit (WS-A) — emit a spec-conformant coSWID that carries BOTH hashes.

The OSF Firmware Embedded SBOM spec (and RFC 9393) model a per-file cryptographic
hash on a `file-entry`. Real embedded firmware coSWIDs today carry ONLY a
source-file hash (the OSF MUST) — nothing you can reconcile against the shipped
silicon. This tool emits a coSWID per module that carries TWO distinctly-named
file-entry hashes:

  * <module>.src  -> the OSF-mandated SOURCE-FILE SHA-256 (build provenance;
                     "built from that source"). This is the "payload/declared" hash.
  * <module>.efi  -> our NORMALIZED SHIPPED-BYTE SHA-256 (byte-integrity.py's
                     declared hash: GenFw-normalized, XIP un-rebased). This is the
                     "evidence/measured" hash a consumer recomputes from a dumped .fd.

Per RFC 9393 §2.9.3/§2.9.4 the *semantic* home for the second hash is the
`evidence` branch (measured on the device), NOT a second `payload` file-entry.
SPEC-GAP (verified against python-uswid, the OSF reference tool): its
`uSwidEvidence` class carries ONLY {date, device_id} — it has NO hash field, so
the shipped-byte hash CANNOT be expressed in the coSWID `evidence` branch with the
reference tooling. We therefore carry it as a second `payload` file-entry (still a
conformant RFC 9393 hash-entry, just under `payload` rather than `evidence`). This
is exactly the spec/tooling gap the Hughes/USBT verification-profile proposal targets.

All CBOR/coSWID serialization is done by python-uswid (`hughsie/python-uswid`) — no
hand-rolled CBOR. Install: `python3 -m venv v && v/bin/pip install uswid`, then run
this under that interpreter.

Usage:
  coswid-emit.py --sbom sbom.cdx.json [--guids g1,g2] [--source-hashes src.json]
                 --out module.coswid            # single tag  (.coswid, for PE embed)
  coswid-emit.py --sbom sbom.cdx.json --out all.uswid           # container (.uswid)
"""
import argparse
import hashlib
import json
import os
import sys

try:
    from uswid import (uSwidComponent, uSwidEntity, uSwidEntityRole,
                       uSwidPayload, uSwidHash, uSwidHashAlg, uSwidContainer)
    from uswid.format_coswid import uSwidFormatCoswid
    from uswid.format_uswid import uSwidFormatUswid
    from uswid.evidence import uSwidEvidence
except ImportError:
    sys.exit("coswid-emit: python-uswid not importable — run under a venv with `pip install uswid`")

SRC_SUFFIX = ".src"   # payload fs-name suffix: OSF source-file hash (declared)
EFI_SUFFIX = ".efi"   # payload fs-name suffix: normalized shipped-byte hash (evidence)


def module_type(c):
    for p in (c.get("properties") or []):
        if p.get("name") == "edk2:moduleType":
            return p.get("value") or ""
    return ""


def stand_in_source_hash(name):
    """Deterministic STAND-IN source-file hash. The real OSF source hash is SHA-256
    over the module's .c/.h set — the edk2 source tree is NOT in this repo, so when
    no real source hash is supplied we emit a reproducible placeholder and FLAG it."""
    return hashlib.sha256(b"STAND-IN-SOURCE::" + name.encode()).hexdigest()


def build_component(guid, name, version, evidence_sha256, source_sha256, source_is_standin):
    c = uSwidComponent(tag_id=guid, software_name=name, software_version=version or "0")
    # RFC 9393 §2.6: a tag-creator entity MUST be present.
    c.add_entity(uSwidEntity(name="Oats Solutions", regid="oatssolutions.tech",
                             roles=[uSwidEntityRole.TAG_CREATOR, uSwidEntityRole.SOFTWARE_CREATOR]))
    # payload #1 — OSF source-file hash (the MUST; what real firmware carries today)
    p_src = uSwidPayload(name=name + SRC_SUFFIX)
    p_src.add_hash(uSwidHash(alg_id=uSwidHashAlg.SHA256, value=source_sha256))
    c.add_payload(p_src)
    # payload #2 — our normalized shipped-byte hash (belongs semantically in `evidence`,
    # see module docstring; carried as a payload file-entry because uSwidEvidence has no hash).
    p_efi = uSwidPayload(name=name + EFI_SUFFIX)
    p_efi.add_hash(uSwidHash(alg_id=uSwidHashAlg.SHA256, value=evidence_sha256))
    c.add_payload(p_efi)
    # Attach an (empty) evidence entry purely to make the spec-gap visible: it can hold
    # date/device_id but NOT the measured hash — that field does not exist in the tool.
    c.add_evidence(uSwidEvidence(device_id="reconcile:normalized-shipped-bytes"))
    return c, source_is_standin


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sbom", required=True, help="CycloneDX SBOM; component SHA-256 = normalized shipped-byte (evidence) hash")
    ap.add_argument("--source-hashes", help="JSON {guid: sha256} of real OSF source-file hashes (optional)")
    ap.add_argument("--guids", help="comma-separated FILE_GUIDs to emit (default: all with a GUID+SHA-256)")
    ap.add_argument("--out", required=True, help="output .coswid (single tag) or .uswid (container)")
    a = ap.parse_args()

    if not os.path.isfile(a.sbom):
        sys.exit("coswid-emit: --sbom not found: %s" % a.sbom)
    sbom = json.load(open(a.sbom))
    src_map = json.load(open(a.source_hashes)) if a.source_hashes else {}
    src_map = {k.replace("-", "").lower(): v for k, v in src_map.items()}
    want = None
    if a.guids:
        want = {g.replace("-", "").lower() for g in a.guids.split(",")}

    comps, standins = [], []
    for c in sbom.get("components", []):
        ref = (c.get("bom-ref") or "").replace("-", "").lower()
        if len(ref) != 32:
            continue
        if want is not None and ref not in want:
            continue
        ev = None
        for h in (c.get("hashes") or []):
            if h.get("alg") == "SHA-256" and h.get("content"):
                ev = h["content"].lower()
                break
        if not ev:
            continue
        name = c.get("name") or ref
        if ref in src_map:
            src, standin = src_map[ref].lower(), False
        else:
            src, standin = stand_in_source_hash(name), True
            standins.append(name)
        comp, _ = build_component(c.get("bom-ref"), name, c.get("version"), ev, src, standin)
        comps.append(comp)

    if not comps:
        sys.exit("coswid-emit: no components with a GUID + SHA-256 matched")

    container = uSwidContainer(comps)
    ext = a.out.rsplit(".", 1)[-1].lower()
    if ext == "uswid":
        blob = uSwidFormatUswid().save(container)
    elif ext in ("coswid", "cbor"):
        if len(comps) != 1:
            sys.exit("coswid-emit: .coswid is a single tag — %d components matched; select one with --guids "
                     "or use a .uswid container" % len(comps))
        blob = uSwidFormatCoswid().save(container)
    else:
        sys.exit("coswid-emit: --out must end .coswid (single tag) or .uswid (container)")
    with open(a.out, "wb") as f:
        f.write(blob)

    print("coswid-emit: %d module(s) -> %s (%d bytes)" % (len(comps), a.out, len(blob)))
    for c in comps:
        hs = {p.name: p.hashes[0].value[:16] + "…" for p in c.payloads}
        print("  %-22s src=%s  efi=%s" % (c.software_name,
              hs.get(c.software_name + SRC_SUFFIX), hs.get(c.software_name + EFI_SUFFIX)))
    if standins:
        sys.stderr.write("  ⚠ STAND-IN source-file hash used for: %s "
                         "(no edk2 source tree in-repo; pass --source-hashes for the real hash)\n"
                         % ", ".join(standins))


if __name__ == "__main__":
    main()
