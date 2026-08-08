#!/usr/bin/env python3
"""Build the OPA gate input from VERIFIED evidence — the single source of truth.

Ported from assemble-gate-input.sh (kept as a thin shim). Same env-var contract,
same output, so the local runner and the CI workflow can never drift. Every field
is derived from evidence, never asserted:

  - attestation.file_subject (H) + attestation.firmware_subject (D) + reconcile predicate:
    decoded from the VERIFIED multi-subject DSSE bundle — the "firmware-image" subject is the
    firmware anchor D (evidence-graph binding); the bound SBOM-file subject is H (tamper-after-
    signing binding)
  - sbom.hash: the SBOM file's actual SHA-256 H (the policy binds it to attestation.file_subject)
  - provenance.builder_id: the signer identity (cert SAN URI) extracted from the bundle
  - cve.findings: the grype scan
  - firmware.*: the firmware-image anchor legs (build SBOM digest / reconcile re-hash / deployed)

Env in:  SBOM BUNDLE SIG(true|false) OUT  [BUILDER_ID SOURCE_REPO GRYPE_JSON
         CHIPSEC_JSON BUILD_TOOLS_JSON BUILD_TOOLS_SIG SLSA_VERIFIED PROVENANCE_SUBJECT
         FW_IMAGE  DEV_ASSUME_{IDENTITY,SLSA,BUILDTOOLS,CHAIN,FWIMAGE}]
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys


def env(name, default=""):
    return os.environ.get(name, default)


def require(name):
    v = os.environ.get(name)
    if not v:
        sys.exit("assemble_gate_input: %s is required" % name)
    return v


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path):
    with open(path) as f:
        return json.load(f)


def dflt(d, key, default):
    """jq `.key // default` — absent OR null falls through to default."""
    v = d.get(key)
    return default if v is None else v


def decode_dsse(bundle_path):
    """Decode the in-toto Statement from a legacy cosign bundle (.base64Signature).
    Fails closed with a clear message on an unexpected format."""
    try:
        bundle = load_json(bundle_path)
        env_json = json.loads(base64.b64decode(bundle["base64Signature"]))
        stmt = json.loads(base64.b64decode(env_json["payload"]))
        if not isinstance(stmt, dict):
            raise ValueError("payload is not an object")
        return stmt, bundle
    except Exception:
        sys.exit("error: could not decode a DSSE in-toto payload from %s — unexpected cosign "
                 "bundle format (expected legacy .base64Signature). Pin cosign or refresh the bundle."
                 % bundle_path)


def signer_san(bundle):
    """Extract the signer identity (cert SAN URI) from the bundle cert — do NOT
    trust an env string. Shells out to openssl for the one field (no new dep)."""
    cert = bundle.get("cert") or ""
    if not cert:
        return ""
    if "BEGIN" not in cert or "CERTIFICATE" not in cert:
        try:
            cert = base64.b64decode(cert).decode("utf-8", "replace")
        except Exception:
            return ""
    try:
        out = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName"],
                             input=cert, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             universal_newlines=True).stdout
    except Exception:
        return ""
    for tok in out.replace(",", " ").split():
        if tok.startswith("URI:"):
            return tok[len("URI:"):]
    return ""


def build_tools_derive(comps, sig_verified):
    """Pure: components list -> build-tools posture. A component is unpinned if it
    has neither a concrete version (absent or 'latest') nor a hash."""
    unpinned = [c.get("name") for c in comps
                if ((not c.get("version")) or c.get("version") == "latest") and not c.get("hashes")]
    return {"present": len(comps) > 0, "unpinned": unpinned,
            "all_pinned": len(unpinned) == 0, "signature_verified": sig_verified}


def build_tools(path, sig_verified):
    if path and os.path.isfile(path):
        return build_tools_derive(load_json(path).get("components", []) or [], sig_verified)
    # missing file: explicitly not-present and not-pinned (distinct from an empty list)
    return {"present": False, "unpinned": [], "all_pinned": False, "signature_verified": sig_verified}


# DXE-class module types the image-protection policy governs — NX-compat is required
# for these (mirrors producers/reconcile/binary-hardening.py DXE_CLASS). Used as the
# SBOM-derived coverage denominator for binary-hardening, so a cherry-picked verdict
# cannot fake its own coverage.
DXE_CLASS = {"DXE_DRIVER", "DXE_RUNTIME_DRIVER", "DXE_SAL_DRIVER", "UEFI_DRIVER",
             "UEFI_APPLICATION", "DXE_CORE", "SMM_CORE", "DXE_SMM_DRIVER", "MM_STANDALONE"}


def _module_type(c):
    for p in (c.get("properties") or []):
        if p.get("name") == "edk2:moduleType":
            return p.get("value")
    return None


def integrity(sbom):
    mods = [c for c in sbom.get("components", []) if c.get("type") != "library"]
    def hashed(c):
        h = c.get("hashes")
        return isinstance(h, list) and len(h) > 0
    return {"hashable_total": len(mods),
            "hashed": sum(1 for c in mods if hashed(c)),
            "unhashed": [c.get("name") for c in mods if not hashed(c)],
            "dxe_class_total": sum(1 for c in mods if _module_type(c) in DXE_CLASS)}


def generation(sbom):
    """CISA 2026 Minimum Elements — Generation Tool + Generation Context, surfaced
    from the SBOM the same way integrity()/thirdparty() surface their facts. HONESTY:
    this reports what the SBOM DECLARES (a tool with name+version; a lifecycle phase),
    not that the declared tool produced these bytes — the gate rule reflects that ceiling.
      - tool_present: metadata.tools carries at least one entry with a name AND version.
        CycloneDX 1.4 tools is a list; 1.5+ is an object {components:[...],services:[...]}.
      - context_present: metadata.lifecycles[] carries at least one entry with a phase."""
    md = sbom.get("metadata", {}) or {}
    tools = md.get("tools")
    if isinstance(tools, dict):
        tool_list = (tools.get("components") or []) + (tools.get("services") or [])
    elif isinstance(tools, list):
        tool_list = tools
    else:
        tool_list = []
    tool_present = any(t.get("name") and t.get("version") for t in tool_list if isinstance(t, dict))
    lifecycles = md.get("lifecycles") or []
    context_present = any(lc.get("phase") for lc in lifecycles if isinstance(lc, dict))
    return {"tool_present": tool_present, "context_present": context_present}


_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _source_revision(sbom):
    """The build-wide source revision (git commit) the image was built from — the
    -Y SBOM generator records it on the document-root component as edk2:sourceRevision
    ('git:<sha>'). This is the SLSA-provenance-style coarse source anchor, surfaced into
    the gate input's provenance so the evidence records WHICH source produced the image,
    complementing the per-module edk2:sourceHash. Empty (not fabricated) if absent."""
    mc = (sbom.get("metadata", {}) or {}).get("component", {}) or {}
    for p in (mc.get("properties") or []):
        if p.get("name") == "edk2:sourceRevision" and p.get("value"):
            return p.get("value")
    return ""


def _source_hash_present(c):
    """OSF M-srchash: a real source-file hash rides in coSWID colloquial-version. In the
    CycloneDX manifest that carrier is an explicit edk2:sourceHash property — the -Y SBOM
    generator now emits one per module (a SHA-256 over the module's INF [Sources] set). A
    module with no readable source honestly carries none."""
    for p in (c.get("properties") or []):
        if p.get("name") == "edk2:sourceHash" and p.get("value"):
            return True
    return False


def osf_conformance(sbom):
    """OSF Firmware Embedded SBOM structural conformance, surfaced from the CycloneDX
    manifest the gate already holds — a manifest-level proxy for the embedded coSWID
    shape, NOT a parse of the coSWID extracted from the shipped PE (that deeper check
    stays roadmapped; see CONFORMANCE.md). Two MUSTs are separable here:
      - GUID identity (MET): every firmware module's tag-id is its FILE_GUID. In the
        CDX manifest the module's bom-ref carries the FILE_GUID, so guid_tag_id counts
        modules whose bom-ref is GUID-form.
      - Source-file hash / M-srchash (UNMET by default): source_hash_present counts
        modules carrying an edk2:sourceHash. 0 unless --source-hashes was supplied."""
    mods = [c for c in sbom.get("components", []) if c.get("type") != "library"]
    guid_tag_id = sum(1 for c in mods if _GUID_RE.match(str(c.get("bom-ref", ""))))
    return {"evaluated": True,
            "modules_total": len(mods),
            "guid_tag_id": guid_tag_id,
            "source_hash_present": sum(1 for c in mods if _source_hash_present(c))}


def thirdparty(sbom):
    def vendored(c):
        return any(p.get("name") == "edk2:vendored" and p.get("value") == "true"
                   for p in (c.get("properties") or []))
    tp = [c for c in sbom.get("components", []) if vendored(c)]
    def missing(c):
        return (not c.get("purl")) or c.get("purl") == "" \
            or (not c.get("licenses")) or len(c.get("licenses")) == 0
    return {"total": len(tp), "missing": [c.get("name") for c in tp if missing(c)]}


def cve_findings(path):
    if not (path and os.path.isfile(path) and os.path.getsize(path) > 0):
        return []
    try:
        doc = load_json(path)
    except ValueError:
        return []
    seen, out = set(), []
    for m in doc.get("matches", []) or []:
        v = {"id": m.get("vulnerability", {}).get("id"),
             "component": m.get("artifact", {}).get("name"),
             "severity": (m.get("vulnerability", {}).get("severity") or "").upper()}
        key = json.dumps(v, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return sorted(out, key=lambda x: json.dumps(x, sort_keys=True))


def byte_integrity_fact(path):
    """R4: fold the byte-integrity producer's verdict into a gate fact. ran=False
    when no image+edk2 was available to the producer (distinct from a clean run).
    Surfaces skipped_count so the gate can refuse a vacuous pass (all modules
    skipped / nothing verified) — a skip is NOT a pass."""
    absent = {"ran": False, "checked": 0, "verified": 0, "modified_count": 0,
              "skipped_count": 0, "unverifiable": []}
    if not (path and os.path.isfile(path)):
        return absent
    try:
        d = load_json(path)
    except ValueError:
        return absent
    # NAMES of modules that could not be byte-verified (skipped OR errored) — surfaced so
    # the gate can name exactly what did not pass and check each against a reviewed
    # exemption list (data.byte_integrity_exempt); an unexpected one denies.
    unverifiable = [x.get("name") for x in (d.get("skipped", []) or [])] \
        + [x.get("name") for x in (d.get("errored", []) or [])]
    unverifiable = sorted(n for n in unverifiable if n)
    modified_names = sorted(n for n in (m.get("name") for m in (d.get("modified", []) or [])) if n)
    return {"ran": True, "checked": d.get("checked", 0),
            "verified": d.get("byte_verified", 0),
            "modified_count": len(d.get("modified", []) or []),
            "modified": modified_names,  # NAMES of MODIFIED modules, so the gate can name what tampered
            "unverifiable": unverifiable,
            "skipped_count": len(unverifiable)}


def binary_hardening_fact(path):
    """R8: fold the binary-hardening producer's verdict into a gate fact. ran=False
    when no image+edk2 was available (distinct from a clean run). Surfaces the
    DXE-class NX-compat coverage AND the DXE-class modules that could not be scanned
    (unverifiable) so the gate can refuse a vacuous/under-covered pass and name exactly
    what did not pass — an unexamined image is NOT a hardened one."""
    absent = {"ran": False, "dxe_class_checked": 0, "dxe_nx_compat": 0,
              "missing_nx_count": 0, "errored_count": 0, "unverifiable": []}
    if not (path and os.path.isfile(path)):
        return absent
    try:
        d = load_json(path)
    except ValueError:
        return absent
    # NAMES of DXE-class modules that could not be scanned (skipped OR errored). Only
    # DXE-class matters for the NX expectation, so non-DXE skips (PEI/SEC/TE) are not
    # "unverifiable" here. Each is checked against data.binary_hardening_exempt; an
    # unexpected one denies. (skipped/errored entries carry their module `type`.)
    unverifiable = [x.get("name") for x in (d.get("skipped", []) or [])
                    if x.get("type") in DXE_CLASS] \
        + [x.get("name") for x in (d.get("errored", []) or [])
           if x.get("type") in DXE_CLASS]
    unverifiable = sorted(n for n in unverifiable if n)
    missing_nx_names = sorted(n for n in (m.get("name") for m in (d.get("dxe_missing_nx", []) or [])) if n)
    return {"ran": True,
            "dxe_class_checked": d.get("dxe_class_checked", 0),
            "dxe_nx_compat": d.get("dxe_nx_compat", 0),
            "missing_nx_count": len(d.get("dxe_missing_nx", []) or []),
            "missing_nx": missing_nx_names,  # NAMES of missing-NX DXE modules, so the gate can name them
            "errored_count": len(d.get("errored", []) or []),
            "unverifiable": unverifiable}


# CHIPSEC sub-result module names the platform-posture reports read directly (mirrors how
# chipsec-posture already consumes chipsec.json). Surfaced as {fact: PASSED|FAILED|NOTAPPLICABLE},
# defaulting to "ABSENT" when the module did not appear (so the gate can tell absent from failed).
CHIPSEC_FACTS = {"secure_boot": "common.secureboot.variables", "smm": "common.smm",
                 "bios_wp": "common.bios_wp", "bios_ts": "common.bios_ts", "smrr": "common.smrr"}


def chipsec_subresults(doc):
    by = {}
    for r in (doc.get("results", []) or []):
        if r.get("module"):
            by[r["module"]] = (r.get("result") or "").upper()
    return {fact: by.get(mod, "ABSENT") for fact, mod in CHIPSEC_FACTS.items()}


def main():
    sbom_path = require("SBOM"); bundle_path = require("BUNDLE")
    sig = require("SIG"); out_path = require("OUT")
    builder = env("BUILDER_ID"); repo = env("SOURCE_REPO")
    warnings = []

    # SLSA L2 floor
    slsa_verified = env("SLSA_VERIFIED", "false")
    if slsa_verified != "true" and env("DEV_ASSUME_SLSA") == "1":
        slsa_verified = "true"; warnings.append(
            "DEV_ASSUME_SLSA=1 — SLSA L2 provenance ASSUMED for local demo, not platform-verified "
            "(CI verifies it via gh attestation verify)")
    slsa_level = 2 if slsa_verified == "true" else 0

    # CHIPSEC posture
    chipsec_json = env("CHIPSEC_JSON")
    if chipsec_json and os.path.isfile(chipsec_json):
        _chipsec_doc = load_json(chipsec_json)
        chipsec_passed = bool(dflt(_chipsec_doc, "critical_passed", False))
        chipsec_subs = chipsec_subresults(_chipsec_doc)
    else:
        chipsec_passed = env("CHIPSEC_PASSED") == "true"
        chipsec_subs = {fact: "ABSENT" for fact in CHIPSEC_FACTS}

    # Build-tools posture
    bt_sig = env("BUILD_TOOLS_SIG", "false")
    if bt_sig != "true" and env("DEV_ASSUME_BUILDTOOLS") == "1":
        bt_sig = "true"; warnings.append(
            "DEV_ASSUME_BUILDTOOLS=1 — build-tools signature ASSUMED for local demo, not verified "
            "(CI verifies it via cosign verify-blob of the build-tools bundle)")
    bt = build_tools(env("BUILD_TOOLS_JSON"), bt_sig == "true")

    # DSSE decode (from the VERIFIED bundle) + cert-SAN signer identity.
    # The reconcile attestation is a MULTI-SUBJECT in-toto Statement: subject "firmware-image"
    # is the firmware anchor D, and a second subject (the bound SBOM file) carries H. We surface
    # both separately — D drives the firmware/evidence-graph binding, H drives the SBOM-file
    # (tamper-after-signing) binding. A legacy single-subject bundle degrades to file_subject=that
    # subject, firmware_subject="".
    if sig == "true":
        stmt, bundle = decode_dsse(bundle_path)
        subjects = stmt.get("subject", []) or []
        att_firmware = ""
        att_file = ""
        for s in subjects:
            h = dflt(s.get("digest", {}) or {}, "sha256", "")
            if s.get("name") == "firmware-image":
                att_firmware = h
            elif not att_file:
                att_file = h
        if not att_file and subjects:  # legacy single-subject: the lone subject is the file digest H
            att_file = dflt(subjects[0].get("digest", {}) or {}, "sha256", "")
        pred = stmt.get("predicate", {}) or {}
        signer_id = signer_san(bundle)
    else:
        att_firmware, att_file, pred, signer_id = "", "", {}, ""

    # EFFECTIVE_BUILDER: the extracted identity, else assumed, else unverifiable
    if signer_id:
        effective_builder = signer_id
    elif env("DEV_ASSUME_IDENTITY") == "1":
        effective_builder = builder
        warnings.append("DEV_ASSUME_IDENTITY=1 — builder identity ASSUMED, not cryptographically "
                        "verified (CI keyless verifies it for real)")
    else:
        effective_builder = "unverified:no-cert-identity"

    sbom = load_json(sbom_path)
    sbom_hash = sha256_file(sbom_path)
    summary = pred.get("summary", {}) or {}
    clean = (dflt(summary, "missing", 1) == 0 and dflt(summary, "modified", 1) == 0
             and dflt(summary, "added_suspicious", 1) == 0)

    # firmware-image anchor D: the SBOM's own metadata.component SHA-256 — the digest
    # of the firmware bytes the build says it shipped. The evidence graph is rooted at D
    # (see _evidence_chain_bound), so the provenance subject binds to D, not to the SBOM
    # file digest H.
    fw_sbom = ""
    for h in (sbom.get("metadata", {}).get("component", {}).get("hashes") or []):
        if h.get("alg") == "SHA-256":
            fw_sbom = "sha256:" + h.get("content", "")
            break

    # provenance subjects. E2 SLSA provenance is platform-generated (GitHub attest-build-
    # provenance over the SBOM file), so its real subject is the SBOM-file digest H — that is
    # the FILE subject, consumed by the H-consistency leg of evidence-chain-bound. Its FIRMWARE
    # binding to D cannot be extracted (single-subject H), so it is a DEV_ASSUME-class mapping to
    # the firmware anchor D (informational — the rego's firmware binding is checked on the WE-built
    # reconcile attestation, not on E2).
    prov_file_sub = env("PROVENANCE_SUBJECT")
    if not prov_file_sub and env("DEV_ASSUME_CHAIN") == "1":
        prov_file_sub = "sha256:" + sbom_hash
        warnings.append("DEV_ASSUME_CHAIN=1 — provenance FILE subject ASSUMED = SBOM file digest H for "
                        "local demo (CI extracts it from the verified attestation)")
    prov_firmware_sub = fw_sbom  # DEV_ASSUME-class: E2 is single-subject H; D is the anchor mapping

    # firmware-image anchor legs
    fw_reconcile = dflt(pred, "image_digest", "")
    # freshly_measured distinguishes a GENUINE flash-time measurement (a real FW_IMAGE hashed
    # here at leg-3) from DEV_ASSUME_FWIMAGE mode (leg-3 copied from the build self-claim). Only
    # the former discharges SP 800-193 §4.3.1 (admission-time detection); the gate emits the
    # firmware-freshly-measured report ONLY when this is true, so offline/CI never claims §4.3.1.
    fw_image = env("FW_IMAGE")
    if fw_image and os.path.isfile(fw_image):
        fw_deployed = "sha256:" + sha256_file(fw_image)
        fw_freshly_measured = True
    elif env("DEV_ASSUME_FWIMAGE") == "1":
        fw_deployed = fw_sbom
        fw_freshly_measured = False
        warnings.append("DEV_ASSUME_FWIMAGE=1 — deployed .fd digest ASSUMED = SBOM image digest for local "
                        "demo (CI/flash sets FW_IMAGE to hash the real deployed image); §4.3.1 NOT claimed")
    else:
        fw_deployed = ""
        fw_freshly_measured = False

    gate_input = {
        "sbom": {"present": len(sbom.get("components", [])) > 0, "hash": "sha256:" + sbom_hash,
                 "integrity": integrity(sbom), "thirdparty": thirdparty(sbom),
                 "generation": generation(sbom), "osf": osf_conformance(sbom)},
        "attestation": {"file_subject": ("" if att_file == "" else "sha256:" + att_file),
                        "firmware_subject": ("" if att_firmware == "" else "sha256:" + att_firmware)},
        "signature": {"verified": sig == "true", "identity": effective_builder},
        "provenance": {"builder_id": effective_builder, "source_repo": repo,
                       "source_commit": _source_revision(sbom),
                       "slsa_verified": slsa_verified == "true", "slsa_level": slsa_level,
                       "file_subject": prov_file_sub, "firmware_subject": prov_firmware_sub},
        "reconcile": {"clean": clean, "missing": dflt(pred, "missing", []),
                      "added": dflt(pred, "added", []), "modified": dflt(pred, "modified", []),
                      "declared": dflt(summary, "declared_modules", 0),
                      "matched": dflt(summary, "validated", 0),
                      "missing_count": dflt(summary, "missing", 0),
                      "undeclared_observed": dflt(summary, "added_suspicious", 0)},
        "firmware": {"sbom_digest": fw_sbom, "reconcile_digest": fw_reconcile, "deployed_digest": fw_deployed,
                     "freshly_measured": fw_freshly_measured},
        "cve": {"findings": cve_findings(env("GRYPE_JSON"))},
        "chipsec": {"critical_passed": chipsec_passed, **chipsec_subs},
        "byte_integrity": byte_integrity_fact(env("BYTE_INTEGRITY_JSON")),
        "binary_hardening": binary_hardening_fact(env("BINARY_HARDENING_JSON")),
        "build_tools": {"present": bt["present"], "signature_verified": bt["signature_verified"],
                        "all_pinned": bt["all_pinned"], "unpinned": bt["unpinned"]},
    }

    with open(out_path, "w") as f:
        json.dump(gate_input, f, indent=2)
        f.write("\n")

    sys.stderr.write("   builder_id=%s\n" % effective_builder)
    for w in warnings:
        sys.stderr.write("   ⚠ %s\n" % w)


if __name__ == "__main__":
    main()
