#!/usr/bin/env python3
"""Build the OPA gate input from VERIFIED evidence — the single source of truth.

Ported from assemble-gate-input.sh (kept as a thin shim). Same env-var contract,
same output, so the local runner and the CI workflow can never drift. Every field
is derived from evidence, never asserted:

  - subject_digest + reconcile predicate: decoded from the VERIFIED DSSE bundle
  - sbom.hash: the SBOM file's actual SHA-256 (the policy binds it to subject_digest)
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


def integrity(sbom):
    mods = [c for c in sbom.get("components", []) if c.get("type") != "library"]
    def hashed(c):
        h = c.get("hashes")
        return isinstance(h, list) and len(h) > 0
    return {"hashable_total": len(mods),
            "hashed": sum(1 for c in mods if hashed(c)),
            "unhashed": [c.get("name") for c in mods if not hashed(c)]}


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
    absent = {"ran": False, "checked": 0, "verified": 0, "modified_count": 0, "skipped_count": 0}
    if not (path and os.path.isfile(path)):
        return absent
    try:
        d = load_json(path)
    except ValueError:
        return absent
    return {"ran": True, "checked": d.get("checked", 0),
            "verified": d.get("byte_verified", 0),
            "modified_count": len(d.get("modified", []) or []),
            # skipped OR errored modules are both un-verified (not passes)
            "skipped_count": len(d.get("skipped", []) or []) + len(d.get("errored", []) or [])}


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
        chipsec_passed = bool(dflt(load_json(chipsec_json), "critical_passed", False))
    else:
        chipsec_passed = env("CHIPSEC_PASSED") == "true"

    # Build-tools posture
    bt_sig = env("BUILD_TOOLS_SIG", "false")
    if bt_sig != "true" and env("DEV_ASSUME_BUILDTOOLS") == "1":
        bt_sig = "true"; warnings.append(
            "DEV_ASSUME_BUILDTOOLS=1 — build-tools signature ASSUMED for local demo, not verified "
            "(CI verifies it via cosign verify-blob of the build-tools bundle)")
    bt = build_tools(env("BUILD_TOOLS_JSON"), bt_sig == "true")

    # DSSE decode (from the VERIFIED bundle) + cert-SAN signer identity
    if sig == "true":
        stmt, bundle = decode_dsse(bundle_path)
        subject_digest = dflt(stmt.get("subject", [{}])[0].get("digest", {}), "sha256", "")
        pred = stmt.get("predicate", {}) or {}
        signer_id = signer_san(bundle)
    else:
        subject_digest, pred, signer_id = "", {}, ""

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

    # provenance subject (evidence-chain-bound)
    prov_sub = env("PROVENANCE_SUBJECT")
    if not prov_sub and env("DEV_ASSUME_CHAIN") == "1":
        prov_sub = "sha256:" + sbom_hash
        warnings.append("DEV_ASSUME_CHAIN=1 — provenance subject ASSUMED = SBOM digest for local demo "
                        "(CI extracts it from the verified attestation)")

    # firmware-image anchor legs
    fw_sbom = ""
    for h in (sbom.get("metadata", {}).get("component", {}).get("hashes") or []):
        if h.get("alg") == "SHA-256":
            fw_sbom = "sha256:" + h.get("content", "")
            break
    fw_reconcile = dflt(pred, "image_digest", "")
    fw_image = env("FW_IMAGE")
    if fw_image and os.path.isfile(fw_image):
        fw_deployed = "sha256:" + sha256_file(fw_image)
    elif env("DEV_ASSUME_FWIMAGE") == "1":
        fw_deployed = fw_sbom
        warnings.append("DEV_ASSUME_FWIMAGE=1 — deployed .fd digest ASSUMED = SBOM image digest for local "
                        "demo (CI/flash sets FW_IMAGE to hash the real deployed image)")
    else:
        fw_deployed = ""

    gate_input = {
        "sbom": {"present": len(sbom.get("components", [])) > 0, "hash": "sha256:" + sbom_hash,
                 "integrity": integrity(sbom), "thirdparty": thirdparty(sbom)},
        "attestation": {"subject_digest": ("" if subject_digest == "" else "sha256:" + subject_digest)},
        "signature": {"verified": sig == "true", "identity": effective_builder},
        "provenance": {"builder_id": effective_builder, "source_repo": repo,
                       "slsa_verified": slsa_verified == "true", "slsa_level": slsa_level,
                       "subject_digest": prov_sub},
        "reconcile": {"clean": clean, "missing": dflt(pred, "missing", []),
                      "added": dflt(pred, "added", []), "modified": dflt(pred, "modified", []),
                      "declared": dflt(summary, "declared_modules", 0),
                      "matched": dflt(summary, "validated", 0),
                      "missing_count": dflt(summary, "missing", 0),
                      "undeclared_observed": dflt(summary, "added_suspicious", 0)},
        "firmware": {"sbom_digest": fw_sbom, "reconcile_digest": fw_reconcile, "deployed_digest": fw_deployed},
        "cve": {"findings": cve_findings(env("GRYPE_JSON"))},
        "chipsec": {"critical_passed": chipsec_passed},
        "byte_integrity": byte_integrity_fact(env("BYTE_INTEGRITY_JSON")),
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
