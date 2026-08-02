#!/usr/bin/env bash
# Single source of truth for building the OPA gate input from VERIFIED evidence.
# Both the local runner and the CI workflow call this, so they can never drift.
#
# Env in:  SBOM BUNDLE SIG(true|false) BUILDER_ID SOURCE_REPO [GRYPE_JSON] OUT
#          [DEV_ASSUME_IDENTITY=1]  (local dev only — see F2 below)
#
# Every field is derived from evidence:
#   - subject_digest + reconcile predicate: decoded from the VERIFIED DSSE bundle (not the on-disk file)
#   - sbom.hash: the SBOM file's actual digest (bound to subject_digest by the policy)
#   - provenance.builder_id: the signer identity (SAN URI) extracted from the cert in the bundle
#   - cve.findings: the grype scan
set -euo pipefail

SBOM="${SBOM:?}"; BUNDLE="${BUNDLE:?}"; SIG="${SIG:?}"; OUT="${OUT:?}"
BUILDER="${BUILDER_ID:-}"; REPO="${SOURCE_REPO:-}"; GRYPE_JSON="${GRYPE_JSON:-}"
# SLSA L2 provenance is established in CI by attest-build-provenance + the
# `gh attestation verify` hard-gate, which sets SLSA_VERIFIED=true here. The
# offline demo cannot run it; DEV_ASSUME_SLSA=1 opts into an ASSUMED L2 (warned).
SLSA_VERIFIED="${SLSA_VERIFIED:-false}"
if [ "$SLSA_VERIFIED" != "true" ] && [ "${DEV_ASSUME_SLSA:-0}" = "1" ]; then
  SLSA_VERIFIED=true; SLSA_ASSUMED=1
fi
# SR-4/SR-4(3): SLSA build-level floor. E2 is L2 (hosted, platform-generated),
# NOT hermetic/isolated (L3) — so the level is 2 when verified, 0 otherwise.
SLSA_LEVEL=0; [ "$SLSA_VERIFIED" = "true" ] && SLSA_LEVEL=2
# CHIPSEC platform posture (R3): read critical_passed from the CHIPSEC predicate.
CHIPSEC_JSON="${CHIPSEC_JSON:-}"
if [ -n "$CHIPSEC_JSON" ] && [ -f "$CHIPSEC_JSON" ]; then
  CHIPSEC_PASSED="$(jq -r '.critical_passed // false' "$CHIPSEC_JSON")"
else
  CHIPSEC_PASSED="${CHIPSEC_PASSED:-false}"
fi
# Build-tools SBOM posture (E7 — SSDF PO.3.2 / S2C2F REB-3): when BUILD_TOOLS_JSON is set,
# derive present (file exists + components>0), unpinned (components lacking BOTH a version and
# a hash — a "latest" version counts as unpinned), and all_pinned (unpinned empty).
# signature_verified is established in CI by the cosign verify-blob of the build-tools bundle,
# which sets BUILD_TOOLS_SIG=true here. The offline demo cannot run it; DEV_ASSUME_BUILDTOOLS=1
# opts into an ASSUMED signature (warned) — EXACTLY mirroring the SLSA_VERIFIED/DEV_ASSUME_SLSA pattern.
BUILD_TOOLS_JSON="${BUILD_TOOLS_JSON:-}"
BUILD_TOOLS_SIG="${BUILD_TOOLS_SIG:-false}"
if [ "$BUILD_TOOLS_SIG" != "true" ] && [ "${DEV_ASSUME_BUILDTOOLS:-0}" = "1" ]; then
  BUILD_TOOLS_SIG=true; BUILDTOOLS_ASSUMED=1
fi
if [ -n "$BUILD_TOOLS_JSON" ] && [ -f "$BUILD_TOOLS_JSON" ]; then
  BUILDTOOLS="$(jq -c '
    {present: ((.components|length) > 0),
     unpinned: [.components[] | select(((.version|not) or (.version=="latest")) and (.hashes|not)) | .name]}
    | . + {all_pinned: ((.unpinned|length) == 0)}' "$BUILD_TOOLS_JSON")"
else
  BUILDTOOLS='{"present":false,"unpinned":[],"all_pinned":false}'
fi
BUILDTOOLS="$(printf '%s' "$BUILDTOOLS" | jq -c --arg sig "$BUILD_TOOLS_SIG" '. + {signature_verified: ($sig=="true")}')"

if [ "$SIG" = "true" ]; then
  STMT="$(jq -r '.base64Signature' "$BUNDLE" | base64 -d | jq -r '.payload' | base64 -d)"
  SUBJECT_DIGEST="$(printf '%s' "$STMT" | jq -r '.subject[0].digest.sha256 // ""')"
  PRED="$(printf '%s' "$STMT" | jq -c '.predicate')"
  # F2: extract the signer identity (cert SAN URI) from the bundle — do NOT trust an env string.
  CERT_PEM="$(jq -r '.cert // ""' "$BUNDLE")"
  case "$CERT_PEM" in
    *BEGIN*CERTIFICATE*) : ;;                                         # already PEM
    ?*) CERT_PEM="$(printf '%s' "$CERT_PEM" | base64 -d 2>/dev/null || true)" ;;
  esac
  SIGNER_ID="$(printf '%s' "$CERT_PEM" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
                | grep -oE 'URI:[^, ]+' | head -1 | sed 's/URI://' || true)"
else
  SUBJECT_DIGEST=""; PRED='{}'; SIGNER_ID=""
fi

# The builder_id the policy evaluates is the EXTRACTED identity. If the signature carried no cert
# identity (plain local --key signing), it is genuinely unverifiable: fail unless the operator opts
# into DEV_ASSUME_IDENTITY (which the runner warns about loudly). CI keyless always yields a real SIGNER_ID.
if [ -n "$SIGNER_ID" ]; then
  EFFECTIVE_BUILDER="$SIGNER_ID"
elif [ "${DEV_ASSUME_IDENTITY:-0}" = "1" ]; then
  EFFECTIVE_BUILDER="$BUILDER"                 # assumed, NOT cryptographically verified
else
  EFFECTIVE_BUILDER="unverified:no-cert-identity"
fi

SBOM_HASH="$(sha256sum "$SBOM" | cut -d' ' -f1)"
PRESENT="$(jq '(.components|length) > 0' "$SBOM")"
CLEAN="$(printf '%s' "$PRED" | jq '((.summary.missing // 1)==0) and ((.summary.modified // 1)==0) and ((.summary.added_suspicious // 1)==0)')"
# SI-7/CM-8(3): reconcile membership counts, from the signed reconcile predicate summary.
DECLARED="$(printf '%s' "$PRED" | jq '.summary.declared_modules // 0')"
MATCHED="$(printf '%s' "$PRED" | jq '.summary.validated // 0')"
MISSING_N="$(printf '%s' "$PRED" | jq '.summary.missing // 0')"
UNDECLARED="$(printf '%s' "$PRED" | jq '.summary.added_suspicious // 0')"
# SI-7(1): per-component hash coverage — non-library modules and which lack a hash.
INTEG="$(jq -c '[.components[]|select(.type!="library")] | {hashable_total:length, hashed:([.[]|select(.hashes)]|length), unhashed:[.[]|select(.hashes|not)|.name]}' "$SBOM")"
# CISA License/Software-ID, S2C2F SCA-2: third-party components (marked edk2:vendored)
# must carry purl + license. First-party edk2 FFS modules lack the marker and are
# excluded by construction, not by a loosened threshold.
THIRDPARTY="$(jq -c '[.components[]|select(any(.properties[]?; .name=="edk2:vendored" and .value=="true"))] | {total:length, missing:[.[]|select((.purl|not) or (.licenses|not))|.name]}' "$SBOM")"
# evidence-chain-bound: the SLSA provenance subject. CI sets PROVENANCE_SUBJECT (the digest
# gh attestation verify confirmed the provenance covers). The offline demo has no such
# attestation; DEV_ASSUME_CHAIN=1 binds it to the SBOM digest (warned).
PROVENANCE_SUBJECT="${PROVENANCE_SUBJECT:-}"
if [ -z "$PROVENANCE_SUBJECT" ] && [ "${DEV_ASSUME_CHAIN:-0}" = "1" ]; then
  PROVENANCE_SUBJECT="sha256:$SBOM_HASH"; CHAIN_ASSUMED=1
fi
if [ -n "$GRYPE_JSON" ] && [ -f "$GRYPE_JSON" ]; then
  CVE="$(jq '[.matches[]? | {id:.vulnerability.id, component:.artifact.name, severity:(.vulnerability.severity|ascii_upcase)}] | unique' "$GRYPE_JSON")"
else
  CVE='[]'
fi

jq -n --arg sig "$SIG" --arg sh "$SBOM_HASH" --arg sd "$SUBJECT_DIGEST" \
      --arg b "$EFFECTIVE_BUILDER" --arg r "$REPO" --argjson present "$PRESENT" \
      --argjson clean "$CLEAN" --argjson pred "$PRED" --argjson cve "$CVE" \
      --arg slsa "$SLSA_VERIFIED" --arg chipsec "$CHIPSEC_PASSED" --argjson slsa_level "$SLSA_LEVEL" \
      --argjson integ "$INTEG" --argjson declared "$DECLARED" --argjson matched "$MATCHED" \
      --argjson missing_n "$MISSING_N" --argjson undeclared "$UNDECLARED" --argjson thirdparty "$THIRDPARTY" \
      --argjson buildtools "$BUILDTOOLS" --arg provsub "$PROVENANCE_SUBJECT" '{
  sbom:        {present:$present, hash:("sha256:"+$sh), integrity:$integ, thirdparty:$thirdparty},
  attestation: {subject_digest:(if $sd=="" then "" else "sha256:"+$sd end)},
  signature:   {verified:($sig=="true"), identity:$b},
  provenance:  {builder_id:$b, source_repo:$r, slsa_verified:($slsa=="true"), slsa_level:$slsa_level, subject_digest:$provsub},
  reconcile:   {clean:$clean, missing:($pred.missing // []), added:($pred.added // []), modified:($pred.modified // []), declared:$declared, matched:$matched, missing_count:$missing_n, undeclared_observed:$undeclared},
  cve:         {findings:$cve},
  chipsec:     {critical_passed:($chipsec=="true")},
  build_tools: {present:$buildtools.present, signature_verified:$buildtools.signature_verified, all_pinned:$buildtools.all_pinned, unpinned:$buildtools.unpinned}
}' > "$OUT"

echo "   builder_id=$EFFECTIVE_BUILDER"
[ -n "$SIGNER_ID" ] || [ "${DEV_ASSUME_IDENTITY:-0}" != "1" ] || \
  echo "   ⚠ DEV_ASSUME_IDENTITY=1 — builder identity ASSUMED, not cryptographically verified (CI keyless verifies it for real)"
[ "${SLSA_ASSUMED:-0}" != "1" ] || \
  echo "   ⚠ DEV_ASSUME_SLSA=1 — SLSA L2 provenance ASSUMED for local demo, not platform-verified (CI verifies it via gh attestation verify)"
[ "${BUILDTOOLS_ASSUMED:-0}" != "1" ] || \
  echo "   ⚠ DEV_ASSUME_BUILDTOOLS=1 — build-tools signature ASSUMED for local demo, not verified (CI verifies it via cosign verify-blob of the build-tools bundle)"
[ "${CHAIN_ASSUMED:-0}" != "1" ] || \
  echo "   ⚠ DEV_ASSUME_CHAIN=1 — provenance subject ASSUMED = SBOM digest for local demo (CI extracts it from the verified attestation)"
