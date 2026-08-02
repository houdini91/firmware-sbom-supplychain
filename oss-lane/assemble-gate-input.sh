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
# CHIPSEC platform posture (R3): read critical_passed from the CHIPSEC predicate.
CHIPSEC_JSON="${CHIPSEC_JSON:-}"
if [ -n "$CHIPSEC_JSON" ] && [ -f "$CHIPSEC_JSON" ]; then
  CHIPSEC_PASSED="$(jq -r '.critical_passed // false' "$CHIPSEC_JSON")"
else
  CHIPSEC_PASSED="${CHIPSEC_PASSED:-false}"
fi

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
if [ -n "$GRYPE_JSON" ] && [ -f "$GRYPE_JSON" ]; then
  CVE="$(jq '[.matches[]? | {id:.vulnerability.id, component:.artifact.name, severity:(.vulnerability.severity|ascii_upcase)}] | unique' "$GRYPE_JSON")"
else
  CVE='[]'
fi

jq -n --arg sig "$SIG" --arg sh "$SBOM_HASH" --arg sd "$SUBJECT_DIGEST" \
      --arg b "$EFFECTIVE_BUILDER" --arg r "$REPO" --argjson present "$PRESENT" \
      --argjson clean "$CLEAN" --argjson pred "$PRED" --argjson cve "$CVE" \
      --arg slsa "$SLSA_VERIFIED" --arg chipsec "$CHIPSEC_PASSED" '{
  sbom:        {present:$present, hash:("sha256:"+$sh)},
  attestation: {subject_digest:(if $sd=="" then "" else "sha256:"+$sd end)},
  signature:   {verified:($sig=="true")},
  provenance:  {builder_id:$b, source_repo:$r, slsa_verified:($slsa=="true")},
  reconcile:   {clean:$clean, missing:($pred.missing // []), added:($pred.added // []), modified:($pred.modified // [])},
  cve:         {findings:$cve},
  chipsec:     {critical_passed:($chipsec=="true")}
}' > "$OUT"

echo "   builder_id=$EFFECTIVE_BUILDER"
[ -n "$SIGNER_ID" ] || [ "${DEV_ASSUME_IDENTITY:-0}" != "1" ] || \
  echo "   ⚠ DEV_ASSUME_IDENTITY=1 — builder identity ASSUMED, not cryptographically verified (CI keyless verifies it for real)"
[ "${SLSA_ASSUMED:-0}" != "1" ] || \
  echo "   ⚠ DEV_ASSUME_SLSA=1 — SLSA L2 provenance ASSUMED for local demo, not platform-verified (CI verifies it via gh attestation verify)"
