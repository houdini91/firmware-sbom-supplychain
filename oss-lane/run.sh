#!/usr/bin/env bash
# OSS lane, end to end, over the real OVMF SBOM + reconcile verdict:
#   1 keypair  2 cosign attest-blob (predicate = reconcile verdict)
#   3 cosign verify-blob-attestation  4 grype CVE scan  5 assemble gate input  6 OPA gate
#
# Local demo signs with a key. The CI workflow does the same steps with KEYLESS OIDC
# (cosign / attest-build-provenance) and passes the runner's provenance in via env.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
IN="$ROOT/inputs"; BIN="$ROOT/bin"
OPA="${OPA:-$BIN/opa}"; COSIGN="${COSIGN:-cosign}"
KEYS="$HERE/.keys"
SBOM="$IN/sbom.cdx.json"; VERDICT="$IN/reconcile-verdict.json"
TYPE="https://firmware-sbom-supplychain/reconcile/v1"
export COSIGN_PASSWORD=""

echo "== 1. keypair =="
if [ ! -f "$KEYS/cosign.key" ]; then mkdir -p "$KEYS"; ( cd "$KEYS" && "$COSIGN" generate-key-pair >/dev/null 2>&1 ); fi
echo "   $KEYS/cosign.key"

echo "== 2. attest-blob (sign SBOM; predicate = reconcile verdict) =="
"$COSIGN" attest-blob --yes --key "$KEYS/cosign.key" --predicate "$VERDICT" --type "$TYPE" \
  --bundle "$IN/sbom.att.bundle" "$SBOM" >/dev/null 2>&1
echo "   bundle: inputs/sbom.att.bundle"

echo "== 3. verify-blob-attestation =="
if "$COSIGN" verify-blob-attestation --key "$KEYS/cosign.pub" --type "$TYPE" \
     --bundle "$IN/sbom.att.bundle" "$SBOM" >/dev/null 2>&1; then SIG=true; else SIG=false; fi
echo "   signature.verified = $SIG"

echo "== 4. CVE scan (grype over the SBOM) =="
# F6: fail closed — a missing/broken scanner is NOT "found nothing". A scanner that produces a valid
# matches array is trusted even if it exits non-zero (e.g. DB-staleness warning). SKIP_CVE=1 disables loudly.
if [ "${SKIP_CVE:-0}" = "1" ]; then
  echo "   ⚠ SKIP_CVE=1 → CVE gate DISABLED (not a clean scan; findings forced empty)"
  echo '{"matches":[]}' > "$IN/grype.json"
elif command -v grype >/dev/null 2>&1 \
     && grype "sbom:$SBOM" -o json > "$IN/grype.json" 2>/dev/null \
     && jq -e 'has("matches")' "$IN/grype.json" >/dev/null 2>&1; then
  : # scanned OK
else
  echo "   ERROR: CVE scan unavailable (grype missing or DB unusable). Fix grype, or set SKIP_CVE=1 to disable." >&2
  exit 3
fi
CVE="$(jq '[.matches[]? | {id: .vulnerability.id, component: .artifact.name, severity: (.vulnerability.severity|ascii_upcase)}] | unique' "$IN/grype.json")"
echo "   findings: $(echo "$CVE"|jq length)  critical: $(echo "$CVE"|jq '[.[]|select(.severity=="CRITICAL")]|length')"

echo "== 5. extract SIGNED evidence + assemble gate input =="
# F3/F4: trust the reconcile verdict + subject digest ONLY from the VERIFIED attestation, not the
# on-disk file. Compute the SBOM's real digest now and bind it to the signed subject in the policy.
if [ "$SIG" = "true" ]; then
  STMT="$(jq -r '.base64Signature' "$IN/sbom.att.bundle" | base64 -d | jq -r '.payload' | base64 -d)"
  SUBJECT_DIGEST="$(printf '%s' "$STMT" | jq -r '.subject[0].digest.sha256 // ""')"
  PRED="$(printf '%s' "$STMT" | jq -c '.predicate')"
else
  SUBJECT_DIGEST=""; PRED='{}'
fi
SBOM_HASH="$(sha256sum "$SBOM" | cut -d' ' -f1)"           # actual bytes on disk
PRESENT="$(jq '(.components|length) > 0' "$SBOM")"          # F4: real, not a constant
CLEAN="$(printf '%s' "$PRED" | jq '((.summary.missing // 1)==0) and ((.summary.modified // 1)==0) and ((.summary.added_suspicious // 1)==0)')"
BUILDER="${BUILDER_ID:-https://github.com/houdini91/firmware-sbom-supplychain/.github/workflows/supply-chain.yml@refs/heads/main}"
REPO="${SOURCE_REPO:-https://github.com/houdini91/firmware-sbom-supplychain}"
jq -n --arg sig "$SIG" --arg sh "$SBOM_HASH" --arg sd "$SUBJECT_DIGEST" \
      --arg b "$BUILDER" --arg r "$REPO" --argjson present "$PRESENT" \
      --argjson clean "$CLEAN" --argjson pred "$PRED" --argjson cve "$CVE" '{
  sbom:        {present:$present, hash:("sha256:"+$sh)},
  attestation: {subject_digest:(if $sd=="" then "" else "sha256:"+$sd end)},
  signature:   {verified:($sig=="true")},
  provenance:  {builder_id:$b, source_repo:$r},
  reconcile:   {clean:$clean, missing:($pred.missing // []), added:($pred.added // []), modified:($pred.modified // [])},
  cve:         {findings:$cve}
}' > "$IN/gate-input.json"
echo "   subject=sha256:${SUBJECT_DIGEST:0:12}…  sbom=sha256:${SBOM_HASH:0:12}…  clean=$CLEAN  present=$PRESENT"

echo "== 6. gate =="
"$HERE/gate.sh" "$IN/gate-input.json"
