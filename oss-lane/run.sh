#!/usr/bin/env bash
# OSS lane, end to end, over the real OVMF SBOM + reconcile verdict:
#   1 keypair  2 cosign attest-blob (predicate = reconcile verdict)
#   3 cosign verify-blob-attestation  4 grype CVE scan  5 assemble gate input  6 OPA gate
#
# Local demo signs with a key. The CI workflow does the same steps with KEYLESS OIDC
# (cosign keyless) and extracts the real signer identity in the shared assembler.
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

echo "== 5. assemble gate input from VERIFIED evidence (shared assembler) =="
# Local key-signing carries no cert identity, so builder_id can't be cryptographically verified here:
# default to DEV_ASSUME_IDENTITY (loudly warned). CI keyless extracts a real identity instead.
SBOM="$SBOM" BUNDLE="$IN/sbom.att.bundle" SIG="$SIG" \
  BUILDER_ID="${BUILDER_ID:-https://github.com/houdini91/firmware-sbom-supplychain/.github/workflows/supply-chain.yml@refs/heads/main}" \
  SOURCE_REPO="${SOURCE_REPO:-https://github.com/houdini91/firmware-sbom-supplychain}" \
  GRYPE_JSON="$IN/grype.json" OUT="$IN/gate-input.json" \
  DEV_ASSUME_IDENTITY="${DEV_ASSUME_IDENTITY:-1}" \
  DEV_ASSUME_SLSA="${DEV_ASSUME_SLSA:-1}" \
  bash "$HERE/assemble-gate-input.sh"

echo "== 6. gate =="
"$HERE/gate.sh" "$IN/gate-input.json"
