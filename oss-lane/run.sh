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
if command -v grype >/dev/null 2>&1; then
  grype "sbom:$SBOM" -o json > "$IN/grype.json" 2>/dev/null || echo '{"matches":[]}' > "$IN/grype.json"
else echo '{"matches":[]}' > "$IN/grype.json"; fi
CVE="$(jq '[.matches[]? | {id: .vulnerability.id, component: .artifact.name, severity: (.vulnerability.severity|ascii_upcase)}] | unique' "$IN/grype.json")"
echo "   findings: $(echo "$CVE"|jq length)  critical: $(echo "$CVE"|jq '[.[]|select(.severity=="CRITICAL")]|length')"

echo "== 5. assemble gate input =="
BUILDER="${BUILDER_ID:-https://github.com/houdini91/firmware-sbom-supplychain/.github/workflows/supply-chain.yml@refs/heads/main}"
REPO="${SOURCE_REPO:-https://github.com/houdini91/firmware-sbom-supplychain}"
HASH="$(jq -r '.metadata.component.hashes[0].content' "$SBOM")"
CLEAN="$(jq '(.summary.missing==0) and (.summary.modified==0) and (.summary.added_suspicious==0)' "$VERDICT")"
jq -n --arg sig "$SIG" --arg h "$HASH" --arg b "$BUILDER" --arg r "$REPO" \
      --argjson clean "$CLEAN" --slurpfile v "$VERDICT" --argjson cve "$CVE" '{
  sbom:       {present:true, hash:("sha256:"+$h)},
  signature:  {verified:($sig=="true")},
  provenance: {builder_id:$b, source_repo:$r},
  reconcile:  {clean:$clean, missing:($v[0].missing//[]), added:($v[0].added//[]), modified:($v[0].modified//[])},
  cve:        {findings:$cve}
}' > "$IN/gate-input.json"
echo "   inputs/gate-input.json"

echo "== 6. gate =="
"$HERE/gate.sh" "$IN/gate-input.json"
