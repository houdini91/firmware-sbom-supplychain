#!/usr/bin/env bash
# Valint lane: sign firmware evidence, then verify compliance policies + a whole framework initiative,
# over the SAME OVMF SBOM the OSS lane uses.
#
# Signing:
#   - default is keyless (sigstore/OIDC) — works on CI and anywhere with network to sigstore.
#   - offline: export VALINT_X509=1 to sign with a local x509 key (no network).
#
# The compliance rules resolve from the scribe-public/sample-policies bundle, which `valint verify`
# auto-clones (verified). --exit-code 1 turns a policy violation into a failing gate.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
IN="$ROOT/inputs"
V="${VALINT:-$HOME/.scribe/bin/valint}"
SBOM="$IN/sbom.cdx.json"

SIGN=(-D)                       # -D: no scribe cloud
if [ "${VALINT_X509:-0}" = "1" ]; then
  mkdir -p "$HERE/.keys"
  [ -f "$HERE/.keys/key.pem" ] || openssl req -x509 -newkey ec \
    -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$HERE/.keys/key.pem" \
    -out "$HERE/.keys/cert.pem" -days 3650 -nodes -subj "/CN=fw-sbom-builder" 2>/dev/null
  SIGN+=(--attest.default x509 --key "$HERE/.keys/key.pem" --cert "$HERE/.keys/cert.pem")
fi

echo "== 1. attest the firmware SBOM (signed evidence) =="
"$V" bom "file:$SBOM" -o attest "${SIGN[@]}"

echo "== 2. attest SLSA provenance evidence =="
"$V" slsa "file:$SBOM" -o attest "${SIGN[@]}" || echo "(slsa evidence step optional)"

echo "== 3. verify the custom firmware-composition policy =="
"$V" verify "file:$SBOM" -i attest-cyclonedx-json \
  --rule "$HERE/policies/firmware-composition.yaml" --exit-code 1 -D

echo "== 4. verify against a compliance FRAMEWORK initiative (SLSA L2) =="
"$V" verify "file:$SBOM" -i attest-cyclonedx-json \
  --initiative-name "slsa.l2" --exit-code 1 -D
