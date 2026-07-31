#!/usr/bin/env bash
# OSS-lane deploy gate: evaluate the firmware.deploy policy against a gate-input JSON.
# Exit 0 = ALLOW (deploy), non-zero = DENY (block), with reasons.
#
#   ./gate.sh <gate-input.json>
#
# The gate input is produced upstream by verifying the signed attestation
# (cosign verify-attestation), the reconcile verdict, and the CVE scan.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPA="${OPA:-$HERE/../bin/opa}"
POLICY="$HERE/policy"
INPUT="${1:?usage: gate.sh <gate-input.json>}"

[ -x "$OPA" ] || { echo "opa not found at $OPA" >&2; exit 2; }

# load only the deploy policy + its data (NOT the whole dir — testdata/ and other packages would collide)
result="$("$OPA" eval -I -f json \
  -d "$POLICY/firmware.rego" -d "$POLICY/data.json" -d "$POLICY/cve-allowlist.json" \
  'data.firmware.deploy' < "$INPUT")"
allow="$(printf '%s' "$result" | jq -r '.result[0].expressions[0].value.allow')"

if [ "$allow" = "true" ]; then
  echo "✅ ALLOW — $(basename "$INPUT")"
  exit 0
fi

echo "⛔ DENY — $(basename "$INPUT")"
printf '%s' "$result" | jq -r '.result[0].expressions[0].value.deny // [] | .[]' | sed 's/^/   • /'
exit 1
