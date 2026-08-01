#!/usr/bin/env bash
# OSS-lane deploy gate: evaluate the firmware.deploy policy against a gate-input JSON.
# Exit 0 = ALLOW (deploy), non-zero = DENY (block), with reasons.
#
#   ./gate.sh <gate-input.json>
#   VSA_OUT=out/vsa.intoto.json ./gate.sh <gate-input.json>   # also emit the VSA
#
# The gate input is produced upstream by verifying the signed attestation
# (cosign verify-attestation), the reconcile verdict, and the CVE scan.
#
# Output: per-fact verifier reports (Ratify-style, each tagged with the
# framework controls it satisfies) + a SLSA Verification Summary Attestation.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPA="${OPA:-$HERE/../bin/opa}"
POLICY="$HERE/policy"
INPUT="${1:?usage: gate.sh <gate-input.json>}"
VSA_OUT="${VSA_OUT:-}"   # optional: path to write the VSA in-toto statement

[ -x "$OPA" ] || { echo "opa not found at $OPA" >&2; exit 2; }

# load only the deploy policy + its data (NOT the whole dir — testdata/ and other packages would collide)
result="$("$OPA" eval -I -f json \
  -d "$POLICY/firmware.rego" -d "$POLICY/data.json" -d "$POLICY/cve-allowlist.json" \
  'data.firmware.deploy' < "$INPUT")"

val="$(printf '%s' "$result" | jq -c '.result[0].expressions[0].value')"
allow="$(printf '%s' "$val" | jq -r '.allow')"

# --- verifier reports (framework-tagged) ---
echo "  verifier reports ($(basename "$INPUT")):"
printf '%s' "$val" | jq -r '
  .verifier_reports[]
  | "   \(if .isSuccess then "✅" else "⛔" end) \(.name): \(.message)  [\(.controls | join(", "))]"'

# --- emit the VSA (in-toto Statement wrapping the SLSA VSA predicate) ---
subject_digest="$(jq -r '.attestation.subject_digest // "sha256:unknown"' "$INPUT")"
alg="${subject_digest%%:*}"; hex="${subject_digest#*:}"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
vsa_stmt="$(printf '%s' "$val" | jq -c --arg alg "$alg" --arg hex "$hex" --arg ts "$ts" '
  {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [ { "name": .vsa_predicate.resourceUri, "digest": { ($alg): $hex } } ],
    "predicateType": "https://slsa.dev/verification_summary/v1",
    "predicate": (.vsa_predicate + { "timeVerified": $ts })
  }')"
if [ -n "$VSA_OUT" ]; then
  mkdir -p "$(dirname "$VSA_OUT")"
  printf '%s\n' "$vsa_stmt" | jq . > "$VSA_OUT"
  echo "   → VSA written to $VSA_OUT"
fi

if [ "$allow" = "true" ]; then
  echo "✅ ALLOW — $(basename "$INPUT")  (VSA: PASSED, verifiedLevels=[SLSA_BUILD_LEVEL_1])"
  exit 0
fi

echo "⛔ DENY — $(basename "$INPUT")  (VSA: FAILED)"
printf '%s' "$val" | jq -r '.deny // [] | .[]' | sed 's/^/   • /'
exit 1
