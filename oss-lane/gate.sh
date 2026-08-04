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

# Distinguish a POLICY ERROR (rego typo / undefined) from a legitimate DENY.
# On error opa returns value=null (or embeds .errors); without this guard the
# gate would fail closed but print zero reasons — a silent, undiagnosable block.
if [ -z "$val" ] || [ "$val" = "null" ]; then
  echo "⛔ GATE ERROR — policy produced no decision (rego error, not a deny):" >&2
  printf '%s' "$result" | jq -r '(.errors // [])[] | "   • \(.message)"' 2>/dev/null | grep . >&2 \
    || printf '   %s\n' "$result" >&2
  exit 2
fi

allow="$(printf '%s' "$val" | jq -r '.allow')"

# --- verifier reports (framework-tagged) ---
echo "  verifier reports ($(basename "$INPUT")):"
printf '%s' "$val" | jq -r '
  .verifier_reports[]
  | "   \(if .isSuccess then "✅" else "⛔" end) \(.name): \(.message)  [\(.controls | join(", "))]"'

# --- emit the VSA (in-toto Statement wrapping the SLSA VSA predicate) ---
subject_digest="$(jq -r '.attestation.subject_digest // "sha256:unknown"' "$INPUT")"
alg="${subject_digest%%:*}"; hex="${subject_digest#*:}"
# Also carry the FIRMWARE image digest as a subject, so a consumer can verify the
# VSA is about the bytes they hold (the anchor, consumer-side). Empty -> omitted.
fw_digest="$(jq -r '.firmware.sbom_digest // ""' "$INPUT")"
fw_alg="${fw_digest%%:*}"; fw_hex="${fw_digest#*:}"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
vsa_stmt="$(printf '%s' "$val" | jq -c --arg alg "$alg" --arg hex "$hex" --arg ts "$ts" \
  --arg fwalg "$fw_alg" --arg fwhex "$fw_hex" '
  {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": ([ { "name": .vsa_predicate.resourceUri, "digest": { ($alg): $hex } } ]
                + (if $fwhex != "" then [ { "name": "firmware-image", "digest": { ($fwalg): $fwhex } } ] else [] end)),
    "predicateType": "https://slsa.dev/verification_summary/v1",
    "predicate": (.vsa_predicate + { "timeVerified": $ts })
  }')"
if [ -n "$VSA_OUT" ]; then
  mkdir -p "$(dirname "$VSA_OUT")"
  printf '%s\n' "$vsa_stmt" | jq . > "$VSA_OUT"
  echo "   → VSA written to $VSA_OUT"
fi

if [ "$allow" = "true" ]; then
  echo "✅ ALLOW — $(basename "$INPUT")  (VSA: PASSED, verifiedLevels=[SLSA_BUILD_LEVEL_2])"
  exit 0
fi

echo "⛔ DENY — $(basename "$INPUT")  (VSA: FAILED)"
printf '%s' "$val" | jq -r '.deny // [] | .[]' | sed 's/^/   • /'
exit 1
