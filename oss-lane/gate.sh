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

[ -x "$OPA" ] || { echo "opa not found at $OPA (run: make bin)" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "jq not found on PATH — required (https://jqlang.github.io/jq/)" >&2; exit 2; }

# load only the deploy policy + its data (NOT the whole dir — testdata/ and other packages would collide)
result="$("$OPA" eval -I -f json \
  -d "$POLICY/firmware.rego" -d "$POLICY/data.json" -d "$POLICY/cve-allowlist.json" -d "$POLICY/initiatives.json" \
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
  | "   \(if .isSuccess then "✅" else "⛔" end) \(.name): \(.message)  [\(.controls | join(", "))]"
    + (if (.isSuccess | not) and (.remediation // "") != "" then "\n      → fix: \(.remediation)" else "" end)'

# --- emit the VSA (in-toto Statement wrapping the standard SLSA VSA predicate) ---
# subject = the FIRMWARE image digest D (the artifact this gate verifies), named
# "firmware-image" so a consumer can bind the VSA to the bytes they hold. D is the
# primary (and only) subject — the evidence is about the firmware, not a JSON file.
# // only substitutes on null, not "" — an empty digest (e.g. a foreign SBOM with no
# metadata.component hash) would otherwise emit an invalid subject {"":""}. Coalesce empty too.
fw_digest="$(jq -r '(.firmware.sbom_digest // "") | if . == "" then "sha256:unknown" else . end' "$INPUT")"
fw_alg="${fw_digest%%:*}"; fw_hex="${fw_digest#*:}"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
vsa_stmt="$(printf '%s' "$val" | jq -c --arg fwalg "$fw_alg" --arg fwhex "$fw_hex" --arg ts "$ts" '
  {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [ { "name": "firmware-image", "digest": { ($fwalg): $fwhex } } ],
    "predicateType": "https://slsa.dev/verification_summary/v1",
    "predicate": (.vsa_predicate + { "timeVerified": $ts })
  }')"
if [ -n "$VSA_OUT" ]; then
  mkdir -p "$(dirname "$VSA_OUT")"
  printf '%s\n' "$vsa_stmt" | jq . > "$VSA_OUT"
  echo "   → VSA written to $VSA_OUT"
fi

if [ "$allow" = "true" ]; then
  echo "✅ ALLOW — $(basename "$INPUT")  (VSA: PASSED, verifiedLevels=[SLSA_BUILD_LEVEL_0] for the firmware subject; evidenceBuildLevel=SLSA_BUILD_LEVEL_2 — the SBOM artifact's build provenance)"
  exit 0
fi

echo "⛔ DENY — $(basename "$INPUT")  (VSA: FAILED)"
printf '%s' "$val" | jq -r '.deny // [] | .[]' | sed 's/^/   • /'
exit 1
