#!/usr/bin/env bash
# Real compliance verification over the firmware CycloneDX SBOM. No signing, no network — runs a full
# cycle locally so the policy can be developed and tested before it ever hits CI.
#
#   ./verify-compliance.sh [path/to/sbom.cdx.json]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OPA="${OPA:-$ROOT/bin/opa}"
SBOM="${1:-$ROOT/inputs/sbom.cdx.json}"
POL="$HERE/policy/compliance"

[ -x "$OPA" ] || { echo "opa not found at $OPA" >&2; exit 2; }
[ -f "$SBOM" ] || { echo "sbom not found: $SBOM" >&2; exit 2; }

echo "== NTIA / BSI minimum-elements — $(basename "$SBOM") =="
r="$("$OPA" eval -I -f json -d "$POL/ntia.rego" 'data.firmware.compliance.ntia.report' < "$SBOM")"
printf '%s' "$r" | jq -r '.result[0].expressions[0].value | @json' | jq -r '
  "  components      : \(.total_components)",
  "  complete        : \(.complete)",
  "  incomplete      : \(.incomplete)",
  "  field coverage  : name=\(.coverage.name) version=\(.coverage.version) unique_id=\(.coverage.unique_id) supplier=\(.coverage.supplier)",
  "  sbom author     : \(.sbom_author)",
  "  sbom timestamp  : \(.sbom_timestamp)",
  "  dependencies    : \(.has_dependencies)",
  "  NTIA compliant  : \(.ntia_compliant)"'

echo "== top incomplete components (missing required fields) =="
"$OPA" eval -I -f json -d "$POL/ntia.rego" 'data.firmware.compliance.ntia.incomplete' < "$SBOM" \
  | jq -r '.result[0].expressions[0].value | sort_by(.ref) | .[0:8][] | "  \(.ref)  missing: \(.missing|join(", "))"'
