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
"$OPA" eval -I -f json -d "$POL/ntia.rego" 'data.firmware.compliance.ntia.report' < "$SBOM" \
  | jq -r '.result[0].expressions[0].value |
  "  components          : \(.total_components)",
  "  NTIA compliant      : \(.ntia_compliant)   (incomplete: \(.incomplete_components))",
  "  external id (purl/cpe): \(.identifiers_purl_cpe.n)/\(.total_components)  (\(.identifiers_purl_cpe.pct)%)   <- CVE-mappable",
  "  real version        : \(.version.real)/\(.total_components)   (\(.version.placeholder) are the build-label placeholder)",
  "  supplier            : \(.supplier.n)/\(.total_components)  (\(.supplier.pct)%)",
  "  hashes              : \(.hashes.n)/\(.total_components)  (\(.hashes.pct)%)",
  "  licenses            : \(.licenses.n)/\(.total_components)  (\(.licenses.pct)%)",
  "  in dependency graph : \(.dependency_graph_coverage.in_graph)/\(.total_components)  (\(.dependency_graph_coverage.pct)%)",
  "  sbom author/time    : \(.sbom_author) / \(.sbom_timestamp)",
  "  primary component   : supplier=\(.primary_component.has_supplier) id=\(.primary_component.has_external_id) hash=\(.primary_component.has_hash) license=\(.primary_component.has_license)"'

echo "== top incomplete components (missing required fields) =="
"$OPA" eval -I -f json -d "$POL/ntia.rego" 'data.firmware.compliance.ntia.incomplete' < "$SBOM" \
  | jq -r '.result[0].expressions[0].value | sort_by(.ref) | .[0:8][] | "  \(.ref)  missing: \(.missing|join(", "))"'
