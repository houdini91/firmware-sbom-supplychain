#!/usr/bin/env bash
# Interop step (operator/demo-side): convert the CycloneDX SBOM to SPDX with
# protobom's sbom-convert. This is deliberately NOT part of the edk2 generator
# (which stays CycloneDX-only, no new build dependency) — SPDX conversion is a
# downstream consumer concern. See DESIGN.md ("only the generator" upstream).
#
#   ./interop/to-spdx.sh [in.cdx.json] [out.spdx.json]
#
# Install the converter once:  go install github.com/protobom/sbom-convert@latest
# (GOBIN=./bin so it lands next to bin/opa; bin/ is gitignored).
#
# Note: CDX->SPDX is not fully lossless (protobom maps what maps); the SPDX is an
# interop artifact, the CycloneDX remains the canonical SBOM.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CONV="${SBOM_CONVERT:-$ROOT/bin/sbom-convert}"
IN="${1:-$ROOT/inputs/sbom.cdx.json}"
OUT="${2:-$ROOT/inputs/sbom.spdx.json}"

[ -x "$CONV" ] || { echo "sbom-convert not found at $CONV — run: GOBIN=$ROOT/bin go install github.com/protobom/sbom-convert@latest" >&2; exit 2; }
[ -f "$IN" ]   || { echo "input CDX not found: $IN" >&2; exit 2; }

"$CONV" convert "$IN" -f spdx -o "$OUT"
echo "✓ SPDX ($("$CONV" version 2>/dev/null | head -1 || echo protobom)) written to ${OUT#$ROOT/}"
