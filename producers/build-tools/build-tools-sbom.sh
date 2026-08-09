#!/usr/bin/env bash
# Build-tools SBOM: inventory the *toolchain* that produces/verifies the firmware SBOM — the SHA-pinned
# CI actions and the pipeline tools — as a CycloneDX SBOM. This closes the product-SBOM vs build-SBOM gap:
# the actions/tools ARE supply chain, so they should be inventoried, signed, and gated too (and it turns
# the A1 action SHA-pins into attested evidence, not just YAML).
#
#   ./build-tools-sbom.sh [out.cdx.json]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
WF="$ROOT/.github/workflows/supply-chain.yml"
OUT="${1:-$ROOT/inputs/build-tools.cdx.json}"

# 1) CI actions, SHA-pinned, from the workflow:  uses: owner/repo@<40-hex> # tag
actions="$(grep -oE 'uses:[[:space:]]*[A-Za-z0-9._/-]+@[0-9a-f]{40}([[:space:]]*#[[:space:]]*[^ ]+)?' "$WF" \
  | sed 's/uses:[[:space:]]*//' | sort -u \
  | jq -Rn '[ inputs
      | capture("(?<repo>[^@]+)@(?<sha>[0-9a-f]{40})([[:space:]]*#[[:space:]]*(?<tag>.+))?")
      | { type:"application", name:.repo, version:(.tag // .sha[0:12]),
          purl:("pkg:github/\(.repo)@\(.sha)"),
          hashes:[{alg:"SHA-1", content:.sha}],
          properties:[{name:"pipeline:role", value:"ci-action"}] } ]')"

# 2) pipeline tools + versions (best-effort; empty version if the tool is absent locally)
ver() { command -v "$1" >/dev/null 2>&1 && ("${@:2}" 2>/dev/null | grep -oiE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1) || true; }
tools="$(jq -n \
  --arg cosign "$(ver cosign cosign version)" \
  --arg opa    "$( { opa version 2>/dev/null || "$ROOT/bin/opa" version 2>/dev/null; } | grep -oiE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" \
  --arg grype  "$(ver grype grype version)" \
  --arg valint "$( [ -x "$HOME/.scribe/bin/valint" ] && "$HOME/.scribe/bin/valint" --version 2>/dev/null | grep -oiE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" \
  --arg jq     "$(jq --version 2>/dev/null | grep -oiE '[0-9]+\.[0-9]+' | head -1)" '
  [ {n:"cosign",u:"pkg:github/sigstore/cosign", v:$cosign},
    {n:"opa",   u:"pkg:github/open-policy-agent/opa", v:$opa},
    {n:"grype", u:"pkg:github/anchore/grype", v:$grype},
    {n:"valint",u:"pkg:github/scribe-public/valint", v:$valint},
    {n:"jq",    u:"pkg:generic/jq", v:$jq} ]
  | map(select(.v != ""))
  | map({type:"application", name:.n, version:.v, purl:("\(.u)@\(.v)"),
         properties:[{name:"pipeline:role", value:"tool"}]}) ')"

jq -n --argjson actions "$actions" --argjson tools "$tools" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
  bomFormat:"CycloneDX", specVersion:"1.6", version:1,
  metadata:{
    timestamp:$ts,
    component:{ type:"application", name:"uefi-supply-chain-pipeline",
                "bom-ref":"pipeline", description:"CI toolchain that builds & verifies the firmware SBOM" },
    properties:[{name:"sbom:kind", value:"build-tools"}]
  },
  components: (($actions + $tools) | map(. + {"bom-ref": .purl}))
}' > "$OUT"

echo "wrote $OUT"
jq -r '"components: \(.components|length)  (actions: \([.components[]|select(.properties[]?.value=="ci-action")]|length), tools: \([.components[]|select(.properties[]?.value=="tool")]|length))"' "$OUT"
jq -r '.components[] | "  \(.name)  \(.version)  \(.purl)"' "$OUT"
