#!/usr/bin/env bash
# F5: prove the GATE blocks when the REAL evidence is bad — not just that the rego denies fixtures.
# Reuses the already-produced signed bundle, runs the real assembler, and asserts deploy/block.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
IN="$ROOT/inputs"
OPA="${OPA:-$ROOT/bin/opa}"
BUNDLE="$IN/sbom.att.bundle"
# builder identity + source repo come from the single source of truth (data.json)
export BUILDER_ID="${BUILDER_ID:-$(jq -r '.expected.builder_id' "$ROOT/oss-lane/policy/data.json")}"
export SOURCE_REPO="${SOURCE_REPO:-$(jq -r '.expected.source_repo' "$ROOT/oss-lane/policy/data.json")}"

[ -f "$BUNDLE" ] || { echo "SKIP: no signed bundle (run attest first)"; exit 0; }
[ -f "$IN/grype.json" ] || echo '{"matches":[]}' > "$IN/grype.json"
# E7 build-tools SBOM: produce it so the build-tools-signed gate has a fact to consume; local run
# can't verify its keyless signature, so DEV_ASSUME_BUILDTOOLS=1 DEV_ASSUME_CHAIN=1 (as in the offline demo).
[ -f "$IN/build-tools.cdx.json" ] || "$ROOT/oss-lane/build-tools-sbom.sh" "$IN/build-tools.cdx.json" >/dev/null 2>&1
fail=0

run_case() { # <name> <sbom-file> <expect allow|deny>
  SBOM="$2" BUNDLE="$BUNDLE" SIG=true GRYPE_JSON="$IN/grype.json" \
    OUT="/tmp/neg-gate.json" DEV_ASSUME_IDENTITY=1 DEV_ASSUME_SLSA=1 CHIPSEC_JSON="$IN/chipsec.json" \
    BUILD_TOOLS_JSON="$IN/build-tools.cdx.json" DEV_ASSUME_BUILDTOOLS=1 DEV_ASSUME_CHAIN=1 \
    bash "$ROOT/oss-lane/assemble-gate-input.sh" >/dev/null 2>&1
  OPA="$OPA" "$ROOT/oss-lane/gate.sh" /tmp/neg-gate.json >/dev/null 2>&1; rc=$?
  got=allow; [ "$rc" -ne 0 ] && got=deny
  if [ "$got" = "$3" ]; then printf 'PASS  %-26s -> %s\n' "$1" "$3"
  else printf 'FAIL  %-26s expected %s, got %s\n' "$1" "$3" "$got"; fail=1; fi
}

echo "== in-pipeline negative tests (real evidence) =="
# baseline: the genuinely-signed SBOM deploys
run_case "unmodified-sbom" "$IN/sbom.cdx.json" allow
# tamper the SBOM AFTER signing -> its digest no longer matches the signed subject -> must block
jq '.metadata.timestamp = "1999-01-01T00:00:00Z"' "$IN/sbom.cdx.json" > /tmp/sbom-tampered.json
run_case "tampered-after-signing" "/tmp/sbom-tampered.json" deny
echo "================================================"
[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
