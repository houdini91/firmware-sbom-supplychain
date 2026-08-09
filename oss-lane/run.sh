#!/usr/bin/env bash
# OSS lane, end to end, over the real OVMF SBOM + reconcile verdict:
#   1 keypair  2 cosign attest-blob (predicate = reconcile verdict)
#   3 cosign verify-blob-attestation  4 grype CVE scan  5 assemble gate input  6 OPA gate
#
# Local demo signs with a key. The CI workflow does the same steps with KEYLESS OIDC
# (cosign keyless) and extracts the real signer identity in the shared assembler.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
IN="$ROOT/inputs"; BIN="$ROOT/bin"
OPA="${OPA:-$BIN/opa}"
# prefer the pinned, SHA-verified bin/ tools (make bin) over whatever's on PATH
COSIGN="${COSIGN:-$([ -x "$BIN/cosign" ] && echo "$BIN/cosign" || echo cosign)}"
GRYPE="${GRYPE:-$([ -x "$BIN/grype" ] && echo "$BIN/grype" || echo grype)}"
# preflight: fail with an actionable message, not a cryptic set -e abort mid-step
for tool in "$COSIGN" "$GRYPE"; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: '$tool' not found on PATH — this lane needs it (see requirements.txt); set the matching env var or install it." >&2; exit 2; }
done
KEYS="$HERE/.keys"
SBOM="$IN/sbom.cdx.json"; VERDICT="$IN/reconcile-verdict.json"
TYPE="https://firmware-sbom-supplychain/reconcile/v1"
BI_TYPE="https://firmware-sbom-supplychain/byte-integrity/v1"
BH_TYPE="https://firmware-sbom-supplychain/binary-hardening/v1"
export COSIGN_PASSWORD=""

echo "== 1. keypair =="
if [ ! -f "$KEYS/cosign.key" ]; then mkdir -p "$KEYS"; ( cd "$KEYS" && "$COSIGN" generate-key-pair >/dev/null 2>&1 ); fi
echo "   $KEYS/cosign.key"

echo "== 2. attest-blob (sign SBOM; predicate = reconcile verdict) =="
"$COSIGN" attest-blob --yes --key "$KEYS/cosign.key" --predicate "$VERDICT" --type "$TYPE" \
  --bundle "$IN/sbom.att.bundle" "$SBOM" >/dev/null
echo "   bundle: inputs/sbom.att.bundle"

echo "== 3. verify-blob-attestation =="
if "$COSIGN" verify-blob-attestation --key "$KEYS/cosign.pub" --type "$TYPE" \
     --bundle "$IN/sbom.att.bundle" "$SBOM" >/dev/null 2>&1; then SIG=true; else SIG=false; fi
echo "   signature.verified = $SIG"

echo "== 3b. attest byte-integrity + binary-hardening (subject #1 = firmware D) =="
# SECURITY: byte-integrity/binary-hardening were the ONLY image-derived verdicts not wrapped in a
# signed, firmware-D-anchored attestation — so an attacker with inputs/ write (no signing key) could
# rewrite byte-integrity.json to modified:0 and the gate believed it. Now signed the SAME way reconcile
# is in CI: wrap.sh builds a MULTI-SUBJECT in-toto Statement (subject #1 firmware-image=D, subject #2
# the verdict file's own H), attest-blob --statement signs it AS-IS (LEGACY bundle, so the assembler can
# decode the DSSE + read subject #1 D). The assembler reads the verdict FROM this bundle, not the loose file.
#
# attest-blob --statement needs cosign >= 2.6.0 (the version supply-chain.yml pins). If the local cosign
# predates it (bin/ pins 2.5.2), fall back to the repo's established synth idiom (the same wrap.sh Statement
# in a legacy .base64Signature envelope that tests/pipeline-negative.sh builds) so `make demo` still
# exercises the D-anchored consumption path. The real signature + keyless identity are produced AND verified
# in CI (supply-chain.yml pins cosign 2.6.0 and runs cosign verify-blob-attestation on each bundle).
D="$(jq -r '.metadata.component.hashes[]? | select(.alg=="SHA-256") | .content' "$SBOM")"
[ -n "$D" ] || { echo "error: no SHA-256 in metadata.component — cannot anchor byte-integrity/binary-hardening to D" >&2; exit 2; }
COSIGN_HAS_STATEMENT=0
"$COSIGN" attest-blob --help 2>&1 | grep -q -- '--statement' && COSIGN_HAS_STATEMENT=1

attest_evidence() { # <predicate-file> <predicateType> <bound-name> <out-bundle>
  local pred="$1" ptype="$2" name="$3" out="$4"
  local stmt="$IN/${name}.intoto.json"
  # wrap.sh: subject #1 firmware-image=D, subject #2 <name>=H (the predicate is the verdict itself)
  "$ROOT/producers/wrap.sh" "$pred" "$ptype" "$D" "$pred" "$name" > "$stmt"
  if [ "$COSIGN_HAS_STATEMENT" = "1" ]; then
    "$COSIGN" attest-blob --yes --key "$KEYS/cosign.key" \
      --statement "$stmt" --bundle "$out" >/dev/null
    # subject #1 is the firmware image D, not present locally -> --check-claims=false (signature only);
    # a deploy-time verifier holding the real .fd checks the subject-digest claim. Tampered bundle -> abort.
    "$COSIGN" verify-blob-attestation --key "$KEYS/cosign.pub" --type "$ptype" \
      --check-claims=false --bundle "$out" >/dev/null 2>&1 \
      || { echo "error: cosign verify of $out FAILED (tampered bundle) — aborting" >&2; exit 4; }
    echo "   signed + verified $out (subject #1 = firmware D)"
  else
    # Legacy synth: wrap the Statement in the .base64Signature DSSE envelope the assembler decodes.
    python3 - "$stmt" "$out" <<'PY'
import base64, json, sys
stmt = open(sys.argv[1], "rb").read()
dsse = {"payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(stmt).decode(), "signatures": [{"sig": ""}]}
json.dump({"base64Signature": base64.b64encode(json.dumps(dsse).encode()).decode()}, open(sys.argv[2], "w"))
PY
    echo "   ⚠ this cosign lacks attest-blob --statement (needs >= 2.6.0, which CI pins) — synthesized"
    echo "     an UNSIGNED but D-anchored $out so the demo exercises the signed-consumption path."
    echo "     SECURITY: locally this gives STRUCTURAL-CONSISTENCY only (correct D-binding), NOT crypto"
    echo "     assurance — the real keyless signature + verify-blob-attestation gate runs in CI (cosign 2.6.0)."
  fi
}
attest_evidence "$IN/byte-integrity.json"   "$BI_TYPE" byte-integrity.json   "$IN/byte-integrity.att.bundle"
attest_evidence "$IN/binary-hardening.json" "$BH_TYPE" binary-hardening.json "$IN/binary-hardening.att.bundle"

echo "== 4. CVE scan (grype over the SBOM) =="
# F6: fail closed — a missing/broken scanner is NOT "found nothing". A scanner that produces a valid
# matches array is trusted even if it exits non-zero (e.g. DB-staleness warning). SKIP_CVE=1 disables loudly.
if [ "${SKIP_CVE:-0}" = "1" ]; then
  echo "   ⚠ SKIP_CVE=1 → CVE gate DISABLED (not a clean scan; findings forced empty)"
  echo '{"matches":[]}' > "$IN/grype.json"
elif command -v "$GRYPE" >/dev/null 2>&1 \
     && "$GRYPE" "sbom:$SBOM" -o json > "$IN/grype.json" 2>/dev/null \
     && jq -e 'has("matches")' "$IN/grype.json" >/dev/null 2>&1; then
  : # scanned OK
else
  echo "   ERROR: CVE scan unavailable (grype missing or DB unusable). Fix grype, or set SKIP_CVE=1 to disable." >&2
  exit 3
fi
CVE="$(jq '[.matches[]? | {id: .vulnerability.id, component: .artifact.name, severity: (.vulnerability.severity|ascii_upcase)}] | unique' "$IN/grype.json")"
echo "   findings: $(echo "$CVE"|jq length)  critical: $(echo "$CVE"|jq '[.[]|select(.severity=="CRITICAL")]|length')"

echo "== 5. build-tools SBOM (inventory the CI toolchain, SHA-pinned) =="
# E7: inventory the actions/tools that build & verify the SBOM so the build-tools-signed gate
# (SSDF PO.3.2 / S2C2F REB-3) has a fact to consume. Local key-signing carries no cert identity,
# so the signature can't be verified here: opt into DEV_ASSUME_BUILDTOOLS (loudly warned).
"$ROOT/producers/build-tools/build-tools-sbom.sh" "$IN/build-tools.cdx.json"

echo "== 6. assemble gate input from VERIFIED evidence (shared assembler) =="
# Local key-signing carries no cert identity, so builder_id can't be cryptographically verified here:
# default to DEV_ASSUME_IDENTITY (loudly warned). CI keyless extracts a real identity instead.
SBOM="$SBOM" BUNDLE="$IN/sbom.att.bundle" SIG="$SIG" \
  BUILDER_ID="${BUILDER_ID:-$(jq -r '.expected.builder_id' "$HERE/policy/data.json")}" \
  SOURCE_REPO="${SOURCE_REPO:-$(jq -r '.expected.source_repo' "$HERE/policy/data.json")}" \
  GRYPE_JSON="$IN/grype.json" OUT="$IN/gate-input.json" \
  DEV_ASSUME_IDENTITY="${DEV_ASSUME_IDENTITY:-1}" \
  DEV_ASSUME_SLSA="${DEV_ASSUME_SLSA:-1}" \
  CHIPSEC_JSON="${CHIPSEC_JSON:-$IN/chipsec.json}" \
  REQUIRE_SIGNED_EVIDENCE=1 \
  BYTE_INTEGRITY_BUNDLE="${BYTE_INTEGRITY_BUNDLE:-$IN/byte-integrity.att.bundle}" \
  BINARY_HARDENING_BUNDLE="${BINARY_HARDENING_BUNDLE:-$IN/binary-hardening.att.bundle}" \
  BYTE_INTEGRITY_JSON="${BYTE_INTEGRITY_JSON:-$IN/byte-integrity.json}" \
  BINARY_HARDENING_JSON="${BINARY_HARDENING_JSON:-$IN/binary-hardening.json}" \
  BUILD_TOOLS_JSON="${BUILD_TOOLS_JSON:-$IN/build-tools.cdx.json}" \
  DEV_ASSUME_BUILDTOOLS="${DEV_ASSUME_BUILDTOOLS:-1}" \
  DEV_ASSUME_CHAIN="${DEV_ASSUME_CHAIN:-1}" \
  DEV_ASSUME_FWIMAGE="${DEV_ASSUME_FWIMAGE:-1}" \
  bash "$HERE/assemble-gate-input.sh"

echo "== 7. gate =="
"$HERE/gate.sh" "$IN/gate-input.json"
