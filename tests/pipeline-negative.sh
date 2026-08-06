#!/usr/bin/env bash
# F5: prove the GATE blocks when the REAL evidence is bad — not just that the rego denies fixtures.
# Reuses the already-produced signed bundle, runs the real assembler, and asserts deploy/block.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
IN="$ROOT/inputs"
OPA="${OPA:-$ROOT/bin/opa}"
BUNDLE="$IN/sbom.att.bundle"
PRED_TYPE="${PRED_TYPE:-https://firmware-sbom-supplychain/reconcile/v1}"
# builder identity + source repo come from the single source of truth (data.json)
export BUILDER_ID="${BUILDER_ID:-$(jq -r '.expected.builder_id' "$ROOT/oss-lane/policy/data.json")}"
export SOURCE_REPO="${SOURCE_REPO:-$(jq -r '.expected.source_repo' "$ROOT/oss-lane/policy/data.json")}"

fail=0
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT   # private temp dir, cleaned on exit (no world-readable /tmp collisions)

# The tamper-after-signing assertions below need a bundle whose signed SBOM-file subject (H) binds
# the CURRENT inputs/sbom.cdx.json. Use the real signed bundle when it does (the heavy supply-chain.yml
# has just produced it on push-to-main); otherwise — on a PR / fresh checkout (bundles are gitignored)
# or against a stale local leftover — SYNTHESIZE a self-consistent UNSIGNED bundle from the committed
# inputs so these assertions actually RUN instead of silently skipping to a false green. The real
# cryptographic signature + keyless identity are verified in supply-chain.yml's "Keyless verify" step;
# what THIS test proves is the assembler + gate binding (sbom.hash == signed file subject; firmware
# subject == anchor D), which is signature-independent.
H_now="$(sha256sum "$IN/sbom.cdx.json" | cut -d' ' -f1)"
bundle_binds_current() { # <bundle-path> — decode the legacy DSSE and check its SBOM-file subject == H_now
  [ -f "$1" ] || return 1
  python3 - "$1" "$H_now" <<'PY'
import base64, json, sys
try:
    b = json.load(open(sys.argv[1]))
    env = json.loads(base64.b64decode(b["base64Signature"]))
    stmt = json.loads(base64.b64decode(env["payload"]))
    subs = stmt.get("subject", []) or []
    fs = next((s.get("digest", {}).get("sha256", "") for s in subs if s.get("name") != "firmware-image"), "")
    if not fs and subs:
        fs = subs[0].get("digest", {}).get("sha256", "")
    sys.exit(0 if fs == sys.argv[2] else 1)
except Exception:
    sys.exit(1)
PY
}
if bundle_binds_current "$BUNDLE"; then
  echo "using the signed bundle (binds the current SBOM): $BUNDLE"
else
  # Rebuild the SAME multi-subject Statement supply-chain.yml signs (wrap.sh → firmware-image=D + SBOM-file=H),
  # then wrap it in the legacy .base64Signature envelope the assembler decodes. No signature — this lane
  # exercises binding only.
  D="$(jq -r '.metadata.component.hashes[] | select(.alg=="SHA-256").content' "$IN/sbom.cdx.json")"
  "$ROOT/producers/wrap.sh" "$IN/reconcile-verdict.json" "$PRED_TYPE" "$D" "$IN/sbom.cdx.json" sbom.cdx.json > "$TMP/reconcile.intoto.json"
  python3 - "$TMP/reconcile.intoto.json" "$TMP/synth.att.bundle" <<'PY'
import base64, json, sys
stmt = open(sys.argv[1], "rb").read()
dsse = {"payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(stmt).decode(), "signatures": [{"sig": ""}]}
json.dump({"base64Signature": base64.b64encode(json.dumps(dsse).encode()).decode()}, open(sys.argv[2], "w"))
PY
  BUNDLE="$TMP/synth.att.bundle"
  echo "note: no signed bundle binds the current SBOM (PR / fresh checkout / stale local leftover) —"
  echo "      synthesized an unsigned, self-consistent bundle so the binding assertions RUN"
  echo "      (real signature + keyless identity are verified in supply-chain.yml)."
fi

[ -s "$IN/grype.json" ] || echo '{"matches":[]}' > "$IN/grype.json"
# E7 build-tools SBOM: produce it so the build-tools-signed gate has a fact to consume; local run
# can't verify its keyless signature, so DEV_ASSUME_BUILDTOOLS=1 DEV_ASSUME_CHAIN=1 (as in the offline demo).
[ -f "$IN/build-tools.cdx.json" ] || "$ROOT/producers/build-tools/build-tools-sbom.sh" "$IN/build-tools.cdx.json" >/dev/null 2>&1

run_case() { # <name> <sbom-file> <expect allow|deny>
  SBOM="$2" BUNDLE="$BUNDLE" SIG=true GRYPE_JSON="$IN/grype.json" \
    OUT="$TMP/neg-gate.json" DEV_ASSUME_IDENTITY=1 DEV_ASSUME_SLSA=1 CHIPSEC_JSON="$IN/chipsec.json" \
    BYTE_INTEGRITY_JSON="$IN/byte-integrity.json" BINARY_HARDENING_JSON="$IN/binary-hardening.json" \
    BUILD_TOOLS_JSON="$IN/build-tools.cdx.json" DEV_ASSUME_BUILDTOOLS=1 DEV_ASSUME_CHAIN=1 DEV_ASSUME_FWIMAGE=1 \
    bash "$ROOT/oss-lane/assemble-gate-input.sh" >/dev/null 2>&1
  OPA="$OPA" "$ROOT/oss-lane/gate.sh" "$TMP/neg-gate.json" >/dev/null 2>&1; rc=$?
  got=allow; [ "$rc" -ne 0 ] && got=deny
  if [ "$got" = "$3" ]; then printf 'PASS  %-26s -> %s\n' "$1" "$3"
  else printf 'FAIL  %-26s expected %s, got %s\n' "$1" "$3" "$got"; fail=1; fi
}

echo "== in-pipeline negative tests (real evidence) =="
# baseline: the genuinely-signed SBOM deploys
run_case "unmodified-sbom" "$IN/sbom.cdx.json" allow
# tamper the SBOM AFTER signing -> its digest no longer matches the signed subject -> must block
jq '.metadata.timestamp = "1999-01-01T00:00:00Z"' "$IN/sbom.cdx.json" > "$TMP/sbom-tampered.json"
run_case "tampered-after-signing" "$TMP/sbom-tampered.json" deny
echo "================================================"
[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
