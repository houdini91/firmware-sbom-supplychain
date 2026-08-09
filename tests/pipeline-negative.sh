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
D_now="$(jq -r '.metadata.component.hashes[] | select(.alg=="SHA-256").content' "$IN/sbom.cdx.json")"
bundle_binds_current() { # <bundle-path> — decode the legacy DSSE and require BOTH the SBOM-file subject == H_now
  # AND the firmware-image subject == D_now. A single-subject bundle (no firmware-image=D) — e.g. one a local
  # cosign < 2.6.0 emits via `attest-blob --predicate` — does NOT satisfy the multi-subject evidence-graph
  # binding these assertions exercise (evidence-chain-bound needs firmware_subject == D), so it is rejected
  # here and a self-consistent multi-subject bundle is synthesized instead of a false green/red.
  [ -f "$1" ] || return 1
  python3 - "$1" "$H_now" "$D_now" <<'PY'
import base64, json, sys
try:
    b = json.load(open(sys.argv[1]))
    env = json.loads(base64.b64decode(b["base64Signature"]))
    stmt = json.loads(base64.b64decode(env["payload"]))
    subs = stmt.get("subject", []) or []
    fs = next((s.get("digest", {}).get("sha256", "") for s in subs if s.get("name") != "firmware-image"), "")
    if not fs and subs:
        fs = subs[0].get("digest", {}).get("sha256", "")
    fw = next((s.get("digest", {}).get("sha256", "") for s in subs if s.get("name") == "firmware-image"), "")
    sys.exit(0 if (fs == sys.argv[2] and fw == sys.argv[3]) else 1)
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

# ---------------------------------------------------------------------------------------------------
# SECURITY (keystone verdicts): byte-integrity + binary-hardening are now consumed from a SIGNED,
# firmware-D-anchored bundle (subject #1 firmware-image == D). Prove the loose-file forge no longer
# feeds the gate: with a bundle set, the assembler reads the verdict FROM the bundle and IGNORES the
# loose inputs/*.json, and a bundle whose subject D != the image fails closed (not-ran -> DENY).
#
# Bundles here are UNSIGNED but self-consistent (same wrap.sh Statement + legacy .base64Signature
# envelope the synth block above uses) — the cryptographic signature + keyless identity are verified
# in supply-chain.yml / run.sh (cosign verify-blob-attestation of each bundle). What THIS test proves
# is the assembler's D-binding + bundle-vs-loose precedence, which is signature-independent.
echo "== signed byte-integrity / binary-hardening: the loose-file forge no longer feeds the gate =="
D="$(jq -r '.metadata.component.hashes[] | select(.alg=="SHA-256").content' "$IN/sbom.cdx.json")"
BI_TYPE=https://firmware-sbom-supplychain/byte-integrity/v1
BH_TYPE=https://firmware-sbom-supplychain/binary-hardening/v1

synth_evidence_bundle() { # <predicate-file> <D-hex> <predicateType> <bound-name> <out-bundle>
  "$ROOT/producers/wrap.sh" "$1" "$3" "$2" "$1" "$4" > "$TMP/ev.stmt.json"
  python3 - "$TMP/ev.stmt.json" "$5" <<'PY'
import base64, json, sys
stmt = open(sys.argv[1], "rb").read()
dsse = {"payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(stmt).decode(), "signatures": [{"sig": ""}]}
json.dump({"base64Signature": base64.b64encode(json.dumps(dsse).encode()).decode()}, open(sys.argv[2], "w"))
PY
}

run_bundle_case() { # <name> <BI_BUNDLE|-> <BI_LOOSE> <BH_BUNDLE|-> <BH_LOOSE> <expect allow|deny>
  local nm="$1" bib="$2" bil="$3" bhb="$4" bhl="$5" exp="$6"
  local extra=()
  [ "$bib" != "-" ] && extra+=(BYTE_INTEGRITY_BUNDLE="$bib")
  [ "$bhb" != "-" ] && extra+=(BINARY_HARDENING_BUNDLE="$bhb")
  env SBOM="$IN/sbom.cdx.json" BUNDLE="$BUNDLE" SIG=true GRYPE_JSON="$IN/grype.json" \
      OUT="$TMP/neg-gate.json" DEV_ASSUME_IDENTITY=1 DEV_ASSUME_SLSA=1 CHIPSEC_JSON="$IN/chipsec.json" \
      "${extra[@]}" BYTE_INTEGRITY_JSON="$bil" BINARY_HARDENING_JSON="$bhl" \
      BUILD_TOOLS_JSON="$IN/build-tools.cdx.json" DEV_ASSUME_BUILDTOOLS=1 DEV_ASSUME_CHAIN=1 DEV_ASSUME_FWIMAGE=1 \
      bash "$ROOT/oss-lane/assemble-gate-input.sh" >/dev/null 2>&1
  OPA="$OPA" "$ROOT/oss-lane/gate.sh" "$TMP/neg-gate.json" >/dev/null 2>&1; local rc=$?
  local got=allow; [ "$rc" -ne 0 ] && got=deny
  if [ "$got" = "$exp" ]; then printf 'PASS  %-38s -> %s\n' "$nm" "$exp"
  else printf 'FAIL  %-38s expected %s, got %s\n' "$nm" "$exp" "$got"; fail=1; fi
}

# (1) signed bundles carrying the GENUINE (clean) verdicts, anchored to the real image D
synth_evidence_bundle "$IN/byte-integrity.json"   "$D" "$BI_TYPE" byte-integrity.json   "$TMP/bi.clean.bundle"
synth_evidence_bundle "$IN/binary-hardening.json" "$D" "$BH_TYPE" binary-hardening.json "$TMP/bh.clean.bundle"
# (2) signed bundle carrying the TRUE MODIFIED byte-integrity verdict (what a trojaned image really is)
jq '.modified = [{"name":"TrojanCorePei","guid":"deadbeefdeadbeefdeadbeefdeadbeef"}] | .byte_verified = (.byte_verified - 1)' \
  "$IN/byte-integrity.json" > "$TMP/bi.modified.json"
synth_evidence_bundle "$TMP/bi.modified.json" "$D" "$BI_TYPE" byte-integrity.json "$TMP/bi.modified.bundle"
# (3) signed byte-integrity bundle re-pointed at ANOTHER firmware (subject #1 D != this image's D)
WRONG_D="$(printf '%s' not-this-image | sha256sum | cut -d' ' -f1)"
synth_evidence_bundle "$IN/byte-integrity.json" "$WRONG_D" "$BI_TYPE" byte-integrity.json "$TMP/bi.wrongd.bundle"
# (4) signed bundle carrying the TRUE missing-NX binary-hardening verdict
jq '.dxe_missing_nx = [{"name":"TrojanDxe","type":"DXE_DRIVER"}] | .dxe_nx_compat = (.dxe_nx_compat - 1)' \
  "$IN/binary-hardening.json" > "$TMP/bh.modified.json"
synth_evidence_bundle "$TMP/bh.modified.json" "$D" "$BH_TYPE" binary-hardening.json "$TMP/bh.modified.bundle"

# The attacker's LOOSE forge: byte-integrity.json flipped to a CLEAN verdict (it already is clean here,
# so the committed file IS the "forged clean" input the pre-fix gate would have trusted).
BI_FORGED_CLEAN="$IN/byte-integrity.json"
BH_LOOSE="$IN/binary-hardening.json"

# baseline: the signed clean bundles deploy (the signed path works end to end)
run_bundle_case "signed-clean-bundles"          "$TMP/bi.clean.bundle"    "$BI_FORGED_CLEAN" "$TMP/bh.clean.bundle"    "$BH_LOOSE" allow
# CONTRAST — the pre-fix behavior: with NO bundle, the CLEAN loose forge is trusted -> allow.
run_bundle_case "loose-clean-forge-NObundle"    "-"                       "$BI_FORGED_CLEAN" "-"                       "$BH_LOOSE" allow
# KEYSTONE — same CLEAN loose forge, but the signed bundle carries the TRUE modified verdict: the loose
# file is IGNORED, the signed truth wins -> DENY. The inputs/-write forge no longer feeds the gate.
run_bundle_case "loose-clean-forge-BLOCKED"     "$TMP/bi.modified.bundle" "$BI_FORGED_CLEAN" "$TMP/bh.clean.bundle"    "$BH_LOOSE" deny
# a bundle re-pointed at another firmware (subject D != image D) fails closed -> not-ran -> DENY.
run_bundle_case "wrong-anchor-D-BLOCKED"        "$TMP/bi.wrongd.bundle"   "$BI_FORGED_CLEAN" "$TMP/bh.clean.bundle"    "$BH_LOOSE" deny
# symmetry — binary-hardening loose forge blocked by its own signed (missing-NX) verdict.
run_bundle_case "binhard-loose-forge-BLOCKED"   "$TMP/bi.clean.bundle"    "$BI_FORGED_CLEAN" "$TMP/bh.modified.bundle" "$BH_LOOSE" deny
echo "================================================"
[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
