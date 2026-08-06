#!/usr/bin/env bash
# attack-demo — "same-GUID trojan caught" end-to-end proof.
#
# Takes a REAL committed edk2 PE32 module, byte-tampers ONE copy of it while keeping
# the SAME FILE_GUID/name (a same-GUID swap), runs the REAL byte-integrity producer
# and the REAL OPA deploy gate over both, and shows:
#     clean copy   -> byte-verified  -> gate ALLOW
#     trojaned copy -> MODIFIED       -> gate DENY  (while reconcile-membership still PASSES)
#
# This is the check the flagship claim rests on: membership/signatures pass a
# same-GUID swap; byte-integrity is what actually catches it.
#
# Self-contained (committed fixtures + opa + python3) — runs locally and in CI.
# For the FULL real-image capture over your own OVMF build, also point it at one:
#     make attack-demo FW_IMAGE=/path/OVMF.fd EDK2=/path/edk2
# which additionally runs the producer's real --image + FMMT carve path.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OPA="${OPA:-$ROOT/bin/opa}"
BI="$ROOT/producers/reconcile/byte-integrity.py"
GATE="$ROOT/oss-lane/gate.sh"
BUILD="$HERE/attack_demo_build.py"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/attack-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
SBOM="$WORK/demo-sbom.cdx.json"

rule() { printf '%s\n' "────────────────────────────────────────────────────────────────────"; }
step() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }

echo "== attack demo: same-GUID trojan caught =="
echo "   real producer: producers/reconcile/byte-integrity.py    real gate: oss-lane/gate.sh"

step "0. Stage a real module + a same-GUID byte-tampered copy (from committed fixtures)"
python3 "$BUILD" stage "$WORK"

# --- helper: run the real producer, print its output, return its real exit code ---
run_bi() {  # <label> <ffs-dir> <verdict-out>
  local label="$1" ffsdir="$2" out="$3" rc=0
  echo "\$ python3 producers/reconcile/byte-integrity.py --sbom demo-sbom.cdx.json --ffs-dir $label -o verdict.json"
  python3 "$BI" --sbom "$SBOM" --ffs-dir "$ffsdir" -o "$out" || rc=$?
  echo "   producer exit=$rc"
  return "$rc"
}

step "1. Clean image — the real producer byte-verifies the module"
CLEAN_V="$WORK/clean-verdict.json"; rc=0; run_bi clean "$WORK/clean" "$CLEAN_V" || rc=$?
[ "$rc" -eq 0 ] || { echo "UNEXPECTED: clean run did not pass (exit $rc)"; exit 1; }
jq -c '{checked,byte_verified,modified,clean}' "$CLEAN_V"

step "2. Trojaned image — SAME GUID, 1 byte flipped — the real producer flags it MODIFIED"
BAD_V="$WORK/tampered-verdict.json"; rc=0
run_bi tampered "$WORK/tampered" "$BAD_V" 2>"$WORK/bi.err" || rc=$?
cat "$WORK/bi.err"
[ "$rc" -eq 1 ] || { echo "UNEXPECTED: trojaned run should exit 1, got $rc"; exit 1; }
jq -c '{checked,byte_verified,modified:(.modified|map({name,guid,declared:.declared[0:16],observed:.observed[0:16]})),clean}' "$BAD_V"

# --- fold each real verdict into a gate input and run the REAL deploy gate ---
CLEAN_GI="$WORK/clean-gate-input.json"; BAD_GI="$WORK/tampered-gate-input.json"
python3 "$BUILD" gate-input "$CLEAN_V" "$CLEAN_GI" >/dev/null
python3 "$BUILD" gate-input "$BAD_V"   "$BAD_GI"   >/dev/null

step "3. The deploy gate ALLOWs the clean image"
rc=0; OPA="$OPA" bash "$GATE" "$CLEAN_GI" || rc=$?
[ "$rc" -eq 0 ] || { echo "UNEXPECTED: gate should ALLOW the clean image (exit $rc)"; exit 1; }

step "4. The deploy gate DENYs the trojaned image (membership passes, bytes fail)"
rc=0; OPA="$OPA" bash "$GATE" "$BAD_GI" > "$WORK/gate.out" 2>&1 || rc=$?
cat "$WORK/gate.out"
[ "$rc" -eq 1 ] || { echo "UNEXPECTED: gate should DENY the trojaned image (exit $rc)"; exit 1; }
grep -q "reconcile-membership: every declared module observed" "$WORK/gate.out" \
  || { echo "UNEXPECTED: reconcile-membership should still PASS"; exit 1; }
grep -q "component-byte-integrity" "$WORK/gate.out" || { echo "UNEXPECTED: no byte-integrity report"; exit 1; }
grep -q "module(s) MODIFIED" "$WORK/gate.out" || { echo "UNEXPECTED: no MODIFIED denial reason"; exit 1; }

# --- optional: the FULL real-image path over the user's own OVMF build (FMMT carve) ---
if [ -n "${FW_IMAGE:-}" ] && [ -n "${EDK2:-}" ]; then
  step "5. FULL real-image run — the producer's real --image + FMMT carve over your OVMF"
  echo "\$ python3 producers/reconcile/byte-integrity.py --sbom inputs/sbom.cdx.json --image $FW_IMAGE --edk2 <edk2> -o verdict.json"
  rc=0; python3 "$BI" --sbom "$ROOT/inputs/sbom.cdx.json" --image "$FW_IMAGE" --edk2 "$EDK2" \
        -o "$WORK/real-verdict.json" || rc=$?
  echo "   producer exit=$rc"
  jq -c '{checked,byte_verified,verified_direct,verified_unrebase,modified:(.modified|length),skipped:(.skipped|length)}' \
     "$WORK/real-verdict.json"
  echo "   (a clean build byte-verifies every module; tamper a module in $FW_IMAGE to see MODIFIED here too)"
fi

rule
echo "RESULT: same-GUID byte swap — reconcile-membership PASSED, component-byte-integrity DENIED. ✔ caught."
