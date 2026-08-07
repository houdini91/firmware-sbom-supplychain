#!/usr/bin/env bash
# coswid-demo — the coSWID emit + FULL-LOOP verification proof (WS-A + WS-B).
#
# Proves, on the fixture-staged path (no OVMF build required), that an embedded
# coSWID emitted via python-uswid's NATIVE CycloneDX loader — carrying the module
# GUID + the normalized shipped-byte SHA-256 as its native payload hash — closes the
# verification loop end to end (see CONFORMANCE.md for what this does/doesn't claim):
#
#   emit coSWID (native uswid loader)  [python-uswid, real CBOR]
#     -> embed in a PE .sbom + dump + extract   [uswid + objcopy, real round-trip]
#       -> ingest -> per-module declared hash    [python-uswid]
#         -> reconcile MEMBERSHIP                 [real sbom-reconcile.py]
#           -> byte-integrity vs shipped bytes    [real byte-integrity.py, declared hash]
#             -> gate ALLOW + signed VSA          [real gate.sh + firmware.rego]
#
# Then the tamper case (same-GUID, 1 code byte flipped):
#   membership still PASS, byte-integrity FAIL -> gate DENY.
#
# The shipped-byte hash rides natively (no private payload-suffix format); a REAL
# source hash, when supplied, rides in colloquial-version. A device-measured
# "evidence" hash remains a verification-profile PROPOSAL (CONFORMANCE.md), not a
# shipped format.
#
# REAL: the coSWID CBOR/PE round-trip, both producers, the OPA gate, the tamper.
# STUBBED: the source-file hash (edk2 source not vendored) and the FMMT view /
#          FFS (synthetic, = what FMMT emits) — same fixture philosophy as attack-demo.
#
# Needs python-uswid. Point the demo at an interpreter that has it, and its uswid CLI:
#   COSWID_PY=/path/venv/bin/python USWID=/path/venv/bin/uswid make coswid-demo
# (defaults: COSWID_PY=python3, USWID=uswid — works if uswid is installed globally.)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OPA="${OPA:-$ROOT/bin/opa}"
PY="${COSWID_PY:-python3}"
USWID="${USWID:-uswid}"
OBJCOPY="${OBJCOPY:-/usr/bin/objcopy}"

EMIT="$ROOT/producers/interop/coswid-emit.py"
INGEST="$ROOT/producers/interop/coswid-ingest.py"
RECON="$ROOT/producers/reconcile/sbom-reconcile.py"
BI="$ROOT/producers/reconcile/byte-integrity.py"
GATE="$ROOT/oss-lane/gate.sh"
BUILD="$HERE/coswid_demo_build.py"

# --- preflight: python-uswid + uswid CLI + objcopy must be present ---
"$PY" -c 'import uswid' 2>/dev/null || { echo "python-uswid not importable under '$PY'." >&2
  echo "  python3 -m venv v && v/bin/pip install uswid && COSWID_PY=v/bin/python USWID=v/bin/uswid make coswid-demo" >&2; exit 2; }
command -v "$USWID" >/dev/null 2>&1 || { echo "uswid CLI not found (set USWID=/path/to/uswid)" >&2; exit 2; }
command -v "$OBJCOPY" >/dev/null 2>&1 || { echo "objcopy not found (set OBJCOPY=...)" >&2; exit 2; }
[ -x "$OPA" ] || { echo "opa not found at $OPA (run: make bin)" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/coswid-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
step() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
rule() { printf '%s\n' "────────────────────────────────────────────────────────────────────"; }

echo "== coSWID emit + full-loop verification demo =="
echo "   uswid: $($USWID --version 2>&1 | head -1)    (python-uswid — real CBOR/coSWID)"

step "0. Stage the module + a same-GUID byte-tampered copy (committed fixture)"
"$PY" "$BUILD" stage "$WORK"
IN_SBOM="$WORK/input-sbom.cdx.json"; SRC="$WORK/source-hashes.json"; FMMT="$WORK/fmmt-view.txt"

step "1. WS-A: emit a coSWID via uswid's native loader (GUID + shipped-byte hash; source hash -> colloquial-version)"
COSWID="$WORK/DemoNetworkDxe.coswid"
"$PY" "$EMIT" --sbom "$IN_SBOM" --source-hashes "$SRC" --out "$COSWID"

step "2. Embed the coSWID in a PE .sbom section, then dump + extract it back"
CAR="$WORK/carrier.efi"; cp "$ROOT/tests/fixtures/pe/pcdpeim.declared.efi" "$CAR"
echo "\$ uswid --load DemoNetworkDxe.coswid --save carrier.efi --objcopy"
"$USWID" --load "$COSWID" --save "$CAR" --objcopy "$OBJCOPY"
objdump -h "$CAR" 2>/dev/null | grep -i '\.sbom' | sed 's/^/   section: /'
EXTRACT="$WORK/extracted.coswid"
echo "\$ uswid --load carrier.efi --save extracted.coswid --objcopy   (dump the embedded SBOM back)"
"$USWID" --load "$CAR" --save "$EXTRACT" --objcopy "$OBJCOPY"

step "3. WS-B: ingest the extracted coSWID -> per-module hashes + a reconcile-ready SBOM"
ING_SBOM="$WORK/ingested.cdx.json"
"$PY" "$INGEST" --load "$EXTRACT" --out-sbom "$ING_SBOM" --out-map "$WORK/hashmap.json"
echo "   (the SBOM the reconcile lane consumes now carries the SHIPPED-BYTE hash, recovered from the coSWID)"

# ---- helper: run membership + byte-integrity + gate for a given FFS dir/label ----
run_case() {  # <label> <ffs-dir> <expect-gate: allow|deny>
  local label="$1" ffs="$2" expect="$3"
  local rv="$WORK/$label-reconcile.json" bv="$WORK/$label-byte.json" gi="$WORK/$label-gate.json"

  echo "\$ sbom-reconcile.py --sbom ingested.cdx.json --fmmt fmmt-view.txt   ($label)"
  local rc=0; "$PY" "$RECON" --sbom "$ING_SBOM" --fmmt "$FMMT" -o "$rv" || rc=$?
  jq -c '{clean, validated:.summary.validated, missing:.summary.missing, suspicious:.summary.added_suspicious}' "$rv"
  [ "$rc" -eq 0 ] || { echo "UNEXPECTED: membership should PASS for $label (same GUID present)"; exit 1; }

  echo "\$ byte-integrity.py --sbom ingested.cdx.json --ffs-dir $label   (compare shipped bytes to the EVIDENCE hash)"
  rc=0; "$PY" "$BI" --sbom "$ING_SBOM" --ffs-dir "$ffs" -o "$bv" 2>"$WORK/$label-bi.err" || rc=$?
  cat "$WORK/$label-bi.err" 2>/dev/null || true
  jq -c '{checked, byte_verified, modified:(.modified|length), clean}' "$bv"

  "$PY" "$BUILD" gate-input "$rv" "$bv" "$gi" >/dev/null
  rc=0; VSA_OUT="$WORK/$label-vsa.json" OPA="$OPA" bash "$GATE" "$gi" >"$WORK/$label-gate.out" 2>&1 || rc=$?
  cat "$WORK/$label-gate.out"
  if [ "$expect" = "allow" ]; then
    [ "$rc" -eq 0 ] || { echo "UNEXPECTED: gate should ALLOW $label (exit $rc)"; exit 1; }
    grep -q '"predicateType": "https://slsa.dev/verification_summary/v1"' "$WORK/$label-vsa.json" \
      || { echo "UNEXPECTED: no signed VSA emitted for $label"; exit 1; }
  else
    [ "$rc" -eq 1 ] || { echo "UNEXPECTED: gate should DENY $label (exit $rc)"; exit 1; }
    grep -q "reconcile-membership: every declared module observed" "$WORK/$label-gate.out" \
      || { echo "UNEXPECTED: reconcile-membership should still PASS for $label"; exit 1; }
    grep -q "module(s) MODIFIED" "$WORK/$label-gate.out" \
      || { echo "UNEXPECTED: no byte-integrity MODIFIED denial for $label"; exit 1; }
  fi
}

step "4. CLEAN image — membership PASS, evidence-hash PASS -> gate ALLOW + signed VSA"
run_case clean "$WORK/clean" allow

step "5. TAMPERED image (same GUID, 1 code byte flipped) — membership PASS, evidence-hash FAIL -> gate DENY"
run_case tampered "$WORK/tampered" deny

rule
echo "RESULT: coSWID round-tripped through a PE .sbom; its EVIDENCE hash drove the reconcile."
echo "        clean -> ALLOW (+VSA);  same-GUID byte swap -> membership PASS, byte-integrity DENY. ✔"
