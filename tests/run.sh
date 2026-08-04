#!/usr/bin/env bash
# Honesty tests: prove the gate ALLOWS a clean input and BLOCKS each failure mode.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/../oss-lane/gate.sh"
IN="$HERE/../oss-lane/fixtures"
fail=0

expect() { # <fixture> <allow|deny>
  "$GATE" "$IN/$1" >/dev/null 2>&1; rc=$?
  got=allow; [ "$rc" -ne 0 ] && got=deny
  if [ "$got" = "$2" ]; then
    printf 'PASS  %-22s -> %s\n' "$1" "$2"
  else
    printf 'FAIL  %-22s expected %s, got %s\n' "$1" "$2" "$got"; fail=1
  fi
}

echo "== OSS-lane gate honesty tests =="
expect clean.json          allow
expect tampered-sbom.json  deny
expect wrong-builder.json  deny
expect critical-cve.json   deny
expect accepted-cve.json   allow
expect swapped-sbom.json   deny
expect unverified-provenance.json deny
expect chipsec-fail.json    deny
expect reconcile-mismatch.json deny
expect unhashed-module.json deny
expect high-unadjudicated.json deny
expect thirdparty-missing.json deny
expect build-tools-unsigned.json deny
expect slsa-level-low.json    deny
expect chain-mismatch.json    deny
expect untrusted-signer.json  deny
expect firmware-digest-mismatch.json deny
expect byte-integrity-modified.json deny
expect byte-integrity-vacuous.json deny
echo "================================"
[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
