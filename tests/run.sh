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
expect firmware-subject-unbound.json deny
expect untrusted-signer.json  deny
expect firmware-digest-mismatch.json deny
expect byte-integrity-modified.json deny
expect byte-integrity-vacuous.json deny
expect byte-integrity-undercoverage.json deny
expect byte-integrity-unexpected-skip.json deny
expect binary-hardening-missing-nx.json deny
expect binary-hardening-vacuous.json deny
expect binary-hardening-undercoverage.json deny
expect binary-hardening-unexpected-skip.json deny
expect generation-tool-missing.json deny
expect generation-context-missing.json deny
expect kev-component.json deny
expect secureboot-fail.json deny
expect platform-protection-fail.json deny
expect osf-nonconformant.json deny
expect cve-not-scanned.json deny
expect baseline-metadata-missing.json deny
expect dependency-dangling.json deny
expect data-quality-bad.json deny
expect firmware-freshly-measured.json allow

# byte-integrity exemption ALLOW path: the same un-verifiable module that DENYs above must
# ALLOW once it is a reviewed entry in data.byte_integrity_exempt — proves the escape hatch works.
OPA="${OPA:-$HERE/../bin/opa}"; POL="$HERE/../oss-lane/policy"
_td="$(mktemp)"; jq '.byte_integrity_exempt += {"SomeUnverifiableModule":"reviewed test exemption"}' "$POL/data.json" > "$_td"
_av="$("$OPA" eval -I -f json -d "$POL/firmware.rego" -d "$_td" -d "$POL/cve-allowlist.json" -d "$POL/initiatives.json" 'data.firmware.deploy.allow' < "$IN/byte-integrity-unexpected-skip.json" 2>/dev/null | jq -r '.result[0].expressions[0].value')"
rm -f "$_td"
if [ "$_av" = "true" ]; then echo "PASS  byte-integrity exemption: the same module, listed in byte_integrity_exempt -> ALLOW"; else echo "FAIL  byte-integrity exemption ALLOW path (got $_av)"; fail=1; fi

# binary-hardening exemption ALLOW path: a DXE-class module that could not be scanned DENYs
# above, but ALLOWs once it is a reviewed entry in data.binary_hardening_exempt.
_tb="$(mktemp)"; jq '.binary_hardening_exempt += {"SomeUnscannableDxeModule":"reviewed test exemption"}' "$POL/data.json" > "$_tb"
_bv="$("$OPA" eval -I -f json -d "$POL/firmware.rego" -d "$_tb" -d "$POL/cve-allowlist.json" -d "$POL/initiatives.json" 'data.firmware.deploy.allow' < "$IN/binary-hardening-unexpected-skip.json" 2>/dev/null | jq -r '.result[0].expressions[0].value')"
rm -f "$_tb"
if [ "$_bv" = "true" ]; then echo "PASS  binary-hardening exemption: the same module, listed in binary_hardening_exempt -> ALLOW"; else echo "FAIL  binary-hardening exemption ALLOW path (got $_bv)"; fail=1; fi

echo "================================"
[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
