#!/usr/bin/env bash
# Local test of the cosign-native reconcile policy (feature b) — no cosign/OCI/network needed.
# Mirrors what `cosign verify-attestation --policy oss-lane/policy/cosign-reconcile.rego` evaluates.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OPA="${OPA:-$ROOT/bin/opa}"
POL="$ROOT/oss-lane/policy/cosign-reconcile.rego"
TD="$ROOT/oss-lane/policy/testdata"
fail=0

check() { # <name> <statement.json> <expect allow|deny>
  v="$("$OPA" eval -I -f json -d "$POL" 'data.signature.allow' < "$2" | jq -r '.result[0].expressions[0].value')"
  got=deny; [ "$v" = "true" ] && got=allow
  if [ "$got" = "$3" ]; then printf 'PASS  %-22s -> %s\n' "$1" "$3"
  else printf 'FAIL  %-22s expected %s, got %s\n' "$1" "$3" "$got"; fail=1; fi
}

echo "== cosign reconcile-policy tests =="
check reconcile-clean.json "$TD/reconcile-clean.json" allow
check reconcile-dirty.json "$TD/reconcile-dirty.json" deny
echo "==============================="
[ "$fail" -eq 0 ] && echo "ALL PASS" || echo "FAILURES"
exit $fail
