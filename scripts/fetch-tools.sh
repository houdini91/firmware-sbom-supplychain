#!/usr/bin/env bash
# Fetch the pinned CLI tools this repo shells out to, verifying each by SHA-256.
# A supply-chain-integrity demo must not itself run on unpinned, hand-placed
# binaries — so the one tool the self-contained targets need (opa) is pinned here.
#
#   scripts/fetch-tools.sh        (idempotent: re-verifies an existing bin/opa, only fetches if absent/wrong)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/bin"; mkdir -p "$BIN"

OPA_VER="1.18.2"
OPA_URL="https://openpolicyagent.org/downloads/v${OPA_VER}/opa_linux_amd64_static"
OPA_SHA="9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8"

_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch_opa() {
  if [ -x "$BIN/opa" ] && [ "$(_sha "$BIN/opa")" = "$OPA_SHA" ]; then
    echo "opa $OPA_VER ✓ present + SHA-verified"; return
  fi
  command -v curl >/dev/null 2>&1 || { echo "error: curl required to fetch opa" >&2; exit 1; }
  echo "fetching opa $OPA_VER (linux/amd64) ..."
  curl -fsSL -o "$BIN/opa.tmp" "$OPA_URL"
  got="$(_sha "$BIN/opa.tmp")"
  if [ "$got" != "$OPA_SHA" ]; then
    rm -f "$BIN/opa.tmp"
    echo "error: opa SHA-256 mismatch — refusing to install." >&2
    echo "  expected $OPA_SHA" >&2
    echo "  got      $got" >&2
    exit 1
  fi
  chmod +x "$BIN/opa.tmp"; mv "$BIN/opa.tmp" "$BIN/opa"
  echo "opa $OPA_VER ✓ fetched + SHA-verified"
}

fetch_opa
echo "note: cosign, grype, sbom-convert, uswid are needed only for 'make demo' and the producers —"
echo "      install those from their release pages (see requirements.txt)."
