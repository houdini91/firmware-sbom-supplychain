#!/usr/bin/env bash
# Fetch the CLI tools this repo shells out to, each PINNED to a version and
# verified by SHA-256. A supply-chain-integrity demo must not run on unpinned,
# hand-placed binaries. (In CI, cosign + grype are additionally pinned via the
# SHA-pinned sigstore/cosign-installer and anchore/scan-action; this covers the
# local path.) Idempotent: re-verifies an existing bin/<tool>, only fetches if
# absent or the SHA doesn't match.
#
#   scripts/fetch-tools.sh            # all tools
#   ONLY=opa scripts/fetch-tools.sh   # just opa (what `make test` needs)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/bin"; mkdir -p "$BIN"
ONLY="${ONLY:-}"

# name | version | url | sha256 | kind(bin|targz:<member>)
TOOLS=(
  "opa|1.18.2|https://openpolicyagent.org/downloads/v1.18.2/opa_linux_amd64_static|9903e5125ac281104f2c4b7371d10cc3b74a98933743fcbfc174f9bf0ab20de8|bin"
  "cosign|2.5.2|https://github.com/sigstore/cosign/releases/download/v2.5.2/cosign-linux-amd64|bcfeae05557a9f313ee4392d2f335d0ff69ebbfd232019e3736fb04999fe1734|bin"
  "grype|0.96.0|https://github.com/anchore/grype/releases/download/v0.96.0/grype_0.96.0_linux_amd64.tar.gz|11196534554bedcaeb4050450ea884c810c26e893ef2073ba72f84e2e5cf3b38|targz:grype"
)

_sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

_verify() {  # <file> <expected-sha> <label>
  got="$(_sha "$1")"
  [ "$got" = "$2" ] && return 0
  rm -f "$1"
  echo "error: $3 SHA-256 mismatch — refusing to install." >&2
  echo "  expected $2" >&2; echo "  got      $got" >&2
  exit 1
}

fetch_one() {
  local name="$1" ver="$2" url="$3" sha="$4" kind="$5"
  if [ -x "$BIN/$name" ] && [ "$(_sha "$BIN/$name")" = "$sha" ]; then
    echo "$name $ver ✓ present + SHA-verified"; return
  fi
  command -v curl >/dev/null 2>&1 || { echo "error: curl required to fetch $name" >&2; exit 1; }
  echo "fetching $name $ver (linux/amd64) ..."
  local tmp="$BIN/.$name.dl"
  curl -fsSL -o "$tmp" "$url"
  _verify "$tmp" "$sha" "$name"
  case "$kind" in
    bin)
      chmod +x "$tmp"; mv "$tmp" "$BIN/$name" ;;
    targz:*)
      local member="${kind#targz:}"
      tar -xzf "$tmp" -C "$BIN" "$member"
      chmod +x "$BIN/$member"; rm -f "$tmp" ;;
  esac
  echo "$name $ver ✓ fetched + SHA-verified"
}

for entry in "${TOOLS[@]}"; do
  IFS='|' read -r name ver url sha kind <<< "$entry"
  [ -z "$ONLY" ] || [ "$ONLY" = "$name" ] || continue
  fetch_one "$name" "$ver" "$url" "$sha" "$kind"
done
echo "note: jq, gh, sbom-convert, uswid, FMMT (edk2) are not fetched here — see requirements.txt."
