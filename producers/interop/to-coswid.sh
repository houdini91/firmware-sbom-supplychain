#!/usr/bin/env bash
# Cooperative interop (on-device path): convert the CycloneDX SBOM to a
# coSWID / uSWID container, and — if given a PE/COFF carrier — embed it into a
# `.sbom` section and re-extract to prove the round-trip. This is the
# fwupd / uSWID embedded-SBOM path.
#
#   USWID=/path/to/uswid ./producers/interop/to-coswid.sh [carrier.efi]
#
# Needs `uswid` (github.com/hughsie/python-uswid; this project's CDX-type fix
# lives in houdini91/python-uswid#1) and objcopy. Verified round-trip: a 310-
# component CycloneDX SBOM converts to a ~41 KB uSWID container and re-extracts
# to 311 components (the +1 is the document root), and survives a PE `.sbom`
# section embed + re-extract.
#
# Circularity note: the SBOM's document hash H must be computed BEFORE embed —
# embedding the coSWID changes the bytes the SBOM describes (see DESIGN.md).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
UW="${USWID:-uswid}"
IN="$ROOT/inputs/sbom.cdx.json"
CONTAINER="$ROOT/inputs/sbom.uswid"

command -v "$UW" >/dev/null 2>&1 || { echo "uswid not found — set USWID=/path/to/uswid (pip install -e python-uswid)" >&2; exit 2; }

# 1) CDX -> coSWID / uSWID container
"$UW" --load "$IN" --save "$CONTAINER"
echo "✓ coSWID/uSWID container -> ${CONTAINER#$ROOT/} ($(wc -c < "$CONTAINER") bytes)"

# private temp dir, cleaned on exit (portable — no GNU mktemp --suffix)
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

_count() { # <in.cdx.json> <out.cdx.json> <label> — component counts, paths via argv (not interpolated)
  python3 -c 'import json,sys
a=len(json.load(open(sys.argv[1])).get("components",[]))
b=len(json.load(open(sys.argv[2])).get("components",[]))
print("  %s: %d -> %d components" % (sys.argv[3], a, b))' "$1" "$2" "$3"
}

# 2) round-trip: container -> CycloneDX (prove components survive)
RT="$TMP/roundtrip.cdx.json"
"$UW" --load "$CONTAINER" --save "$RT"
_count "$IN" "$RT" "round-trip"

# 3) optional: embed into a PE .sbom section + re-extract
if [ "${1:-}" ]; then
  CAR="$TMP/carrier.efi"; cp "$1" "$CAR"
  "$UW" --load "$IN" --save "$CAR" --objcopy /usr/bin/objcopy --cc gcc
  objdump -h "$CAR" 2>/dev/null | grep -i sbom | sed 's/^/  section: /'
  EX="$TMP/extracted.cdx.json"
  "$UW" --load "$CAR" --save "$EX" --objcopy /usr/bin/objcopy
  _count "$IN" "$EX" "PE .sbom re-extract"
fi
