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

# 2) round-trip: container -> CycloneDX (prove components survive)
RT="$(mktemp --suffix=.cdx.json)"
"$UW" --load "$CONTAINER" --save "$RT"
python3 -c "import json,sys;a=len(json.load(open('$IN'))['components']);b=len(json.load(open('$RT')).get('components',[]));print('  round-trip components: %d -> %d'%(a,b))"
rm -f "$RT"

# 3) optional: embed into a PE .sbom section + re-extract
if [ "${1:-}" ]; then
  CAR="$(mktemp --suffix=.efi)"; cp "$1" "$CAR"
  "$UW" --load "$IN" --save "$CAR" --objcopy /usr/bin/objcopy --cc gcc
  objdump -h "$CAR" 2>/dev/null | grep -i sbom | sed 's/^/  section: /'
  EX="$(mktemp --suffix=.cdx.json)"
  "$UW" --load "$CAR" --save "$EX" --objcopy /usr/bin/objcopy
  python3 -c "import json;print('  extracted from PE .sbom:', len(json.load(open('$EX')).get('components',[])), 'components')"
  rm -f "$CAR" "$EX"
fi
