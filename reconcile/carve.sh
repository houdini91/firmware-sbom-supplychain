#!/usr/bin/env bash
# Observed side of reconcile: carve a firmware image into its FFS files with
# edk2 FMMT (which decompresses the LZMA'd FVs), then reconcile that observed
# set against the declared CycloneDX SBOM. Requires an edk2 build tree (FMMT +
# GenFw on PATH). Regenerates inputs/reconcile-verdict.json — it is NOT canned.
#
#   EDK2=/path/to/edk2 ./reconcile/carve.sh <firmware.fd>
#
# Example: EDK2=/media/.../edk2 ./reconcile/carve.sh \
#            "$EDK2/Build/OvmfX64/DEBUG_GCC/FV/OVMF.fd"
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
EDK2="${EDK2:?set EDK2=/path/to/edk2 build tree (needs BaseTools FMMT + GenFw)}"
IMG="${1:?usage: EDK2=<tree> carve.sh <firmware.fd>}"

export PYTHONPATH="$EDK2/BaseTools/Source/Python"
export PATH="$EDK2/BaseTools/Source/C/bin:$PATH"

VIEW="$HERE/ovmf-fmmt-view.txt"
python3 "$EDK2/BaseTools/Source/Python/FMMT/FMMT.py" -v "$IMG" > "$VIEW"
echo "✓ carved $(basename "$IMG") -> ${VIEW#$ROOT/}"

python3 "$HERE/sbom-reconcile.py" \
  --sbom "$ROOT/inputs/sbom.cdx.json" \
  --fmmt "$VIEW" \
  --image "$IMG" \
  -o "$ROOT/inputs/reconcile-verdict.json"
