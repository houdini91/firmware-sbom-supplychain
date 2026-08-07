#!/usr/bin/env bash
# Regenerate the canonical reference inputs/sbom.cdx.json from a real edk2 `-Y SBOM` build.
#
# Run this on a machine with the edk2 build toolchain. It builds OvmfPkgX64 with the hardened
# `-Y SBOM` generator (on your fork's master / feat/build-y-sbom-generator), copies the SBOM
# here, and replaces the hand-annotated interim reference with a genuine capture.
#
# Usage:
#   EDK2_DIR=/path/to/edk2 [ARCH=X64] [TARGET=DEBUG] [TOOLCHAIN=GCC5] bash scripts/regen-reference-sbom.sh
set -euo pipefail

EDK2_DIR="${EDK2_DIR:?set EDK2_DIR to your edk2 checkout (fork master, with the -Y SBOM generator)}"
ARCH="${ARCH:-X64}"; TARGET="${TARGET:-DEBUG}"; TOOLCHAIN="${TOOLCHAIN:-GCC5}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$REPO_DIR/inputs/sbom.cdx.json"

echo "== building OvmfPkgX64 ($ARCH/$TARGET/$TOOLCHAIN) with -Y SBOM in $EDK2_DIR =="
cd "$EDK2_DIR"
git submodule update --init                        # openssl etc. -> real third-party components
# shellcheck disable=SC1091
source edksetup.sh
make -C BaseTools                                  # GenFw -> rebase-0 canonical hashes
build -a "$ARCH" -t "$TOOLCHAIN" -p OvmfPkg/OvmfPkgX64.dsc -b "$TARGET" -Y SBOM -y /tmp/edk2-buildreport.txt

SRC="$EDK2_DIR/Build/OvmfX64/${TARGET}_${TOOLCHAIN}/CompileInfo/sbom.cdx.json"
[ -f "$SRC" ] || { echo "ERROR: expected SBOM not found at $SRC"; exit 1; }

echo "== verifying the hardening properties are present =="
python3 - "$SRC" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
hcf = sum(1 for c in d.get("components", []) if any(p.get("name")=="edk2:hashCanonicalForm" for p in c.get("properties", [])))
tpe = [p for p in d.get("metadata", {}).get("component", {}).get("properties", []) if p.get("name")=="edk2:thirdPartyEnumeration"]
assert hcf > 0, "no edk2:hashCanonicalForm in the fresh SBOM — is the hardened generator on this branch?"
assert tpe, "no edk2:thirdPartyEnumeration on metadata.component"
print(f"  ok: {hcf} components carry hashCanonicalForm; thirdPartyEnumeration={tpe[0]['value']}; components={len(d['components'])}")
PY

cp "$SRC" "$DEST"
echo "== copied genuine capture -> $DEST =="
echo
echo "NEXT (manual):"
echo "  1) remove the '## Note on sbom.cdx.json hardening annotations' block from inputs/README.md"
echo "     (this is now a real build capture, not an annotation)."
echo "  2) COSWID_PY=<venv>/bin/python make test-full   # confirm green with the fresh SBOM"
echo "  3) git add inputs/sbom.cdx.json inputs/README.md && git commit -m 'inputs: canonical -Y SBOM capture (replaces interim annotation)'"
