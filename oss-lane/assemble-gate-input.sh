#!/usr/bin/env bash
# Thin shim → the Python assembler (assemble_gate_input.py).
#
# The logic was ported to Python for readability + unit-testability (this was
# ~140 lines of jq/DSSE/digest data-processing). This shim is kept at the same
# path and env-var contract (SBOM BUNDLE SIG OUT BUILDER_ID SOURCE_REPO GRYPE_JSON
# CHIPSEC_JSON BUILD_TOOLS_JSON BUILD_TOOLS_SIG SLSA_VERIFIED PROVENANCE_SUBJECT
# FW_IMAGE DEV_ASSUME_*) so run.sh, the CI workflow, and the tests are unchanged.
# Output is golden-parity-identical to the former shell implementation.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$HERE/assemble_gate_input.py" "$@"
