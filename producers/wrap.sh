#!/usr/bin/env bash
# Wrap a predicate into a MULTI-SUBJECT in-toto v1 Statement, fed to
# `cosign attest-blob --statement <stmt>` (cosign >= 2.6.0). Two subjects, in this order:
#
#   1. { name: "firmware-image", digest: sha256=D }  — PRIMARY: the firmware anchor, so
#      every piece of evidence WE build binds to the firmware bytes (the evidence graph).
#   2. { name: <bound-name>,     digest: sha256=H }  — the digest of the bound evidence
#      FILE itself, so a tamper-after-signing of that artifact is detectable.
#
# Never use `cosign attest-blob --type custom` — it re-wraps the predicate and rewrites the
# subject to the blob's own digest, destroying the multi-subject binding.
#
#   wrap.sh <predicate-file> <predicateType> <sha256-hex-D> <bound-file> [bound-name]
#
# <bound-file> is the artifact whose own digest is subject #2 (H) — e.g. the SBOM file for the
# reconcile attestation, so the assembler's SBOM-file binding (sbom.hash == file_subject) holds.
# <bound-name> defaults to the basename of <bound-file>. Emits the Statement JSON on stdout.
set -euo pipefail

pred="${1:?usage: wrap.sh <predicate-file> <predicateType> <sha256-hex-D> <bound-file> [bound-name]}"
ptype="${2:?predicateType required (e.g. https://cyclonedx.org/bom)}"
d="${3:?sha256 hex of the firmware image digest D required}"
bound="${4:?bound-file (its own sha256 becomes subject #2, H) required}"
name="${5:-$(basename "$bound")}"

d="${d#sha256:}"   # tolerate a "sha256:"-prefixed D
command -v jq >/dev/null 2>&1 || { echo "wrap.sh: jq not found on PATH" >&2; exit 2; }
[ -f "$pred" ]  || { echo "wrap.sh: predicate file not found: $pred" >&2; exit 2; }
[ -f "$bound" ] || { echo "wrap.sh: bound file not found: $bound" >&2; exit 2; }

h="$(sha256sum "$bound" | cut -d' ' -f1)"

jq -n --slurpfile p "$pred" --arg pt "$ptype" --arg d "$d" --arg h "$h" --arg n "$name" '
  {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [
      { "name": "firmware-image", "digest": { "sha256": $d } },
      { "name": $n,               "digest": { "sha256": $h } }
    ],
    "predicateType": $pt,
    "predicate": $p[0]
  }'
