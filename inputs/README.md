# `inputs/` — the evidence artifacts

The real evidence the pipeline operates on for the OVMF/edk2 demo target. Two kinds:

**Source-of-record (committed)** — the demo's evidence, checked in so the gate and tests are reproducible
without a full firmware build:

| File | What | Produced by |
|---|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 SBOM (311 components; firmware digest in `metadata.component`) | edk2 `-Y SBOM` (fork PR #6), demo-enriched |
| `sbom.spdx.json` | SPDX 2.3 view of the same BOM | `producers/interop/to-spdx.sh` (protobom) |
| `sbom.uswid` | coSWID view + embed carrier | `producers/interop/to-coswid.sh` (uSWID) |
| `reconcile-verdict.json` | declared-vs-observed verdict (+ `image_digest`, anchor leg 2) | `producers/reconcile/carve.sh` |
| `chipsec.json` | CHIPSEC platform-posture predicate | `producers/chipsec/to-predicate.py` |
| `vex.openvex.json` / `vex.csaf.json` | CVE triage (OpenVEX) + BSI CSAF view | authored / `producers/interop/to-csaf.py` |

**Generated at run time (gitignored)** — recreated by `make demo` / the gate; safe to `make clean`:
`grype.json` (CVE scan), `gate-input.json` (assembled facts), `sbom.att.bundle` (cosign bundle),
`build-tools.cdx.json` (CI toolchain inventory).

> Not to be confused with `oss-lane/fixtures/` — those are hand-authored **test vectors** (one per gate
> failure mode), not real evidence.
