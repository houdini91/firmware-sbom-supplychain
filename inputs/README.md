# `inputs/` — the evidence artifacts

The real evidence the pipeline operates on for the OVMF/edk2 demo target. Two kinds:

**Source-of-record (committed)** — the demo's evidence, checked in so the gate and tests are reproducible
without a full firmware build:

| File | What | Produced by |
|---|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 SBOM (311 components; firmware digest in `metadata.component`) | edk2 `-Y SBOM` (fork PR #6) |
| `sbom.spdx.json` | SPDX 2.3 view of the same BOM | `producers/interop/to-spdx.sh` (protobom) |
| `sbom.uswid` | coSWID view + embed carrier | `producers/interop/to-coswid.sh` (uSWID) |
| `reconcile-verdict.json` | declared-vs-observed **membership** verdict (+ `image_digest`, anchor leg 2) | `producers/reconcile/carve.sh` |
| `byte-integrity.json` | **byte-integrity** verdict — each module's shipped PE32 bytes vs the SBOM hash (R4, 122 of 123) | `producers/reconcile/byte-integrity.py` |
| `chipsec.json` | CHIPSEC platform-posture predicate — **sample/illustrative data** (`producers/chipsec/sample-results.json`), not a live CHIPSEC run | `producers/chipsec/to-predicate.py` |
| `vex.openvex.json` / `vex.csaf.json` | CVE triage (OpenVEX) + BSI CSAF view | authored / `producers/interop/to-csaf.py` |

> **How these are trusted.** `reconcile-verdict.json`, `byte-integrity.json`, `chipsec.json`, and `binary-hardening.json` are produced
> **offline against the real deployed `.fd`** (they need an edk2 tree + a built OVMF image) and committed here;
> the gate — locally and in CI — **consumes them as evidence, it does not regenerate them** (CI has no built
> firmware). A consumer verifying their *own* firmware re-runs the producers against their image. To
> regenerate the byte-integrity verdict: `make byte-integrity EDK2=<edk2 tree> IMG=<OVMF.fd>` (needs `pefile`
> + edk2 FMMT; ~6 min — one FMMT extraction per module).

**Generated at run time (gitignored)** — recreated by `make demo` / the gate; safe to `make clean`:
`grype.json` (CVE scan), `gate-input.json` (assembled facts), `sbom.att.bundle` (cosign bundle),
`build-tools.cdx.json` (CI toolchain inventory).

> Not to be confused with `oss-lane/fixtures/` — those are hand-authored **test vectors** (one per gate
> failure mode), not real evidence.
