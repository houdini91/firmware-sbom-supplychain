# Changelog

All notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this is a research/portfolio project, so "releases" mark
coherent milestones rather than shipped products.

## [0.1.0] — 2026-08-04

First tagged milestone: an end-to-end firmware supply-chain verification gate on the OVMF/edk2 reference target,
with byte-level integrity.

### Added
- **Enforcing OSS-lane gate** — 18 OPA `verifier_reports` ANDed into a signed SLSA **VSA**; each report has an
  isolating negative fixture. Covers SBOM presence, keyless signature + signer identity, SLSA L2 provenance,
  reconcile membership, component + third-party integrity, VEX adjudication, CHIPSEC posture, build-tools
  signing, the firmware-digest anchor, and byte-integrity.
- **R4 byte-integrity (122/122)** — `producers/reconcile/byte-integrity.py` matches each module's shipped PE32
  bytes to the SBOM's declared hash: DXE drivers directly, XIP/PEI modules via **un-rebase canonicalization**.
  Catches a same-GUID trojan that membership checks miss. Gate report `component-byte-integrity`.
- **Firmware-digest anchor** — evidence bound to the deployed `.fd` bytes (SBOM digest == reconcile re-hash ==
  deployed image).
- **Consumer CLI** — `cli/fw-supplychain-verify`: hash your firmware, bind it to the VSA, per-framework
  scorecard; degrades honestly to `MISSING_EVIDENCE` on unattested firmware.
- **Initiative layer** — `frameworks.yaml` + `verify-initiative.py`: per-framework, per-control coverage from a
  signed VSA (PASS / FAIL / MISSING_EVIDENCE) across SLSA, SSDF, SP 800-53, SP 800-193, S2C2F, CRA/BSI/CISA.
- **Producers** — build-time SBOM generator (edk2 `-Y SBOM`, fork PR #6), FMMT carve + reconcile, CDX→SPDX /
  coSWID interop, CHIPSEC posture, build-tools SBOM.
- **Docs** — `PRIMER.md` (plain-language on-ramp) + mermaid diagrams; `FRAMEWORKS.md` control map;
  `EDK2-DEPENDENCY-RISK.md`; `SECURITY.md`; `CONTRIBUTING.md`.
- **CI** — keyless signing + SLSA L2 provenance (`supply-chain.yml`), CodeQL, Scorecard, and a fast
  `pr-checks` gate (tests + coverage) on every PR/push. `opa` pinned + SHA-verified.
- **Tests** — gate honesty fixtures, assembler + byte-integrity unit tests, cosign-native policy test.

### Security hardening (post-audit)
- Byte-integrity cannot pass vacuously: the gate requires every checked module verified (`verified == checked`,
  a skip is not a pass). The producer is crash-safe (fail-closed per module) and fails closed on unsupported
  relocation types / malformed images.

### Honest scope
Membership + byte-integrity are enforced; TE-format/compressed module sections and runtime/measured-boot
attestation are out of scope. Firmware-derived evidence is produced offline against the real `.fd` and consumed
(not regenerated) by CI. Offline `DEV_ASSUME_*` opt-ins are loudly warned and never set in CI.

[0.1.0]: https://github.com/houdini91/firmware-sbom-supplychain/releases/tag/v0.1.0
