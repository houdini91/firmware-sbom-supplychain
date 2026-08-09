# Changelog

All notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this is a research/portfolio project, so "releases" mark
coherent milestones rather than shipped products.

## [Unreleased]

### Changed
- **Gate grew from 21 → 31 always-emitted verifier reports** (32 on the reference release incl. the
  conditional `osf-source-provenance`); controls now **46 across 8 frameworks**. New reports: the signed
  byte-integrity keystone, `no-duplicate-guid` (shadow-GUID detection), the CISA/BSI SBOM-metadata set
  (author/timestamp/supplier/serial/completeness/component-supplier/dependencies/data-quality), and a
  machine-readable `evidenceGrade` (verified/declared/sample/assumed) on every report.
- **CHIPSEC is now real, not sample.** `secureboot.variables` is a real offline varstore read; the
  hardware-rooted checks are a deploy-time advisory slot (ADR 0001). A real `-D SECURE_BOOT_ENABLE`
  build proves the red→green (`secboot-profile.json`).

### Added
- **byte-integrity production-hardening (the flagship control).** The verdict now emits a **full
  per-module manifest** (every verified module + method, alongside modified/skipped/errored); the gate
  **binds coverage** to the SBOM's declared hashable-module count, so a cherry-picked or stale verdict is
  denied; and any module that cannot be byte-verified must be a **reviewed exemption** in
  `data.byte_integrity_exempt` (with a documented reason) or the gate **denies and names it**. New negative
  fixtures for the undercoverage and unexpected-un-verifiable paths, plus an exemption-allow test; the
  un-rebase unit test now loudly flags a skipped crux group instead of passing silently.

### Fixed
- **byte-integrity: rebased modules with no relocation table.** `canon_unrebase` now correctly
  canonicalizes an XIP/PEI module that was rebased but has no `.reloc` table (e.g.
  `StatusCodeHandlerPei`, ImageBase `0x8452c0`): with no relocations to reverse, header
  normalization alone reproduces the declared base-0 hash (empirically verified against the SBOM
  digest). The prior code failed closed and undercounted (121/122 with one ERRORED); byte-integrity
  is a true **122/122** again. Added a regression test for the no-reloc path (+ its tamper case) and a
  committed fixture — the case that previously had no coverage.

### Changed
- **Firmware-digest anchor narrowed to the immutable code region.** The SBOM's `metadata.component`
  digest `D` now anchors **`OVMF_CODE.fd`** (`7965c317…`, 3653632 B — the immutable code) instead of the
  unified **`OVMF.fd`** (`374472f0…`, 4194304 B), which folds in the mutable `OVMF_VARS` NVRAM that
  legitimately changes on first boot — anchoring the whole image would false-fail any booted flash. The
  generator now prefers the `*_CODE` FD for `firmware:primary-image` and still enumerates **every** FD
  (`OVMF.fd`, `OVMF_CODE.fd`, `OVMF_VARS.fd`, `MEMFD.fd`) as a `firmware:fd-image` property with its own
  digest+size, enabling **two-state** verification (whole-image `OVMF.fd` for a *fresh* flash, code-region
  `D` for a *booted* one). Reconcile (123/123) and byte-integrity (122/122) re-run against the code region;
  all three anchor legs and the gate fixtures re-bind to the new `D`.
- **SBOM + derived artifacts regenerated from the current generator.** `openssl` is now emitted
  natively by `-Y SBOM` (retiring the "demo enrichment" framing), every built firmware device is
  enumerated as a `firmware:fd-image` property (incl. `MEMFD.fd`), and `reconcile-verdict` /
  `byte-integrity` / `sbom.uswid` / `sbom.spdx` / `vex.csaf` were refreshed. Component count is **311**.

## [0.1.0] — 2026-08-04

First tagged milestone: an end-to-end firmware supply-chain verification gate on the OVMF/edk2 reference target,
with byte-level integrity.

### Added
- **Enforcing OSS-lane gate** — 21 OPA `verifier_reports` ANDed into a signed SLSA **VSA**; each report has an
  isolating negative fixture. Covers SBOM presence, keyless signature + signer identity, SLSA L2 provenance,
  reconcile membership, component + third-party integrity, VEX adjudication, CHIPSEC posture, build-tools
  signing, the firmware-digest anchor, and byte-integrity.
- **R4 byte-integrity (122 of 123)** — `producers/reconcile/byte-integrity.py` matches each module's shipped PE32
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

[0.1.0]: https://github.com/houdini91/uefi-supply-chain/releases/tag/v0.1.0
