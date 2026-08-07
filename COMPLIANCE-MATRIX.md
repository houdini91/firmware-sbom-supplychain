# Compliance Matrix — what the gate actually enforces, per framework

*Last derived: 2026-08-07 · source of truth: [`oss-lane/initiatives/frameworks.yaml`](oss-lane/initiatives/frameworks.yaml) (control map) + [`oss-lane/policy/firmware.rego`](oss-lane/policy/firmware.rego) (the reports) · live status regenerated with `make coverage`.*

This document is the honest, framework-by-framework audit of the deploy gate. For every
control we claim, it names the **gated verifier report** that backs it, the **evidence**
that report reads, and the **live status** on a clean release. It also names, per framework,
the parts of that framework we **do not** gate — a RED / out-of-scope entry is a *truthful*
result and is recorded here deliberately, not hidden.

## How to read this

- **Gated** means the report is one of the 24 always-emitted `verifier_reports` that are
  ANDed into `allow` (`allow if { every r in verifier_reports { r.isSuccess } }`,
  `firmware.rego:601`). If any gated report is `isSuccess:false`, the gate DENYs.
- **Three-state per control** (`verify-initiative.py`): a control is **PASS** only when
  *every* report in its `satisfied_by` list is present **and** green; **FAIL** if a
  satisfier is present but red; **MISSING_EVIDENCE** (❔) if a satisfier is absent. AND
  semantics — an always-green report does not spuriously satisfy a control that also needs
  an absent one.
- **Scope**: this maps a **firmware build-and-deploy supply-chain** slice of each framework.
  A gate that inspects an SBOM, an attestation, a reconcile verdict, a CVE scan, and a
  CHIPSEC report can only evidence controls those artifacts speak to. Everything a framework
  requires *outside* that evidence envelope (org process, source-code review, runtime, legal
  process) is listed under **Not gated** with the honest reason.
- **Sample-data caveat**: every CHIPSEC-derived signal is **SAMPLE / ILLUSTRATIVE** on an
  OVMF/QEMU target — config-level posture, **not** a live hardware-rooted CHIPSEC run. Those
  rows are honestly labelled and would need a real run on physical silicon to be load-bearing.

## Scoreboard

| Framework | Mapped controls | Gated | Clean status | Largest honest gap |
|---|---|---|---|---|
| SLSA v1.0 — Build L2 | 3 | 3 | 3/3 ✅ | L3 (hermetic/isolated) not claimed; Build track only |
| NIST SSDF (SP 800-218 v1.1) | 7 | 7 | 7/7 ✅ | Org/design/secure-coding/review tasks (PO.1–2, PW.1–3/5/7–9) out of evidence scope |
| NIST SP 800-53 Rev 5 | 10 | 10 | 10/10 ✅ | Only an SR/SI/CM/RA firmware slice of a 1000+ control catalog |
| NIST SP 800-193 | 3 | 2 gated + 1 advisory | 2/3 (§4.3.1 ❔ advisory) | **Recovery (§4.4) not covered**; Detection needs a real flash-time measurement |
| OpenSSF S2C2F v2 | 4 | 4 | 4/4 ✅ | Ingestion/mirroring/enforcement practice areas (ING/ENF/UPD) not covered |
| EU CRA / BSI TR-03183-2 / CISA 2026 | 7 | 7 | 7/7 ✅ | Only SBOM-artifact obligations; CRA vuln-handling/disclosure/update duties out of scope |
| NIST SP 800-147 / 147B + UEFI Secure Boot | 2 | 2 | 2/2 ✅ (sample) | **Authenticated BIOS-update mechanism not assessed**; sample CHIPSEC, not silicon |
| **Total** | **36** | **35 gated + 1 advisory** | **35/36** | §4.3.1 is the single non-green, honestly MISSING on clean |

35/36 satisfied on a clean release. The one non-green (§4.3.1 Detection) is **advisory** —
it reports MISSING_EVIDENCE until a genuine flash-time measurement is supplied, and it is
*not* counted against `allow`. A control with no satisfying report reports MISSING_EVIDENCE,
never a silent pass.

---

## 1 · SLSA v1.0 — Build track, Level 2

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| provenance-exists (L1) | `provenance-identity` | keyless attestation identity: built by the expected builder + source | ✅ |
| provenance-authentic (L2) | `slsa-provenance`, `slsa-level-floor` | platform-generated provenance (`attest-build-provenance` + `gh attestation verify`); build level ≥ 2 | ✅ |
| subject-binding | `sbom-binding`, `evidence-chain-bound` | SBOM/attestation/provenance name one subject digest; SBOM-file digest agrees across all three | ✅ |

**Not gated (truthful scope):**
- **Build L3** (hermetic, isolated, non-falsifiable build) is *not* claimed — `slsa-level-floor`
  caps at "≥ 2, not L3". Claiming L3 would need a hardened, isolated builder we do not assess.
- **Source track** (SLSA's source-integrity levels) is entirely out of scope; this is a
  build-provenance gate.
- **Honesty note:** the firmware image subject carries `verifiedLevels:[SLSA_BUILD_LEVEL_0]`.
  The real L2 belongs to the *SBOM artifact's* build provenance and is scoped to
  `evidenceBuildLevel`, so the VSA never machine-claims the firmware itself is L2.

## 2 · NIST SSDF — SP 800-218 v1.1

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| PS.2.1 | `attestation-signature` | keyless attestation signature verified — integrity info for acquirers | ✅ |
| PS.3.1 | `sbom-present`, `provenance-identity` | SBOM archived + provided per release, with provenance | ✅ |
| PO.3.2 | `build-tools-signed` | toolchain SBOM present, signed, every component SHA/version-pinned | ✅ |
| PO.3.3 | `slsa-provenance` | build tools emit signed artifacts of secure practice | ✅ |
| PW.4.4 | `thirdparty-identifiers`, `cve-triage` | third-party components carry purl+license; no un-triaged critical CVE | ✅ |
| PW.6.2 | `binary-hardening` | every DXE-class module declares NX_COMPAT (W^X-ready; declared posture) | ✅ |
| RV.1.1 | `cve-triage`, `vex-adjudicated` | ongoing CVE discovery + every high/critical carries a VEX justification | ✅ |

**Not gated (truthful scope):** SSDF has ~40 tasks; we evidence the artifact-integrity,
provenance, third-party and vuln-triage slice. Out of a build/deploy gate's evidence envelope:
PO.1/PO.2 (org security requirements, roles, toolchains-as-policy), PS.1 (protect all forms of
code at rest), PW.1–PW.3 (secure design + threat modelling + design review), PW.5 (secure
coding), PW.7 (human code review), PW.8 (testing), PW.9 (secure-by-default config), RV.2/RV.3
(remediation + root-cause). These are process/design controls no post-build artifact can prove.

## 3 · NIST SP 800-53 Rev 5 (SR / SI / CM / RA)

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| SI-7 | `reconcile-membership`, `component-integrity` | every declared module observed; every hashable module hashed | ✅ |
| SI-7(1) | `component-integrity`, `component-byte-integrity` | integrity checks over components; shipped bytes match declared hash | ✅ |
| SI-7(15) | `signer-identity-pinned` | code authenticated by a trusted keyless signer (SAN allowlist) | ✅ |
| SI-16 | `binary-hardening` | W^X-ready modules (declared NX_COMPAT posture) | ✅ |
| CM-8 | `sbom-present`, `reconcile-membership`, `component-integrity` | component inventory exists, complete, hashed | ✅ |
| CM-8(3) | `reconcile-membership` | unauthorized-component detection (no undeclared artifact in the image) | ✅ |
| CM-14 | `signer-identity-pinned` | signed components | ✅ |
| SR-4 | `slsa-level-floor` | provenance | ✅ |
| SR-4(3) | `slsa-level-floor`, `evidence-chain-bound`, `reconcile-membership`, `firmware-digest-anchor`, `component-byte-integrity` | validate genuine + not altered, end to end | ✅ |
| RA-5 | `cve-triage`, `no-kev-component` | vuln scanning + known-exploited prioritization (CISA KEV) | ✅ |

**Not gated (truthful scope):** 800-53 is a full control catalog (1000+ controls across 20
families). We map only the SR/SI/CM/RA controls a firmware supply-chain gate can evidence.
Everything else — AC/AU/IA/SC families, CM-3 change control, SI-7(6) cryptographic protection,
operational and organizational controls — is out of scope by design, not by omission.

## 4 · NIST SP 800-193 — Platform Firmware Resiliency

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| §4.2 Protection | `chipsec-posture` | applicable critical CHIPSEC modules passed (**sample**, OVMF/QEMU) | ✅ |
| §4.2.3 SMM | `platform-protection-posture` | CHIPSEC `smm` SMM-isolation PASSED (**sample**) | ✅ |
| §4.3.1 Detection | `component-byte-integrity`, `firmware-digest-anchor`, **`firmware-freshly-measured`** | admission-time off-device detection of corrupted code | ❔ **MISSING (advisory)** |

**The honest gaps here are the most important in the whole matrix:**
- **§4.3.1 Detection is MISSING on a clean release**, on purpose. Two of its satisfiers are
  always-green, but the third — `firmware-freshly-measured` — is a **conditional** report,
  emitted *only* when a genuine flash-time `FW_IMAGE` measurement is supplied. In offline/CI
  (`DEV_ASSUME_FWIMAGE`) mode no fresh measurement exists, so the report is **absent**, the
  control is honestly MISSING, and — because it is flagged `advisory` — it does **not** flip
  `allow`. The gate must not newly *claim* detection on demo data.
- **Recovery (§4.4) is NOT covered at all — a truthful RED.** 800-193's third pillar
  (auto-recovery of corrupted firmware to a known-good image) is outside what an
  admission-time supply-chain gate can evidence. It is not mapped and not claimed.
- **All CHIPSEC signals are SAMPLE / ILLUSTRATIVE on QEMU** — config-level posture with no
  hardware root of trust. `bios_ts`/`smrr` report N/A on QEMU and are reported-not-gated.
  A load-bearing §4.2 claim needs a live CHIPSEC run on physical silicon.

## 5 · OpenSSF S2C2F v2

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| SCA-1 | `cve-triage`, `vex-adjudicated` | scan OSS for known vulnerabilities + adjudicate | ✅ |
| SCA-2 | `thirdparty-identifiers` | scan OSS for licenses (purl + license per third-party) | ✅ |
| REB-3 | `build-tools-signed` | SBOM for the rebuilt build tooling | ✅ |
| AUD-3 | `component-byte-integrity`, `reconcile-membership` | validate integrity of ingested artifacts / shipped bytes | ✅ |

**Not gated (truthful scope):** S2C2F has 8 practice areas across maturity levels. We gate the
scan + inventory + shipped-byte-integrity slice. Not covered: **ING** (ingest/mirror OSS into a
controlled feed), **ENF** (enforce provenance at ingestion), **UPD** (update cadence / patch
SLAs), and the rest of **AUD**/**FIX**/**REB**. Those are ingestion-pipeline and process
controls upstream of the artifact this gate inspects.

## 6 · EU CRA / BSI TR-03183-2 / CISA 2026 Minimum Elements (SBOM obligations)

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| cra-annex-I-II-1 | `sbom-present`, `reconcile-membership` | CRA Annex I Part II(1): a machine-readable SBOM exists + matches the image | ✅ |
| cisa-hash | `component-integrity` | CISA 2026 minimum field: component hash | ✅ |
| cisa-fw-binding | `firmware-digest-anchor` | SBOM bound to the firmware image digest — **our extension**, beyond the CISA/NTIA minimum | ✅ |
| cisa-license-id | `thirdparty-identifiers` | CISA 2026 minimum fields: license + software identifiers | ✅ |
| cisa-generation-tool | `sbom-generation-tool` | CISA 2026: generation tool declared (name+version in `metadata.tools[]`) | ✅ |
| cisa-generation-context | `sbom-generation-context` | CISA 2026: generation context declared (`metadata.lifecycles[].phase`) | ✅ |
| cisa-kev | `no-kev-component` | no shipped component on the CISA KEV catalog (or an explicit exec-risk waiver) | ✅ |

**Not gated (truthful scope):**
- **EU CRA is a legal regulation**, not a data spec. We gate only its **SBOM-artifact**
  obligation (Annex I Part II(1)). The CRA's vulnerability-handling process, coordinated-
  disclosure duty, security-update obligation, and market-surveillance requirements are
  organizational/legal and outside a build gate's evidence.
- **BSI TR-03183-2** mandates additional SBOM fields (author, timestamp, supplier, full
  dependency relationships). We assert component id / hash / license / tool / context; we do
  **not** yet assert author/timestamp/supplier as gated fields — a candidate for the next cycle.
- **Declared-not-proven ceiling:** `cisa-generation-tool`/`-context` and `no-kev-component`
  assert what the SBOM *declares* (a tool name, a lifecycle phase, a component version), not
  that the declared tool produced these bytes or that the version is runtime-exploitable. KEV
  membership is by declared version; `data.cisa_kev` is a small illustrative seed.

## 7 · NIST SP 800-147 / 147B + UEFI Secure Boot

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| 800-147-flash-wp | `platform-protection-posture` | CHIPSEC `bios_wp` BIOS-region flash write-protection PASSED (**sample**) | ✅ |
| 800-147B-secure-boot | `uefi-secure-boot-posture` | CHIPSEC `secureboot.variables` PASSED — Secure Boot provisioned + enforcing (**sample**) | ✅ |

**Not gated (truthful scope):**
- **The authenticated BIOS-update mechanism — the core of 800-147 — is NOT assessed.** 800-147
  is primarily about a *signed capsule / authenticated update* path; we gate the
  flash-write-protection and Secure-Boot-enforcement pillars that the QEMU target actually
  exposes, not the update-authentication mechanism. Truthful RED.
- **147B rollback protection** (monotonic version / anti-rollback on update) is not assessed.
- **Sample CHIPSEC, not silicon** — both rows are config-level posture on OVMF/QEMU with no
  hardware root of trust.

---

## Cross-cutting honesty ledger

These caveats apply across the matrix and are the difference between "attestation theater" and
an honest gate:

1. **CHIPSEC = sample on QEMU.** Every §4.2/§4.2.3/800-147 row reads an illustrative
   `chipsec.json` on OVMF/QEMU. No hardware root of trust. Real deployment substitutes a live
   CHIPSEC run on physical silicon; the report messages say so explicitly.
2. **OSF embedded-SBOM MUSTs are not gate-verified.** The gate verifies that the *shipped bytes
   reconcile* against the SBOM (an extension *beyond* OSF), not that the embedded coSWID matches
   the OSF Firmware Embedded SBOM shape. See [`CONFORMANCE.md`](CONFORMANCE.md); a Tier-2
   `osf-sbom-conformance` gate is roadmapped.
3. **L0 on the firmware subject.** The VSA sets `verifiedLevels:[SLSA_BUILD_LEVEL_0]` on the
   firmware image and scopes real L2 to `evidenceBuildLevel` (the SBOM artifact's provenance).
   The machine-readable claim never overstates the firmware's own build level.
4. **Declared-not-proven ceiling** on `vex-adjudicated`, `sbom-generation-tool`,
   `sbom-generation-context`, `no-kev-component`: each asserts a *declared* fact in the SBOM,
   not an independently proven one.
5. **§4.3.1 advisory.** Detection stays MISSING_EVIDENCE until a real flash-time measurement is
   supplied — it is never counted as a pass on demo data.

## Regenerating this matrix

- The **coverage** column (PASS/FAIL/MISSING per control) is fully derivable from the signed
  VSA: `make coverage` runs the gate on `fixtures/clean.json`, emits a VSA, and prints the
  per-framework three-state. If a number here disagrees with `make coverage`, `make coverage`
  wins — fix this file.
- The **control map** (which report satisfies which control) lives in
  `oss-lane/initiatives/frameworks.yaml`; `initiatives.json` is regenerated from it and
  `tests/test_initiatives_sync.py` fails the build on drift.
- The **Not-gated / honest-gaps** sections are curated, not auto-derived — they are the
  deliberate record of scope, and must be updated by hand whenever a new control is gated or a
  gap is closed.
