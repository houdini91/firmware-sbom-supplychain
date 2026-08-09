# Compliance Matrix — what the gate actually enforces, per framework

*Last derived: 2026-08-07 · source of truth: [`oss-lane/initiatives/frameworks.yaml`](oss-lane/initiatives/frameworks.yaml) (control map) + [`oss-lane/policy/firmware.rego`](oss-lane/policy/firmware.rego) (the reports) · live status regenerated with `make coverage`.*

This document is the honest, framework-by-framework audit of the deploy gate. For every
control we claim, it names the **gated verifier report** that backs it, the **evidence**
that report reads, and the **live status** on a clean release. It also names, per framework,
the parts of that framework we **do not** gate — a RED / out-of-scope entry is a *truthful*
result and is recorded here deliberately, not hidden.

## How to read this

- **Gated** means the report is one of the 34 always-emitted `verifier_reports` that are
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
| EU CRA / BSI TR-03183-2 / CISA 2026 | 15 | 15 | 15/15 ✅ | Only SBOM-artifact obligations; CRA vuln-handling/disclosure/update duties out of scope |
| NIST SP 800-147 / 147B + UEFI Secure Boot | 2 | 2 | 2/2 ✅ (sample) | **Authenticated BIOS-update mechanism not assessed**; sample CHIPSEC, not silicon |
| OSF Firmware Embedded SBOM (structural) | 2 | 2 | 2/2 ✅ | Manifest-level proxy, not a parse of the shipped-PE coSWID (deeper check roadmapped) |
| **Total** | **46** | **45 gated + 1 advisory** | **45/46** | §4.3.1 Detection is the one advisory-MISSING, honest on clean |

45/46 satisfied on a clean release. The one non-green control (§4.3.1 Detection) is
**advisory** — it reports MISSING_EVIDENCE until a genuine flash-time measurement is supplied,
and it is not counted against `allow`. (OSF source-hash was advisory-MISSING until the `-Y SBOM`
generator began emitting a real per-module `edk2:sourceHash`; it is now MET — see §8.) A control
with no satisfying report reports MISSING_EVIDENCE, never a silent
pass.

**Not every ✅ is equally strong — evidence grade.** Each verifier report carries a machine-readable
`evidenceGrade`, and `verify-initiative.py` prints a control's **weakest-link** grade so a green ✅ is
never read as an unqualified proof. Of the 45 satisfied controls: **15 verified · 26 declared · 4
sample**.
- **verified** — re-derived from the shipped bytes or a verified signature (reconcile re-hash, the
  byte-integrity keystone, `cosign` signatures, cross-subject binding).
- **declared** — the SBOM/attestation *asserts* it and we check the claim is present + well-formed,
  but not that it is true of the running firmware (most CISA/BSI metadata fields, KEV-by-version,
  NX_COMPAT-declared hardening, the OSF shape/source-hash claims).
- **sample** — CHIPSEC config-level posture on a QEMU/OVMF target, **not** hardware-rooted silicon
  (the two 800-147 rows + the platform-protection maps).

The grade is deliberate per report (`data.evidence_grade`), guarded by `tests/test_evidence_grade.py`
(a new report cannot ship ungraded), and defaults to the conservative `declared` — never `verified`.
Note: in the offline demo the `DEV_ASSUME_*` legs (SLSA / identity / build-tools / firmware-image)
are **assumed**, not verified, and loudly warned; their `verified` grade reflects the real CI pipeline.

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
| cisa-author | `sbom-author` | CISA 2026 **required**: SBOM Author (`metadata.authors[].name`) | ✅ |
| cisa-timestamp | `sbom-timestamp` | CISA 2026 **required**: Timestamp (`metadata.timestamp`, ISO-8601) | ✅ |
| cisa-supplier | `sbom-supplier` | CISA 2026 **required**: Software Producer / Supplier (`metadata.supplier.name`) | ✅ |
| cisa-sbom-version | `sbom-serial-number` | CISA 2026: unique id (`serialNumber` urn:uuid) | ✅ |
| cisa-completeness | `sbom-completeness` | CISA 2026: completeness declaration (`compositions[].aggregate`) | ✅ |
| cisa-component-producer | `component-supplier` | CISA 2026: per-component Producer (`component.supplier.name`) | ✅ |
| cisa-dependencies | `dependency-relationships` | CISA 2026 **required**: Dependency Relationship — `dependencies[]` present + referentially sound (integrity, not completeness) | ✅ |
| cisa-data-quality | `sbom-data-quality` | NTIA data quality: declared purls parse + licenses well-formed (validity, not just presence; not full SPDX-list membership) | ✅ |
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
  dependency relationships) — these **are** gated: `sbom-author`, `sbom-timestamp`,
  `sbom-supplier`, and `dependency-relationships` (which parses the emitted dependency graph),
  alongside component id / hash / license / tool / context. What remains outside scope is the
  organizational/process half of TR-03183-2 (operator obligations), not SBOM fields.
- **Declared-not-proven ceiling:** `cisa-generation-tool`/`-context` and `no-kev-component`
  assert what the SBOM *declares* (a tool name, a lifecycle phase, a component version), not
  that the declared tool produced these bytes or that the version is runtime-exploitable. KEV
  membership is by declared version, matched against a real snapshot of the CISA KEV catalog
  (`data.cisa_kev`, 1,662 entries — refresh with `make refresh-kev`), not a hand-picked seed.

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

## 8 · OSF Firmware Embedded SBOM Specification (structural conformance)

| Control | Gated report(s) | Evidence read | Clean |
|---|---|---|---|
| osf-guid-identity | `osf-identity-shape` | every firmware module carries a GUID-form tag-id (== FILE_GUID) in the CDX manifest | ✅ |
| osf-source-hash | `osf-source-provenance` | a source-file hash rides in colloquial-version for every module (M-srchash) | ✅ |

Both controls are now MET, and the scope stays honestly labelled:
- **GUID-identity MUST (MET):** every firmware module's tag-id is its FILE_GUID.
  `osf-identity-shape` is an always-emitted, gated report: on a clean release every module's
  `bom-ref` is GUID-form, so it is GREEN; a module lacking a GUID tag-id DENYs (see fixture
  `osf-nonconformant.json`).
- **Source-hash / M-srchash MUST (now MET):** the `-Y SBOM` generator emits a real per-module
  **`edk2:sourceHash`** — a SHA-256 over the module's INF `[Sources]` file set, deterministic
  and reproducible (verified by independent recompute) — for **123/123** OvmfPkgX64 modules,
  plus a document-level **`edk2:sourceRevision`** (git commit) also surfaced into the gate's
  provenance as `source_commit`. `osf-source-provenance` fires GREEN. It stays **non-gating**:
  the report is emitted only when the MUST is *fully* met, so a build with partial/zero source
  hashes leaves it ABSENT (control MISSING) rather than DENYing — an advisory that never blocks.
- **The honest ceiling that remains:** `osf-identity-shape` is a **manifest-level structural
  proxy** — it reasons about the CycloneDX manifest the gate holds, **not** the coSWID parsed
  from the shipped PE / `.sbom` COFF section. A firmware whose *embedded* coSWID diverged from
  its manifest could still pass. The deeper "extract the coSWID from the shipped image →
  `uswid --validate` → assert it matches the manifest" check remains roadmapped.

---

## Cross-cutting honesty ledger

These caveats apply across the matrix and are the difference between "attestation theater" and
an honest gate:

1. **CHIPSEC = sample on QEMU.** Every §4.2/§4.2.3/800-147 row reads an illustrative
   `chipsec.json` on OVMF/QEMU. No hardware root of trust. Real deployment substitutes a live
   CHIPSEC run on physical silicon; the report messages say so explicitly.
2. **OSF embedded-SBOM MUSTs are gate-verified at the manifest level, not the shipped PE.** The
   gate now checks the OSF GUID-identity MUST (`osf-identity-shape`) **and** the source-hash MUST
   (`osf-source-provenance` — a real per-module `edk2:sourceHash` is emitted, so it is MET), both
   at framework 8 — but it still does **not** parse the coSWID from the shipped PE / `.sbom` COFF
   section. So the deeper embedded-conformance check (and the shipped-byte reconcile, which is an
   extension *beyond* OSF) remain as documented. See [`CONFORMANCE.md`](CONFORMANCE.md); the
   shipped-PE coSWID parse is still roadmapped.
3. **L0 on the firmware subject.** The VSA sets `verifiedLevels:[SLSA_BUILD_LEVEL_0]` on the
   firmware image and scopes real L2 to `evidenceBuildLevel` (the SBOM artifact's provenance).
   The machine-readable claim never overstates the firmware's own build level.
4. **Declared-not-proven ceiling** on `vex-adjudicated`, `sbom-generation-tool`,
   `sbom-generation-context`, `no-kev-component`: each asserts a *declared* fact in the SBOM,
   not an independently proven one.
5. **§4.3.1 advisory.** Detection stays MISSING_EVIDENCE until a real flash-time measurement is
   supplied — it is never counted as a pass on demo data.
6. **No vacuous SATISFIED — the CVE and reconcile facts carry non-vacuity guards.** An empty CVE
   findings list only satisfies `cve-triage`/`vex-adjudicated`/`no-kev-component` when a scan
   actually ran (`cve.scanned`); a zeroed reconcile block (`declared==0`) does not satisfy
   `reconcile-membership`. Without a scan/reconcile these controls report **not-satisfied**
   (fail-closed), never "clean" — parity with the `byte_integrity.ran` / `binary_hardening`
   coverage guards. `no-kev-component` matches against a real CISA KEV catalog snapshot
   (`data.cisa_kev`, 1,662 entries; `make refresh-kev`), and `osf-identity-shape` is a GUID-**shape** check (a UUID from
   any tool passes; it does not prove the value is a live UEFI FILE_GUID). These are stated in the
   report messages, not just here.

## Applicability — this gate is edk2/`-Y SBOM`-shaped (honest scope)

The gate reads edk2 shapes (GUID `bom-ref`, `edk2:*` properties, module `type`). Run against a
**foreign** vendor SBOM (Dell/Lenovo/coreboot) it correctly **DENYs** and — after the non-vacuity
guards above — reports the un-evidenced controls as **not-satisfied** rather than falsely SATISFIED.
But its edk2-shaped readers (`thirdparty` keys off `edk2:vendored`; `integrity`/`binary-hardening`
off `edk2:moduleType`) still can't *positively assess* a non-edk2 SBOM's real components. A
format-agnostic mapping layer (read `purl`/`licenses`/`hashes`/`type` from standard CycloneDX) and
an explicit NOT-APPLICABLE state for non-edk2 inputs are **roadmapped** — until then, treat a
foreign-SBOM verdict as "not evidenced here," not "non-compliant."

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
