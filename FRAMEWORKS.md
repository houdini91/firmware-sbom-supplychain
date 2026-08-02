# Compliance map — evidence to specific controls, honestly

> **This is not a "we comply with SLSA / SSDF / CRA" document.** Each framework has hundreds of
> controls, most irrelevant to a firmware SBOM pipeline. Claiming whole-framework compliance would be
> meaningless. Instead this maps the **specific evidence we produce** to the **specific control (with its exact
> section/subsection number)** it satisfies, states honestly *how far* it satisfies it, and builds the case for
> the next evidence worth producing. Companion to [`DESIGN.md`](./DESIGN.md); the enforced subset lives in
> [`oss-lane/compliance-map.md`](./oss-lane/compliance-map.md).

## Posture in three tiers

- **Enforced today** — the deploy pipeline **hard-blocks the release** on **seven OPA verifier reports** (SBOM
  present · attestation signature · SBOM↔subject binding · provenance identity · **SLSA L2 provenance** ·
  reconcile · CVE/VEX), the SLSA-L2 one backed by the `gh attestation verify` CI hard-gate. These are the
  controls we can defend as *actually enforced*, not merely mapped.
- **Satisfiable from evidence we already emit** — many named controls across SLSA, NIST SSDF/800-53/800-161,
  OpenSSF S2C2F, the CISA/NTIA SBOM elements, EU CRA, BSI TR-03183-2, and NIST 800-190 are met or partly met by
  the seven evidence artifacts — but *not wired into a gate*. Marked `EVIDENCE` / `PARTIAL`.
- **Not yet, and honestly named** — SBOM enrichment work (`PLANNED`) and the entire runtime/attestation stack
  (SP 800-193, TCG RIM, IETF RATS — `FUTURISTIC`), which needs a class of evidence we do not produce: a signed
  **TPM quote** and a signed **golden RIM**.

The single highest-value next step is enriching **one artifact** (the SBOM — add PURLs, licenses, and
third-party/submodule components), which advances ~10 controls across five frameworks at once.

## How to read this

Every row below is one link in this chain:

```
framework  →  §control (exact ref)  →  evidence that proves it  →  status  →  (if enforced) how
```

**Status legend** — the honest axis is *how real is it*, not *does it tick*:

| Status | Meaning |
|---|---|
| **`ENFORCED`** | The release is **hard-blocked if this fails** — by one of the seven OPA `verifier_reports` in [`firmware.rego`](./oss-lane/policy/firmware.rego) *(gate)*; the `slsa-provenance` report is additionally backed by a CI hard-gate step *(CI)*, `gh attestation verify`. The mechanism is named per row. |
| **`EVIDENCE`** | We produce the artifact/field, but no gate rule checks it yet — the control is *satisfiable from what we emit*, just not *enforced*. |
| **`PARTIAL`** | The evidence meets the control only in part; the named shortfall is in the note. |
| **`PLANNED`** | A concrete, near-term artifact change (mostly SBOM enrichment + byte-integrity reconcile) would satisfy it. |
| **`FUTURISTIC`** | Needs a new *class* of evidence we do not produce (runtime attestation: TPM quote + golden RIM). |
| **`N/A (process)`** | An organizational/process obligation (a policy, an SLA, an acquisition process) that **no build artifact can satisfy** — listed so it is visibly out of scope, not silently dropped. |

## Evidence inventory — what we actually produce (E1–E7)

Every table references these seven atoms. The ground-truth column is read from the real artifacts in this repo,
not asserted.

| # | Evidence | Format / predicate | What it proves | Ground-truth today | Enforced by |
|---|---|---|---|---|---|
| **E1** | **CycloneDX 1.6 SBOM** | in-toto SBOM predicate | declared composition of the firmware | 310 components (3 app / 108 driver / 12 firmware / 187 lib); **SHA-256+512 on 122 of the 123 non-library modules** (`ResetVector`, a raw reset-vector blob not a PE image, is the one skip); `metadata` timestamp/authors/tools/`lifecycle:build` populated; **0 PURLs, 0 licenses, ~0 third-party/submodule components** | `sbom-present` *(gate)* — presence only |
| **E2** | **SLSA Build L2 provenance** | `slsa.dev/provenance/v1` | build origin is authentic (platform-generated) | GitHub `attest-build-provenance`, **verified green in CI** with `gh attestation verify` | `slsa-provenance` *(gate)* backed by `gh attestation verify` *(CI)*; `provenance-identity` *(gate, identity)* |
| **E3** | **Reconcile verdict** | custom in-toto predicate | shipped bytes match the declared component set | FMMT-carved FFS vs SBOM by GUID, **123/123 module-granular; membership only** (no per-component byte hash yet) | `reconcile` *(gate)* |
| **E4** | **CVE + VEX** | grype JSON + OpenVEX | no un-triaged critical vulnerability ships | scan over E1 + OpenVEX triage allowlist | `cve-triage` *(gate)* |
| **E5** | **Signature + signer identity** | cosign keyless (Fulcio/Rekor) DSSE | the signed artifact came from the expected build identity | OIDC SAN extracted from the Fulcio cert and **checked**, not asserted; **signed subject is the SBOM/attestation, not the firmware image** | `attestation-signature` + `sbom-binding` *(gate)* |
| **E6** | **VSA** | `slsa.dev/verification_summary/v1` | the gate's verdict, as portable signed evidence | `verifier.id`/`policy.uri`/`verificationResult:PASSED`/`verifiedLevels:[L2]` populated; `resourceUri` generic; no `dependencyLevels` | output artifact |
| **E7** | **Build-tools SBOM** | CycloneDX + SHA-pins | the *build* toolchain is inventoried + signed | CI actions/tools, SHA-pinned + keyless-signed; **direct only, not transitive** | — (not gated) |
| **E8** | **SAST report** | CodeQL SARIF | static code-analysis findings | `codeql-sast` workflow — `python` (this repo's tooling) on push + scoped edk2 `c-cpp` (NetworkPkg) on dispatch; **green in CI**, uploaded to the Security tab. First *code-analysis* evidence. Attestation + `sast` gate report = the rest of R2 | — (SARIF produced, not gated yet) |

> **The trust anchor:** the seven gate reports are `sbom-present` (E1), `attestation-signature` (E5),
> `sbom-binding` (E1↔E5 digest), `provenance-identity` (E2), `slsa-provenance` (E2, backed by the
> `gh attestation verify` CI hard-gate), `reconcile` (E3), `cve-triage` (E4) — the gate ANDs them and emits E6.
> E1 and E5 each feed two reports.

## Cross-framework overlap — one evidence, many controls

The honest payoff of a control-level map: a single artifact satisfies clauses in several frameworks at once, so
effort spent on it is *reused*. Cells hold the **exact control ref** each evidence ticks.
**Bold** = enforced today (gate report or CI hard-gate) · `◐` = partial · plain = `EVIDENCE` (satisfiable, not
enforced) — see the per-framework tables for the exact status of every cell.

| Evidence | SLSA v1.0 | NIST SSDF 800-218 | 800-53 / 800-161 | S2C2F | CISA/NTIA elements | EU CRA | BSI TR-03183-2 | 800-190 | Runtime (futuristic) |
|---|---|---|---|---|---|---|---|---|---|
| **E1** SBOM | — | PS.3.2 | CM-8, SR-4◐ | INV-1 | name·ver·hash·ts·author·tool·context *(license,PURL,supplier: planned)* | **Annex I §II(1)** | §4, §5.2.1, §5.2.2 (name/ver/SHA-512) | — | RIM-analog◐ |
| **E2** Provenance | Prov-Exists **(L1, gate)** · **Prov-Authentic (L2, gate)** · Distribute | PO.3.3, PS.3.1 | SR-4, SI-7(15)◐ | — | — | §II(7)◐ | §8.1.15◐ | §4.1.5◐ | RATS §8.4-analog |
| **E3** Reconcile | — | — | SR-4(3)◐, SR-4(4)◐, SI-7◐, SI-7(1)◐ | AUD-3◐ | dependency◐ | — | §5.2.2 deps◐ | §4.1.5◐ | 800-193 §4.3◐, RATS §4.1 (Verifier), 800-155 |
| **E4** CVE+VEX | — | RV.1.1, RV.2.2, PW.4.4◐ | **RA-5** | **SCA-1** | — | §II(1) vuln, §II(3)◐ | §8.1.14 (CSAF-pref) | **§4.1.1** | — |
| **E5** Sig+ID | Prov-Authentic (L2) input | **PS.2.1** | SI-7(15)◐ | — | — | §II(7)◐, Annex VII 2(b) | §8.1.15 | §4.1.5◐ | RATS §4.1 (RP trust) |
| **E6** VSA | VSA `verification_summary` | PO.4.2◐ | — | — | — | — | — | — | RATS §8.4 / RP-analog |
| **E7** Build-tools SBOM | (isolation: SHA-pin) | PO.3.2◐ | CM-8 (tools) | INV-1◐ | — | — | §8.4.3 (Build SBOM) | — | — |
| **E8** SAST | — | PW.7.1, PW.8 | SA-11(1) | — | — | §II(3)◐ | — | — | — |

**Reading it:** E1, E2 and E5 are the load-bearing artifacts — each satisfies clauses in **five-plus**
frameworks. Note how few cells are **bold**: most mapped controls are *satisfiable but not enforced*. That gap
between "we emit the evidence" and "the gate blocks on it" is honest, and is what the *Gap → value* ranking
prioritizes closing.

## Reconcile: the novel control (positioning)

No regulation or firmware-SBOM effort requires verifying a declared SBOM against the shipped bytes — this is the
project's differentiator — but there *is* adjacent prior art, so the claim must be precise:
- **Binary-analysis SBOM tools** (Syft, EMBA, ONEKEY, binwalk) produce an *observed* SBOM but never diff it
  against a *declared build* SBOM.
- **Harness "SBOM Drift"** compares SBOMs across builds — not against bytes.
- **Academic (on-point):** a 2026 consumer-side-reproducibility paper argues the same thesis (a
  provenance-embedded SBOM digest is insufficient; the consumer should re-derive and compare). **UVSCAN**
  detects third-party-component violations in IoT firmware — nearest conceptual prior art.

**Precise claim:** *reconciliation of a declared **build** SBOM against the **observed firmware bytes**, gated by
policy* — ahead of vendor practice, matching cutting-edge research. **Not** "we analyze firmware bytes" (many do),
**not** "first firmware SBOM." Today it is **membership-granular** (all 123 modules present by GUID); byte-level
integrity is *Gap → value* item #2.

## Gap → value: the case for the next evidence to produce

Ranked by **controls-advanced per unit of effort**, using the overlap matrix.

1. **Enrich the SBOM (E1): add PURLs + licenses + third-party/submodule components.** *One artifact change*
   advances: BSI §5.2.2 licenses/deps, §5.2.4 CPE/PURL/URIs; CISA'26 License + Software-Identifiers + Supplier +
   completeness; CRA Annex I §II(1) component identification; S2C2F SCA-2 + INV-1; SSDF PS.3.2 / PW.4.1;
   800-53 SR-4 / SR-4(4) / CM-8 — **~10 controls across 5 frameworks.** *New tooling:* a license/PURL emitter +
   submodule enumeration (from the 13 gitlinks). **Honest limit:** PURL/CPE/license are real for the vendored
   submodules (openssl, brotli…), **not** for edk2 FFS modules — so most components stay identifier-less and
   several cells move *toward* `PARTIAL`, not fully satisfied. Emit where real, mark N/A where not.
2. **Byte-integrity reconcile (E3): compare a canonicalized per-region digest, not just membership.** Advances
   SR-4(3) "not altered", SI-7 / SI-7(1), S2C2F AUD-3 from `PARTIAL` toward strong. **Not** a naive digest match:
   in-FV modules are rebased/relocated, so it needs re-canonicalization image-side (the reconcile verdict already
   shows `modified_skipped` for exactly this reason), and `ResetVector` has no reference hash at all. E1's
   GenFw-rebase-0 SHA-512 is the *starting* reference, not a drop-in — but it makes the digest **triply
   motivated** (reconcile + BSI + CISA).
3. **Wire remaining evidence into gate rules (`EVIDENCE` → `ENFORCED`).** The `slsa-provenance` report now gates
   the L2-verified fact so the VSA lists it (**done** — R0a). Next: a per-component-hash-present check and a
   populated VSA `dependencyLevels`. Low effort; converts satisfiable-but-unenforced controls into enforced ones.
4. **CSAF/VEX document (BSI §8.1.14).** Convert E4's OpenVEX to CSAF for the BSI-named format. Low effort.
5. **Runtime attestation (the FUTURISTIC block).** A signed **TPM quote** (Attester/Evidence) + a signed
   **golden RIM** (Reference Values) unlocks the *entire* SP 800-193 §4.3 Detection, RATS §8.x, TCG RIM, and
   800-155 set at once. High effort, new evidence class — the honest long-horizon item.

**Analysis/test evidence — a new category (in progress).** The `codeql-sast` workflow now produces CodeQL SARIF
(**E8**, green in CI) — our first *code-analysis* evidence, moving SSDF PW.7/PW.8 and 800-53 SA-11(1) from `N/A`
to `EVIDENCE`. Attesting the SARIF + a `sast` verifier report (the rest of R2) makes them `ENFORCED`. **CHIPSEC**
platform-security assessment (R3) and **fuzzing** (R8) extend this same category — see
[`EVIDENCE-ROADMAP.md`](./EVIDENCE-ROADMAP.md).

---

# Detailed control tables (reference)

## A. Build & supply-chain frameworks (real coverage)

### SLSA v1.0 — Build track

The distinguishing axis is the **trust boundary**: *who generates/signs provenance relative to the build's
control plane*, not merely "is it signed." Requirement names are verbatim from `slsa.dev/spec/v1.0/requirements`.
(v0.1 terms — "Scripted build", "Hermetic", "Parameterless" — are **not** v1.0 controls and are not cited.)

| Level · Requirement | Ask | Evidence | Status | Note |
|---|---|---|:--:|---|
| L1 · **Provenance exists** | provenance generated for the artifact | E2 | **ENFORCED** *(gate)* | `provenance-identity` checks builder/source identity. |
| L1 · **Distribute provenance** | make it available to consumers | E2, E6 | **EVIDENCE** | E6 VSA is the distributable summary. |
| **L2 · Provenance is authentic** | signed by the build **control plane**, not the tenant job | E2 (+E5) | **ENFORCED** *(gate + CI)* | Asserted by the `slsa-provenance` verifier report (so the VSA lists it), backed by `attest-build-provenance` (platform-generated) + the `gh attestation verify` CI hard-gate (green). The offline demo, lacking `attest-build-provenance`, does not establish L2 — opt-in `DEV_ASSUME_SLSA` for local runs, loudly warned. |
| L2 · **Hosted** | build runs on a hosted platform, not a workstation | E2 | **EVIDENCE** | GitHub-hosted runner. |
| L3 · **Provenance is unforgeable** | signing material unreachable by build steps | — | **FUTURISTIC** | Needs an isolated/hardened builder (e.g. `slsa-github-generator`). |
| L3 · **Isolated** | builds cannot influence one another | — | **FUTURISTIC** | As above. |

**We are L2** for the SBOM artifact as handled by this operator-side workflow — *not* a claim about the upstream
edk2 firmware build. L3 is the honest remaining gap.

### NIST SSDF — SP 800-218 v1.1 (task text verbatim from the standard)

| Task | Ask | Evidence | Status | Note |
|---|---|---|:--:|---|
| **PS.2.1** | make software-integrity verification info available to acquirers | E5, E1 | **ENFORCED** *(gate)* | `attestation-signature`; keyless sig + extracted signer identity. |
| **PS.3.1** | archive integrity + provenance data per release | E2, E1, E5 | **PARTIAL** | Artifacts produced/stored (E2 as attestation); a retention *policy* is the missing process half. |
| **PS.3.2** | collect + share provenance for **all** components (e.g. an SBOM) | E1, E2 | **PARTIAL** | E1 exists but omits PURLs/licenses/**submodule components** → "all components" not yet met. |
| **PO.3.2** | deploy/operate tools securely; verify tool integrity & provenance | E7, E2 | **PARTIAL** | E7 SHA-pins CI tools (direct only). |
| **PO.3.3** | configure tools to emit artifacts evidencing secure practices | E2, E6, E1, E7 | **EVIDENCE** | Provenance + VSA + SBOMs are exactly these artifacts. |
| **PO.4.2** | automate collection/enforcement of security-check results | E6, E4 | **PARTIAL** | E6 VSA is the signed gate verdict; defining the criteria (PO.4.1) is process. |
| **PW.4.1 / PW.4.4** | acquire + continuously verify third-party components (vuln + integrity) | E4, E5, E1 | **PARTIAL** | E4/E5 cover the checks; capped by E1's missing third-party components. NIST maps PW.4.4 → SR-4(3)/SR-4(4). |
| **RV.1.1** | ongoing vuln discovery across components | E4 | **ENFORCED** *(gate)* | `cve-triage` (grype over the SBOM). |
| **RV.2.2** | plan + record risk response per vuln | E4 | **EVIDENCE** | OpenVEX `not_affected/affected/fixed` is a recorded response. |
| **PW.7.1 / PW.7.2** | code review / **static code analysis** | E8 | **EVIDENCE** | CodeQL SARIF (`codeql-sast`) — SAST evidence produced; the `sast` gate report is the rest of R2. (grype/E4 is SCA, not SAST — do not map E4 here.) |
| **PW.8 / RV.1.2** | code-level testing to find vulns | E8 | **EVIDENCE** | Same CodeQL SARIF; dynamic/fuzz testing is roadmap R8. |
| **RV.1.3** | vulnerability-disclosure policy | — | **N/A (process)** | No artifact; a CVD/PSIRT policy. |

### NIST SP 800-53 Rev 5 / SP 800-161r1 (C-SCRM overlay; SR/SI/CM/RA)

800-161r1 uses the 800-53 SR-family catalog; IDs are identical. Control statements verified for SR-4/SR-11.

| Control | Ask | Evidence | Status | Note |
|---|---|---|:--:|---|
| **SR-4** Provenance | document/monitor/maintain valid provenance of components & data | E2, E1, E7 | **EVIDENCE** | E2 is the anchor; component provenance (E1) incomplete. |
| **SR-4(3)** Validate as Genuine and Not Altered | received components are genuine + unaltered | E5, E2, E3 | **PARTIAL** | E5/E2 validate the build output; **E3 is membership-only → "not altered" at byte level unproven.** |
| **SR-4(4)** Supply Chain Integrity — Pedigree | validate internal composition + provenance of critical products | E1, E3 | **PARTIAL** | Composition touched; no critical-component pedigree; E1 omits submodules. |
| **SI-7** Software/Firmware/Information Integrity | detect unauthorized changes to software/firmware | E5, E2, E1, E3 | **PARTIAL** | Strong on build-output integrity; runtime/byte firmware integrity (E3) not complete. |
| **SI-7(15)** Code Authentication | cryptographically authenticate firmware **prior to installation** | E5, E2 | **PARTIAL** | The signature/`sbom-binding` checks are gate-enforced, but the **signed subject is the SBOM/attestation, not the firmware image** — firmware-byte authentication rides on reconcile (membership-only) and completes with Gap #2. |
| **SI-7(1)** Integrity Checks | integrity checks at defined events/frequency | E1, E3 | **PARTIAL** | Hashes + reconcile provide checks; cadence undefined; E3 membership-only. |
| **CM-8** System Component Inventory | accurate, current component inventory | E1, E7 | **PARTIAL** | E1 is the inventory but incomplete (no licenses/PURLs/submodules); E7 tools direct-only. |
| **RA-5** Vulnerability Monitoring & Scanning | scan for vulnerabilities; remediate per risk | E4 | **ENFORCED** *(gate)* | `cve-triage`; cadence to be documented. |
| **SA-11 / SA-11(1)** Developer Testing & Evaluation / Static Analysis | run static code analysis during development | E8 | **EVIDENCE** | CodeQL SARIF (`codeql-sast`) is exactly SA-11(1) static analysis; `sast` gate report pending (R2). |
| **SR-11** Component Authenticity | anti-counterfeit **policy** + detection | — | **N/A (process)** | E5/E3 give own-build authenticity but are **not** an anti-counterfeit program — do not claim. |
| **SR-3 / SR-5** Processes / Acquisition | documented C-SCRM processes / acquisition strategy | — | **N/A (process)** | Evidence implements pieces; the documented *process* is out of scope. |

### OpenSSF S2C2F v2 (practice IDs verbatim)

| Practice | Ask | Evidence | Status | Note |
|---|---|---|:--:|---|
| **INV-1** | automated inventory of all OSS used | E1, E7 | **PARTIAL** | E1 build-generated but no submodules; E7 direct-only. |
| **SCA-1** | scan OSS for known vulnerabilities | E4 | **ENFORCED** *(gate)* | Direct hit (`cve-triage`). |
| **AUD-3** | validate integrity of OSS consumed into the build | E3 | **PARTIAL** | Reconcile is membership-only — partial integrity signal. |
| **SCA-2** | scan OSS for licenses | — | **PLANNED** | Same missing-license data as CISA/BSI below. |
| **SCA-3** | scan OSS for end-of-life | — | **PLANNED** | Needs an EOL feed. |
| **AUD-1** | verify provenance of **ingested** OSS | — | **N/A / not-forced** | E2/E5 is provenance of *our own output*, a different subject — do not map. |

### in-toto attestation + SLSA VSA (evidence-format controls)

| Control | Ask | Evidence | Status | Note |
|---|---|---|:--:|---|
| in-toto **Statement `_type` v1** | standard statement envelope | E2, E6 | **EVIDENCE** | Both use the v1 Statement wrapper. |
| **subject→digest binding** | attestation bound to a specific artifact digest | E1, E5, E6 | **ENFORCED** *(gate)* | `sbom-binding`: SBOM digest == signed subject. |
| **DSSE signing** | attestation wrapped in a signed DSSE envelope | E5 | **ENFORCED** *(gate)* | Cosign keyless DSSE; OIDC identity. |
| VSA **`verifiedLevels`** | machine-readable level asserted | E6 | **EVIDENCE** | Reads `SLSA_BUILD_LEVEL_2` on allow; note it is *asserted on the pass verdict*, and gate-verified for real only in CI where `gh attestation verify` runs. |
| VSA **`dependencyLevels`** | SLSA levels of transitive deps | — | **PLANNED** | Empty today — ties to the E1/E3 transitive-coverage gap. |

## B. SBOM-content regulation (CRA / BSI / CISA / NTIA)

**The nuance first: CRA-the-law is field-light; the teeth are in BSI/CISA.** CRA requires an SBOM to *exist*,
be machine-readable, and cover *at least top-level dependencies* — **it names no fields and no format**. The
operational bar auditors use is **BSI TR-03183-2 v2.1.0** (CRA's harmonized-standard-in-waiting) and the
**CISA 2026 Minimum Elements**. So E1's missing licenses/PURLs are **not CRA gaps** — they are BSI/CISA gaps.

### EU CRA — Regulation (EU) 2024/2847 (Annex I **Part II** = vulnerability handling; text quoted)

| Ref | Ask (quoted) | Evidence | Status | Note |
|---|---|---|:--:|---|
| **Annex I, Part II(1)** | "…draw up a **SBOM in a commonly used and machine-readable format covering at the very least the top-level dependencies**" | E1, E4 | **ENFORCED ◐** *(gate: `sbom-present`)* | Existence + format are gate-enforced (CycloneDX 1.6). The component leg is thin: no identifiers/submodules to *demonstrate* the dependency set. E4 documents the "vulnerabilities" clause. |
| **Annex I, Part II(2)** | "address and remediate vulnerabilities without delay…" | E4 | **N/A (process)** | VEX feeds the decision; the remediation act/SLA is process. |
| **Annex I, Part II(3)** | "apply effective and regular tests and reviews…" | E4, E8 | **PARTIAL** | Recurring CVE scan (E4) + CodeQL SAST (E8) are two review types; pen-test/fuzz cadence (roadmap R8) would strengthen. |
| **Annex I, Part II(7)** | "mechanisms to **securely distribute updates**…" | E5, E2 | **PARTIAL** | Signing + provenance give the integrity primitives; the distribution channel isn't evidenced. |
| **Annex VII, 2(b)** | tech-doc must include the **SBOM**, CVD policy, contact address, secure-update solution | E1, E5, E2 | **PARTIAL** | SBOM + secure-update solution present; CVD policy + contact address are process artifacts. |

*Legal precision:* CRA does **not** name CycloneDX/SPDX and does **not** require licenses/PURLs/nested deps
(Recital 77; Annex I Part II(1)). It must be kept current across patches and retained as technical documentation
(Art. 31 / Annex VII).

### BSI TR-03183-2 v2.1.0 — SBOM data fields as discrete controls

Tiers (§5.2): **Required** = always mandatory · **Additional** = mandatory *when the data exists*.

| Ref | Field | Tier | Evidence | Status | Note |
|---|---|:--:|---|:--:|---|
| **§4** | format = CycloneDX **≥1.6** (or SPDX) | Req | E1 | **EVIDENCE** | E1 is CDX 1.6 — meets the floor exactly. |
| **§5.2.1 / Table 2** | SBOM creator + timestamp | Req | E1 metadata | **EVIDENCE** | `metadata.authors`=TianoCore + `metadata.timestamp` populated (verified). |
| **§5.2.2 / Table 3** | component name + version | Req | E1 | **PARTIAL** | Names present; ~291/310 versions default to `1.0` (weak). |
| **§5.2.2 / Table 3** | **hash of deployable component — SHA-512** | Req | E1 | **EVIDENCE** | Strong match: SHA-512 on 122 of the 123 modules (GenFw rebase-0 canonical, deployable form). |
| **§5.2.2 / Table 3** | dependencies (with completeness flag) | Req | E1, E3 | **PARTIAL** | Module→library edges exist; **submodule dependency graph absent**; no completeness flag. |
| **§5.2.2 / Table 3** | distribution licences (SPDX IDs) | Req | — | **PLANNED** | E1 has no licenses. |
| **§5.2.2 / Table 3** | component creator / filename | Req | — | **PLANNED** | Not emitted (bom-ref is the GUID, not a filename). |
| **§5.2.2 / Table 3** | executable / archive / structured properties | Req | — | **PLANNED** | BSI publishes a [CycloneDX property taxonomy](https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy) for exactly these. |
| **§5.2.4 / Table 5** | CPE / **PURL**, source/deployable URIs, original licences | Add | — | **PLANNED** | "Additional" = mandatory when computable; PURLs are computable → real gap. |
| **§8.1.14** | vulnerability data → **CSAF (VEX profile)** | rec | E4 | **PARTIAL** | E4 is OpenVEX; BSI's named format is CSAF/VEX. |
| **§8.1.15** | SBOM ideally digitally signed | rec | E5 | **EVIDENCE** | cosign covers it. |
| **§8.4.3** | Build SBOM | — | E7 | **EVIDENCE** | E7 aligns with the Build-SBOM concept. |

### CISA 2026 Minimum Elements (finalized ~July 2026) + NTIA 2021

The **CISA 2026 Minimum Elements** (finalized ~July 2026, superseding the NTIA 2021 baseline) add four fields:
**Component Hash, License, Generation Tool, Generation Context**.

| Element | Source | Evidence | Status | Note |
|---|---|---|:--:|---|
| Component name / version | NTIA'21 | E1 | **EVIDENCE** | Present. |
| **Supplier name** | NTIA'21 (retained '26) | E1 | **PARTIAL** | Only via `metadata.authors` (SBOM author ≠ per-component supplier); per-component supplier is `PLANNED`. |
| **Component Hash** | CISA'26 new | E1 | **EVIDENCE** | Per-module SHA-256/512 — meets the new integrity field on 122 of 123 modules. |
| **License** | CISA'26 new | — | **PLANNED** | Missing. |
| Software Identifiers (PURL/CPE) | NTIA'21 "other IDs" | — | **PLANNED** | No PURLs. |
| Dependency relationship | NTIA'21 | E1, E3 | **PARTIAL** | Internal edges only; no transitive/submodule graph. |
| Author of SBOM data | NTIA'21 | E1 | **EVIDENCE** | `metadata.authors` populated. |
| Timestamp | NTIA'21 | E1 | **EVIDENCE** | `metadata.timestamp` populated. |
| **Generation Tool** | CISA'26 new | E1 | **EVIDENCE** | `metadata.tools` = the `-Y SBOM` generator (name+version). |
| **Generation Context** | CISA'26 new | E1 | **EVIDENCE** | `metadata.lifecycles:[{phase:build}]` — build-time is the gold-standard context. |
| Automation support (format) | NTIA'21 | E1 | **EVIDENCE** | CycloneDX 1.6. |
| Completeness (transitive) | CISA'26 | E1 | **PARTIAL** | No submodule components. |

**Verdict:** CRA (law) **passes** (existence + machine-readable, gate-enforced); NTIA 2021 **mostly** (weak
supplier/identifiers); **CISA 2026** and **BSI v2.1.0** **do not yet pass** — both blocked on the same
fields: **licenses, PURLs, supplier, submodule components**.

## C. Container-analog — NIST SP 800-190 (Sept 2017; §4 read directly)

800-190 predates SBOMs and has no SBOM control; the firmware image maps as the "image."

| Ref | Ask | Evidence | Status | Note |
|---|---|---|:--:|---|
| **§4.1.1** Image vulnerabilities | pipeline vuln scan + "quality gate" above a CVSS threshold | E4, E3 | **ENFORCED** *(gate)* | `cve-triage` at severity=critical is exactly the quality gate. |
| **§4.1.5** Use of untrusted images | discrete signature identity + **validate signature before execution** | E5, E2, E6, E3 | **PARTIAL** | E5/E2/E6/E3 give sign+identify+verify+tamper-detect. **Caveat:** §4.1.5 (footnote 6 → CMVP) wants a **NIST-validated (FIPS 140)** crypto implementation — Sigstore/cosign keyless is **not** CMVP-validated. |
| **§4.2.3** Registry auth/authz | signed + scanned before promotion to a registry | E5, E4 | **PARTIAL** | Pattern supported; registry admission enforcement not shown. |
| **§4.1.2** Image config defects | secure config / minimal base | — | **N/A** | Not addressed by E1–E7. |

## D. Firmware-runtime frameworks — FUTURISTIC (the honest zero)

Everything below needs a **new class of evidence we do not produce**: a signed **TPM quote** (the "Attester's
Evidence") and a signed **golden RIM** (the "Reference Values"). Where our build-time evidence is a genuine
*structural analog* (same compare-artifact-to-reference logic), it is marked `◐ analog`, never covered. *(One
`PARTIAL` row below — §4.2.1 — is met only **pre-deployment**, via the signed update image; the on-device
enforcement it asks for is still futuristic.)*

### NIST SP 800-193 (Platform Firmware Resiliency — §4; subsection numbers verified against the primary PDF)

> The principles are **not** §4/§5/§6. They are subsections of §4 — Protection **§4.2.x**, Detection **§4.3.x**,
> Recovery **§4.4.x**, with roots of trust in **§4.1.x**.

| Ref | Ask | New evidence required | Status | Note |
|---|---|---|:--:|---|
| **§4.2.1** Protection and Update of Mutable Code | only authenticated firmware updates apply | on-device Root of Trust for Update (RTU) | **PARTIAL** *(pre-deployment)* | E5+E2 prove the *update image* is authentic before deployment; the on-device RTU that *refuses* unsigned images is futuristic. |
| **§4.3.1** Detection of Corrupted Code | detect corruption vs an authorized reference | measured-boot measurement + golden RIM, on-device | **FUTURISTIC ◐ analog** | Runtime twin of E3 reconcile — E3 compares *build outputs to SBOM*, not *running firmware to a reference*. |
| **§4.3.2** Detection of Corrupted Critical Data | detect critical-data corruption vs reference | as above | **FUTURISTIC** | — |
| **§4.4.1 / §4.4.2** Recovery of Mutable Code / of Critical Data | auto-recover to a known-good state | golden recovery image + on-device RTRec | **FUTURISTIC** | We can *supply* a signed known-good image (E2/E5); the recovery mechanism is runtime-only. |
| **§4.2.2 / §4.2.3 / §4.2.4** Protection of immutable code / runtime / critical data | hardware-enforced integrity | hardware protection mechanism | **FUTURISTIC** | No E1–E7 touch. |

### IETF RATS — RFC 9334 (roles §4.1; conceptual messages §8.x; topological models §5.x)

| Ref | Role / message | Evidence | Status | Note |
|---|---|---|:--:|---|
| **§4.1** Relying Party | consumes a verdict, gates an action | E6 + gate | **EVIDENCE (analog)** | Our VSA + deploy gate *are* the Relying-Party shape — only the input differs (build verdict vs runtime AR). |
| **§4.1** Verifier | appraises Evidence against Reference Values → result | E3 | **PARTIAL (analog)** | E3 reconcile is Verifier-shaped but appraises *build* evidence, not TPM Evidence. |
| **§8.3** Reference Values | golden values Evidence is compared to | golden RIM (below) | **FUTURISTIC** | E1/E7 SBOMs are the build-plane analog; runtime needs the RIM. |
| **§8.1** Evidence | device signs claims about its running state | **TPM quote + event log** | **FUTURISTIC** | The hard gap — no Attester, no quote. Every runtime row blocks on this. |
| **§8.4** Attestation Result | Verifier's signed verdict for the RP | signed EAT/AR4SI | **FUTURISTIC** | E6 VSA is the structural sibling, over build Evidence. |

### TCG PC Client RIM · NIST SP 800-155

| Ref | Ask | New evidence required | Status | Note |
|---|---|---|:--:|---|
| TCG PC Client RIM (exact §/Table **unverified** — primary PDF Cloudflare-gated) | publish the golden set of expected boot/firmware measurements as a **signed** manifest | a **signed golden RIM** (RIM Info Model mandates W3C XML-Signature) | **FUTURISTIC** | The Reference Values that 800-193 §4.3 and RATS §8.3 both consume. E1/E7 are component-enumeration cousins, not PCR golden hashes. |
| NIST SP 800-155 (IPD, Dec 2011; historical → folded into TCG) | measure BIOS at boot into TPM PCRs, compare to reference | measured-boot log + PCR values + reference set | **FUTURISTIC ◐ analog** | Explicit runtime ancestor of E3's "measure vs known-good" pattern; cite as lineage, not an active target. |

---

## Honest caveats (read before citing)

- **cosign keyless ≠ FIPS/CMVP.** 800-190 §4.1.5 (footnote 6 → CMVP) wants a NIST-validated crypto
  implementation; Sigstore is not CMVP-validated. State it if the audience is strict.
- **SLSA L2 is scoped to the SBOM artifact** on this operator-side workflow, not the upstream firmware build. It
  is enforced by the `slsa-provenance` verifier report, backed by the `gh attestation verify` CI hard-gate.
- **CRA is field-light** — do not attribute the license/PURL asks to CRA; they are BSI/CISA.
- **TCG PC Client RIM exact §/Table numbers are unverified** (primary PDF was gated) — read them off the spec
  before publishing anything that cites a specific RIM subsection.
- **E3 is membership-only** today — every "not altered / byte-integrity" claim is `PARTIAL` until Gap #2 lands.
- **The gate's per-report `.controls` tags are a representative subset**, not the exhaustive mapping — this
  document is the authoritative control map.

## Sources

SLSA: https://slsa.dev/spec/v1.0/requirements · VSA https://slsa.dev/spec/v1.0/verification_summary
SSDF 800-218: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf · 800-53r5 SR-4: https://csf.tools/reference/nist-sp-800-53/r5/sr/sr-4/ · SR-11: https://csf.tools/reference/nist-sp-800-53/r5/sr/sr-11/ · 800-161r1: https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final
S2C2F: https://github.com/ossf/s2c2f/blob/main/specification/framework.md · in-toto: https://github.com/in-toto/attestation
NTIA 2021: https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom · CISA 2026 Minimum Elements: https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom
CRA Reg (EU) 2024/2847: https://eur-lex.europa.eu/eli/reg/2024/2847/oj · BSI TR-03183-2 v2.1.0: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf · BSI CDX taxonomy: https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy
SP 800-190: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf · SP 800-193: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-193.pdf · SP 800-155 (IPD): https://csrc.nist.gov/pubs/sp/800/155/ipd
RATS RFC 9334: https://www.rfc-editor.org/rfc/rfc9334.html · TCG PC Client RIM: https://trustedcomputinggroup.org/resource/tcg-pc-client-reference-integrity-manifest-specification/ · OSCAL: https://pages.nist.gov/OSCAL/
Reconcile prior art: https://developer.harness.io/docs/software-supply-chain-assurance/sbom/sbom-drift/ · https://www.sciencedirect.com/science/article/pii/S2405959526001086
