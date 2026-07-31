# Frameworks & standards evaluation — an attestation-evidence policy map

> **Status: a working evaluation, not a compliance claim.** This document catalogs the security
> frameworks/standards relevant to firmware supply chain, maps them to the evidence this project actually
> produces, and is deliberately honest about partial and zero coverage. Where a framework is only partially
> met, it says so; where a control cannot be proven by any evidence we collect, it is listed as a *required
> evidence gap*, not hidden. Companion to [`DESIGN.md`](./DESIGN.md).

## How to read this

The design is, at its core, an **attestation / evidence-based policy** system:

```
framework  →  control  →  required evidence  →  OPA rule  →  gate verdict (VSA)
```

- A **framework** groups **controls** (SLSA, CRA/BSI, SSDF, TCG RIM …).
- A **control** is one checkable assertion ("provenance is authentic", "SBOM lists component hashes",
  "running firmware matches its golden RIM").
- Each control names the **evidence** that could prove it. If we produce that evidence, an **OPA rule**
  evaluates it. **If we do not, the control is a declared gap** ("required evidence: not collected") — this is
  the Valint pattern: a framework can *require* evidence we don't yet emit, which surfaces the hole instead of
  papering over it.
- The gate's overall decision is itself emitted as a signed **SLSA VSA** (Verification Summary Attestation).

We pick **high-value, artifact-provable slices** of each framework for the first proposal rather than
attempting full coverage — see [First-proposal focus](#first-proposal-focus).

## The evidence we actually collect today

These are the atoms every table below refers to.

| # | Evidence | Form | Notes / honest limits |
|---|---|---|---|
| ① | **CycloneDX 1.6 SBOM** | in-toto SBOM predicate | build-time, from edk2 `-Y COMPILE_INFO` data; **no per-component hashes/licenses/PURLs yet** |
| ② | **SLSA provenance** | `slsa.dev/provenance/v1` predicate | **self-signed by the build job → SLSA L1** (not L2, see below) |
| ③ | **Reconcile verdict** | (custom) in-toto predicate | declared SBOM vs bytes carved from the image; **module/FFS-granular**; a *committed* input in the demo |
| ④ | **CVE + VEX** | scan report + allowlist | raw scan over coarse firmware CPEs → VEX triage required |
| ⑤ | **Signature + signer identity** | cosign keyless (Fulcio/Rekor) | OIDC workload identity, SAN extracted at verify |
| ⑥ | **Build-tools SBOM** | CycloneDX + SHA-pins | **direct** CI actions/tools only, not transitive |

---

## Master framework catalog

Stance legend: **CITE** = standardized elsewhere, reference don't reinvent · **GAP** = weakly/​un-covered, our differentiator · **NORMALIZE** = adopt its vocabulary/format.

| Framework | What it is | Status / version | Design part | Firmware-specific | Stance |
|---|---|---|---|---|---|
| **SLSA v1.0** | build provenance levels L1–L3 | v1.0 (2023), v1.1+ | ② provenance | no | CITE + gap-to-L3 |
| **in-toto Attestation** | Statement+predicate, DSSE | CNCF graduated | carrier for ①②③④ | no | NORMALIZE |
| **SLSA VSA** | signed verification-summary | v1 | gate verdict | no | NORMALIZE (adopt) |
| **NIST SSDF SP 800-218** | secure-dev practices | v1.1, Feb 2022 | governance (all) | no | partial map |
| **NIST SP 800-161r1** | C-SCRM (org risk) | r1, May 2022 | ④ gate governance | no | partial map |
| **OpenSSF S2C2F** | consumer/ingestion practices | 8 practices × 4 levels | ③④ | no | partial map |
| **SCITT (IETF)** | append-only evidence transparency | draft-22 (~WGLC) | evidence store | no | NORMALIZE (target) |
| **NTIA 2021 min elements** | baseline SBOM fields | Jul 2021 | ① | no | CITE (superseded) |
| **CISA 2026 min elements** | updated SBOM fields (hash+license+context) | Jul 2026 | ① | no | **comply (gap)** |
| **CycloneDX 1.6 / ECMA-424** | SBOM format, native `firmware` type, CDXA | Apr 2024 | ① (+②③) | **yes** | CITE (our format) |
| **SPDX 3.0** | alt SBOM format | Apr 2024 | ① | no | interop |
| **CoSWID (RFC 9393)** | concise SWID id tags | Mar 2023 | ① → ⑤runtime | **yes-ish (uSWID)** | CITE (embed) |
| **EU CRA** | regulation; SBOM obligation | in force Dec 2024; SBOM Dec 2027 | ① | **yes (names firmware)** | driver |
| **BSI TR-03183-2** | operational SBOM field spec for CRA | v2.1.0, Aug 2025 | ① | generic (applies) | **comply (gap)** |
| **NIST SP 800-193** | platform firmware resiliency (Protect/Detect/Recover) | May 2018 | ⑤ posture | **yes** | CITE (context) |
| **NIST SP 800-147/147B** | BIOS update protection | 2011 / 2014 | ⑤ update-signing | **yes** | CITE (context) |
| **NIST SP 800-155** | BIOS integrity measurement (RIM ancestor) | **draft only, ~2011, never finalized → folded into TCG** | ③⑤ origin | **yes** | cite as origin |
| **TCG RIM / PC Client RIM** | golden reference measurements | Info Model v1.1 & PC-Client RIM v1.1 r11, Apr 2024 | ⑤ golden RIM | **yes** | CITE (don't invent) |
| **TCG PC Client Firmware Profile** | measured boot → PCRs / event log | active | ⑤ observed side | **yes** | CITE |
| **IETF RATS (RFC 9334)** | Attester/Verifier/Relying-Party roles | Jan 2023 | ⑤ (roles) | no | NORMALIZE (roles) |
| **IETF CoRIM** | concise reference-value transport | draft-ietf-rats-corim-11 | ⑤ ref values | no | CITE (emerging) |
| **TCG DICE** | RoT/identity without full TPM | active | ⑤ alt RoT | **yes (embedded)** | note |
| **CNCF Ratify + Gatekeeper** | verifier→verifierReport→ExternalData→Rego | active (notaryproject) | ④ gate | no | **NORMALIZE (mirror)** |
| **in-toto Witness / Archivista** | attestation capture + evidence graph + signed policy | CNCF in-toto | evidence store + ④ | no | model to cite |
| **Scribe Valint** | evidence create/sign/store/verify --rule | product | our Valint lane | no | our own lane |
| **JFrog Evidence** | in-toto+DSSE evidence over subjects | GA | evidence model | no | confirms norm |
| **Anchore VIPERR / policy** | 6-fn framework + policy gates | active | ④ CVE gate | no | vocab to cite |
| **Chainguard policy-catalog** | ready `ClusterImagePolicy` (Rego/CUE) | active | ④ | no | reusable bundle |
| **Kusari / GUAC** | attestation/​SBOM graph | OpenSSF incubating | evidence graph | no | optional |
| **Venafi / CyberArk CodeSign Protect** | machine-identity + only-signed-code-runs | Jan 2024 (acquired) | ⑤ signing identity | firmware-relevant | analog |
| **CycloneDX Attestations (CDXA)** | claims/evidence/conformance declarations | CDX 1.6 | control claims | no | NORMALIZE (optional) |
| **OpenVEX** | exploitability statements (in-toto predicate) | active | ④ CVE fact | no | NORMALIZE (adopt) |
| **NIST OSCAL** | machine-readable control↔framework mapping | active | the control layer itself | no | NORMALIZE (shape) |

---

## The three buckets

**CITE (standardized — reference, don't imply it's ours).**
The entire **runtime leg (⑤)** is defined by TCG (RIM, PC Client RIM, Firmware Profile), IETF RATS (RFC 9334) + CoRIM/CoSWID, and framed by NIST SP 800-193. **Provenance (②)** is SLSA + in-toto. **SBOM format (①)** is CycloneDX 1.6 / CoSWID. Say "we use X", cite it.

**GAP (our differentiators — state precisely).**
- **Reconcile (③): declared build-SBOM vs observed firmware bytes, as a policy gate.** *No* framework or regulation requires this — they all produce+sign an SBOM and then **trust the declaration**. Adjacent prior art exists, so the novelty must be worded carefully — see [Reconcile: the gap, honestly](#reconcile-the-gap-honestly).
- **Build-time SBOM generation for edk2 specifically (①).** Recognized-hard (the UEFI Forum proposal exists for it); coreboot/fwupd solved theirs, edk2 is the open case.

**NORMALIZE (adopt the shared vocabulary).**
Emit each fact as an **in-toto predicate**; emit the **gate verdict as a SLSA VSA**; structure the gate as **Ratify-style verifier reports**; describe runtime in **RATS roles**; shape the control layer like **OSCAL**; use **OpenVEX** for the CVE fact. See [Normalization vocabulary](#normalization-vocabulary).

---

## Framework × evidence coverage (honest, not forced)

✅ full · ◐ partial · ⭘ none/declared-gap.

| Framework | ① SBOM | ② Prov | ③ Reconcile | ④ CVE/VEX | ⑤ Sig/ID | ⑥ Tools | Honest coverage |
|---|:--:|:--:|:--:|:--:|:--:|:--:|---|
| SLSA Build track | | ◐ | | | ◐ | ◐ | **L1 only** — L2/L3 unproven |
| NTIA 2021 min elements | ◐ | | | | | | mostly (weak on identifiers) |
| CISA 2026 min elements | ◐ | | | | | | **partial** — no hash/license/identifiers |
| CRA (legal floor) | ✅ | | | | | | **meets** (existence + machine-readable + top-level deps) |
| BSI TR-03183-2 v2.1.0 | ◐ | | | | | | **fails required tier** (hash/license/props) |
| SSDF 800-218 | ◐ | ◐ | | | ◐ | ◐ | sliver (PS.2/PS.3/PW.4); rest is org process |
| SP 800-161r1 C-SCRM | ⭘ | ◐ | ◐ | ◐ | | | governance overlay only |
| OpenSSF S2C2F | ◐ | | ◐ | | | ◐ | Inventory/Audit/Enforce partial |
| SP 800-193 / TCG RIM / RATS | ⭘ | ⭘ | ⭘ | ⭘ | ⭘ | ⭘ | **none — declared gap** (runtime evidence not collected) |
| CycloneDX 1.6 / CDXA | ✅ | | | | | | format yes; CDXA claims not emitted |

The honest shape: **strong** on SBOM-format + SLSA-L1 + the novel reconcile control; **partial** on the process frameworks; **transparently zero** on the runtime/attestation frameworks (declared as required-but-unsatisfied, not hidden).

---

## SLSA — L1/L2/L3 mapped, and the gap to L3

SLSA is the load-bearing framework, so it gets a full map. The distinguishing axis is the **trust boundary**:
*who generates and signs the provenance relative to the build's control plane* — not merely "is it signed."

| Level | Requirement (verified against spec) | Us | Evidence needed to advance |
|---|---|:--:|---|
| **L1** | provenance *exists* and is distributed | ✅ **here** | — (we emit ②) |
| **L2** | provenance *authentic*: generated by the build platform **control plane**, signed by a key only the platform holds, **not by the tenant build steps** | ❌ | control-plane-generated provenance (e.g. GitHub `attest-build-provenance`) instead of the job self-signing |
| **L3** | **isolated, hardened** builder; steps cannot influence provenance or reach signing material; non-forgeable | ❌ | isolated-build attestation (e.g. `slsa-github-generator` reusable workflow, or a hosted build service) |

We are **L1**: our workflow job builds *and* self-signs its provenance (cosign keyless) — tenant-generated, which is L1 by definition. *(We fell back to self-signing because `attest-build-provenance` failed on the private fork — so L1 is a real current constraint.)* In the control-spine this becomes two honest **required-evidence gaps**: L2 = "control-plane-signed provenance: not satisfied", L3 = "isolated-builder attestation: not satisfied".

---

## SBOM field compliance — does our generator abide by CRA/BSI/CISA?

**The nuance first: CRA-the-law is field-light; the teeth are in BSI/CISA.** CRA (Annex I, Part II §1) requires only that an SBOM *exists*, is *"commonly used and machine-readable,"* and covers *"at the very least the top-level dependencies"* — **no fields named, no format named**. Against that legal floor **we pass**. The operational bar regulators audit against is **BSI TR-03183-2 v2.1.0** (CRA's harmonized-standard-in-waiting) and **CISA 2026** — and there we **do not yet comply**.

Field-by-field (current generator output: `type, bom-ref=GUID, name, supplier=TianoCore, version?, edk2:* properties, externalReference=.inf, dependencies`):

| Mandatory field | BSI v2.1.0 | CISA 2026 | NTIA 2021 | CRA | Our generator | CycloneDX 1.6 path | Gap |
|---|:--:|:--:|:--:|:--:|---|---|---|
| Component **name** | ✅ | ✅ | ✅ | — | ✅ | `component.name` | ok |
| Component **version** | ✅ | ✅ | ✅ | — | ◐ only when known | `component.version` | partial |
| **Dependencies** | ✅ | ✅ | ✅ (top-lvl) | ✅ (top-lvl) | ✅ 122 edges | `dependencies` | ok (BSI wants completeness flag) |
| Component **hash** | ✅ **SHA-512** | ✅ **value+alg** | — | — | ❌ | `component.hashes` | **miss (critical)** |
| Component **license** | ✅ | ✅ | — | — | ❌ | `component.licenses` | **miss** |
| **Unique identifiers** CPE/PURL | ◐ Additional | ✅ | ◐ | — | ❌ (only internal GUID) | `component.purl`/`.cpe` | **miss** |
| Component **producer/creator** | ✅ | ✅ | ✅ | — | ◐ hardcoded `TianoCore` | `component.supplier` | partial/inaccurate |
| **Filename** | ✅ | — | — | — | ❌ | `component.properties` (BSI taxonomy) | miss (BSI) |
| **Executable/archive/structured** | ✅ | — | — | — | ❌ (`edk2:*` instead) | `component.properties` (BSI taxonomy) | miss (BSI) |
| Source / deployable **URI** | ◐ Additional | — | — | — | ◐ `.inf` as `type:other` | `externalReferences` (`vcs`/`distribution`) | partial |
| SBOM **timestamp** | ✅ | ✅ | ✅ | — | ✅ | `metadata.timestamp` | ok |
| SBOM **author** | ✅ | ✅ | ✅ | — | ◐ supplier only | `metadata.authors` | partial |
| SBOM **tool name / version** | — | ✅ both | — | — | ◐ name only | `metadata.tools` | partial |
| SBOM **generation context** (lifecycle phase) | — | ✅ **new** | — | — | ❌ | `metadata.lifecycles` | miss (trivial — it's `build`) |
| **Format name + version** | ✅ (CDX≥1.6) | ✅ | — | ◐ | ✅ | `bomFormat`/`specVersion` | ok |

**Verdicts:** CRA (law) ✅ pass · NTIA 2021 ~mostly (weak identifiers) · **BSI v2.1.0 ❌** · **CISA 2026 ❌**.

**Why the gaps converge (good news):**
1. The now-mandatory **`component.hashes` (SHA-512) is exactly what reconcile (③) needs** to check *integrity* not just membership. So per-component digests are **triply motivated**: reconcile + BSI + CISA.
2. Most gaps are additive, low-risk CycloneDX fields; **BSI publishes a CycloneDX property taxonomy**
   (`BSI-Bund/tr-03183-cyclonedx-property-taxonomy`) defining exactly how to emit filename/executable/archive/structured.

**Honest caution (don't force it):** `license` and `PURL/CPE` are clean for the **third-party submodules** (openssl, brotli … — where they also feed CVE mapping) but **not meaningful per edk2 FFS module** — there is no sensible PURL type for "an edk2 module." Fabricating one everywhere would be the trap. Emit them where real; mark N/A where not.

### Generator backlog (derived from the gaps)
- **Tier 1** (compliance + reconcile, easy): `component.hashes` SHA-512 · `metadata.lifecycles=build` · tool version · `metadata.authors`.
- **Tier 2** (compliance, moderate): emit **third-party submodule components** with `purl`/`cpe`/`licenses`/real `supplier` (also fixes the hardcoded-TianoCore inaccuracy + feeds CVE mapping) · BSI property taxonomy for filename/exec/archive/structured.
- **Tier 3** (honest non-goals): per-edk2-module PURL/CPE where meaningless → document N/A, don't fabricate.

---

## Reconcile: the gap, honestly

No regulation or firmware-SBOM effort requires verifying a declared SBOM against the shipped bytes. But there
*is* adjacent prior art, so the claim must be precise:
- **Binary-analysis SBOM tools** (Syft, EMBA, ONEKEY, binwalk) produce an *observed* SBOM but never diff it against a *declared build* SBOM.
- **Harness "SBOM Drift"** compares SBOMs across builds — not against bytes.
- **Academic (on-point):** a 2026 paper on *consumer-side reproducibility* of SBOMs argues exactly our thesis (a provenance-embedded SBOM digest is insufficient; the consumer should re-derive and compare). **UVSCAN** (academic) detects third-party-component violations in IoT firmware — nearest conceptual prior art.

**Precise claim:** *reconciliation of a declared **build** SBOM against the **observed firmware bytes**, gated by policy* — ahead of vendor practice, matching cutting-edge research. **Not** "we analyze firmware bytes" (many do) and **not** "first firmware SBOM."

---

## Normalization vocabulary

| Our term (today) | Normalize to | Standard |
|---|---|---|
| the SBOM | CycloneDX SBOM as an **in-toto predicate** | in-toto / CycloneDX 1.6 |
| provenance | **SLSA Provenance** predicate | `slsa.dev/provenance/v1` |
| reconcile verdict | custom **in-toto predicate** (reconcile) | in-toto |
| "no critical CVE" | **OpenVEX** statement (affected/not-affected) | OpenVEX |
| gate verdict | **SLSA VSA** (Verification Summary Attestation) | SLSA VSA |
| per-fact check | **Ratify-style `verifierReport {name,isSuccess,message}`** | Ratify/Gatekeeper |
| evidence store | in-toto attestations in OCI + transparency log | Rekor / **SCITT** |
| roles (runtime) | **Attester / Verifier / Relying Party** | IETF RATS RFC 9334 |
| control↔framework map | **OSCAL**-shaped | NIST OSCAL |

**Highest-ROI single change:** emit the gate verdict as a **VSA** — turns a boolean AND into a signed,
portable "passed policy at level X" artifact others consume without re-verifying.

---

## The framework → control → evidence → OPA-rule spine

High-value slices fully expressed; the rest **stubbed as declared required-evidence gaps** (the honest move —
a framework can require evidence we don't emit yet).

| Framework | Control | Required evidence | Provable now | OPA rule (intent) |
|---|---|---|:--:|---|
| **SLSA** | Build L1 — provenance exists | ② | ✅ | `provenance_present` |
| **SLSA** | Build L2 — provenance authentic (control-plane) | control-plane-signed provenance | ⭘ **gap** | *(stub)* `builder_id ∈ trusted ∧ signer = control_plane` |
| **SLSA** | Build L3 — isolated builder | isolated-build attestation | ⭘ **gap** | *(stub)* |
| **CRA** | Annex I §1 — SBOM exists, machine-readable, top-level deps | ① | ✅ | `bomFormat ∧ specVersion ∧ dependencies` |
| **BSI v2.1.0** | required SBOM fields present | ① (enriched) | ◐ **fails now** | `∀ c: c.hashes ∧ c.licenses ∧ c.name ∧ c.version` |
| **CISA 2026** | hash + license + generation context | ① (enriched) | ◐ **fails now** | `metadata.lifecycles ∧ ∀ c: c.hashes` |
| **(novel)** | declared SBOM matches observed bytes | ③ | ✅ (module-granular) | `reconcile.verdict = "match"` |
| **NIST 800-161 / general** | no known-critical exploitable CVE | ④ + OpenVEX | ✅ | `¬∃ cve: critical ∧ ¬vex_not_affected` |
| **SSDF PS.2 / general** | artifact signed by expected identity | ⑤ | ✅ | `sig_valid ∧ signer = expected` |
| **SLSA / S2C2F** | toolchain inventoried, actions pinned | ⑥ | ✅ | `all_actions_sha_pinned ∧ tools_sbom_present` |
| **SP 800-193 / TCG RIM / RATS** | running firmware matches golden RIM | TPM quote + CoRIM/RIM | ⭘ **gap** | *(stub)* `rim_appraisal = pass` |

Rules are **tagged** with the control(s) they satisfy; the gate emits a **VSA** listing which controls
passed / failed / were unprovable. This gives Valint-style explainability and gap-exposure **without** building
a full GRC engine — the enforced rule set stays lean.

---

## First-proposal focus

Do **not** attempt full framework coverage. Focus the first proposal on the three slices that are
artifact-provable *and* externally driven:

1. **SLSA** — claim L1 honestly, name the L2/L3 path.
2. **CRA / BSI TR-03183-2 SBOM fields** — the generator backlog above (a real regulatory driver; and CRA names firmware).
3. **Reconcile** — the differentiator.

Lead the *regulatory* justification with **EU CRA + BSI TR-03183-2** (firmware-inclusive, still hardening),
**not** EO 14028 — **OMB M-26-05 (Jan 2026) rescinded** the US self-attestation mandate (M-22-18/M-23-16).

## Sources

SLSA: https://slsa.dev/spec/v1.0/levels · https://slsa.dev/spec/v1.0/requirements · VSA https://slsa.dev/spec/v0.1/verification_summary
in-toto: https://github.com/in-toto/attestation · Ratify: https://ratify.dev/docs/1.0/reference/rego-templates/ · Gatekeeper ExternalData: https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata/
Witness/Archivista: https://github.com/in-toto/witness/blob/main/docs/concepts/policy.md · Valint: https://github.com/scribe-security/gatekeeper-valint · JFrog Evidence: https://docs.jfrog.com/governance/docs/evidence-management
Anchore VIPERR: https://anchore.com/blog/introducing-viperr-the-first-software-supply-chain-security-framework-for-all/ · Chainguard: https://github.com/chainguard-dev/policy-catalog · GUAC: https://guac.sh/guac/ · Venafi/CyberArk: https://www.cyberark.com/venafi-and-cyberark-machine-identity-security/
SSDF: https://csrc.nist.gov/pubs/sp/800/218/final · 800-161r1: https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final · S2C2F: https://github.com/ossf/s2c2f/blob/main/specification/framework.md · SCITT: https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/
NTIA 2021: https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom · CISA 2026: https://www.cisa.gov/resources-tools/resources/2026-minimum-elements-software-bill-materials-sbom
CycloneDX 1.6: https://cyclonedx.org/news/cyclonedx-v1.6-released/ · CDXA: https://cyclonedx.org/capabilities/attestations/ · CoSWID: https://www.rfc-editor.org/rfc/rfc9393.html · OpenVEX: https://github.com/openvex
CRA: https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847 · BSI TR-03183-2 v2.1.0: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.html · BSI CDX taxonomy: https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy · OMB M-26-05: https://www.dwt.com/blogs/privacy--security-law-blog/2026/02/omb-changes-course-on-software-security
SP 800-193: https://csrc.nist.gov/pubs/sp/800/193/final · SP 800-155 (draft): https://csrc.nist.gov/pubs/sp/800/155/ipd · TCG RIM: https://trustedcomputinggroup.org/resource/tcg-pc-client-reference-integrity-manifest-specification/ · RATS RFC 9334: https://www.rfc-editor.org/rfc/rfc9334.html · CoRIM: https://datatracker.ietf.org/doc/draft-ietf-rats-corim/
Reconcile prior art: https://developer.harness.io/docs/software-supply-chain-assurance/sbom/sbom-drift/ · https://www.sciencedirect.com/science/article/pii/S2405959526001086
OSCAL: https://pages.nist.gov/OSCAL/
