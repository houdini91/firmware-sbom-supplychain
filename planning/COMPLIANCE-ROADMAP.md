# Compliance Roadmap — next cycle (all 6 frameworks)

Consolidated from a critical per-framework gap+cost review (2026-08-07). Scope held throughout:
this is an **operator-side admission verifier** — reconcile shipped firmware bytes vs the SBOM's
per-module declared hashes → keyless SLSA VSA anchored to the firmware image digest → map to controls.
Not a build platform, not a generator, not an on-device Root of Trust. `S/M/L` = effort; **"free"** = a
manifest/text/mapping change to a check that already runs.

---

## A. Fix-now — honesty & consistency (free; no new code)

These are current over-reaches or drifts an auditor reading the *manifest alone* would catch. Same class
as the CISA-2026 label fix. Recommend doing these before the additive work.

| # | Item | Fix | Where |
|---|------|-----|-------|
| A1 | **S2C2F AUD-3 drift** — `FRAMEWORKS.md` claims AUD-3 enforced via `component-byte-integrity`, but the manifest doesn't map it, so coverage never counts it | add AUD-3 → `[component-byte-integrity, reconcile-membership]` | `frameworks.yaml` |
| A2 | **SLSA `verifiedLevels:[L2]` conflation** — the VSA stamps L2 on a **firmware-subject** attestation, but L2 is about the **SBOM artifact's** build. The machine-readable field carries none of the prose scope caveat → a consumer reads "firmware is L2" | scope the level to the SBOM artifact (annotate the VSA field / claim), matching the honest prose in `FRAMEWORKS.md` | VSA emit (`firmware.rego` ~590) |
| A3 | **SP 800-193 §4.2 description over-reach** — manifest control text lacks the caveat `FRAMEWORKS.md` carries (QEMU/OVMF target, **no HW root of trust**, `chipsec.json` is **sample data**, 4/8 critical NOTAPPLICABLE) | port the caveat text into the manifest control `description` | `frameworks.yaml` |
| A4 | **CRA Annex I II(1) presence-only** — gates only "SBOM exists" but the control text says *"covering at least the top-level dependencies"* | add `reconcile-membership` to `satisfied_by` (proves the declared set is real) | `frameworks.yaml` |
| A5 | **`chipsec-posture` on sample data** — a hard blocking fact derived from illustrative, not live, CHIPSEC data | label the input as sample/illustrative in the VSA/report note | assembler / report note |
| A6 | **Do NOT map SR-11 (component authenticity)** — it's an anti-counterfeit *program*, not byte-integrity; keep N/A(process). Pre-empt the temptation. | (no change — a guard rail) | — |

---

## B. Next-cycle, high-value + cheap (S — evidence already exists)

| # | Addition | Framework | New verifier | Evidence (already produced) |
|---|----------|-----------|--------------|------------------------------|
| B1 | **`sbom-generation-tool` + `sbom-generation-context`** → CISA-2026 **2/4 → 4/4** new elements gated | CISA 2026 | 2 small rego reports + 2 assembler fields + 2 negative fixtures | SBOM `metadata.tools` (`edk2 BuildReport (-Y SBOM)`), `metadata.lifecycles[].phase` |
| B2 | **CM-8 base mapping** — `reconcile-membership` proves declared-inventory == observed-bytes (stronger CM-8 evidence than most tools have) | SP 800-53 | mapping only | E1 + E3 |

> Honesty ceiling on B1: gating "`metadata.tools` present + named" proves the SBOM *declares* a generating
> tool, not that that tool produced it — the same asserted-not-attested ceiling as `vex-adjudicated`. That
> is exactly what the CISA element asks (field presence), so it's legitimate; don't let it read as tool-provenance.

---

## C. Next-cycle, strategic (M — new plumbing, no new evidence *class*)

| # | Addition | Framework | What it takes | Note |
|---|----------|-----------|---------------|------|
| C1 | **SP 800-193 §4.3.1 Detection** (admission-time, off-device, caveated) via a new **`firmware-freshly-measured`** report | SP 800-193 | boolean distinguishing a **real flash-time `FW_IMAGE`** from `DEV_ASSUME_FWIMAGE` + 1 report + mapping + ceiling doc | **The biggest strategic expansion** (only Protection is claimed today). Only honest **with** the fresh-measurement gate — offline it must report *not-satisfied*, or it's conformance theater. §4.3.2 (data) and §4.4 (Recovery) stay out of scope. |
| C2 | **`sast-clean` / SA-11(1)** — fold the already-running CodeQL SARIF into a `verifier_report` | SSDF (PW.7/PW.8), SP 800-53 (SA-11(1)) | SARIF→fact normalizer + 1 rego report + mapping | The scan already runs in CI but is **not carried by the signed VSA** — a seam between "CI green" and the portable verdict. |
| C3 | **`firmware-provenance-binding`** — require the builder's SLSA provenance to name firmware `D` as a subject | SLSA, SP 800-53 SR-4(3) | 1 rego report + assembler surfaces predicate fields | Today the L2 provenance attests the **SBOM JSON**, not the firmware bytes. Worth more than chasing L3. |

---

## D. Deferred / out of scope (L / L+)

| Item | Why deferred |
|------|--------------|
| Per-component **supplier** + **submodule dependency graph** (SR-4(4) pedigree, CISA/BSI completeness) | Needs new SBOM fields — **generator/producer-side work** (edk2 `-Y SBOM`), not the verification gate. L. |
| **On-device RTD**: TPM quote + golden RIM → full §4.3/§4.4 Detection/Recovery, RATS | New **evidence class**; **Recovery is permanently out of scope** for a verification gate (it can supply a known-good reference, not restore). L+. |
| **SLSA L3** | A property of the **build platform** (hermetic/isolated builder). A verifier cannot make someone else's firmware build L3. Out of scope for the firmware; low value for the tool's own artifact. |

---

## The three moves to do first (cheapest × highest value)

1. **A1 (free)** — map S2C2F **AUD-3** in the manifest (fixes a claim/reality drift to a check already passing 122/123).
2. **B1 (S)** — **`sbom-generation-tool` + `sbom-generation-context`** → completes **CISA-2026's four new elements** with evidence already in the SBOM.
3. **C1 (M)** — **SP 800-193 §4.3.1 Detection** *with* the `firmware-freshly-measured` honesty gate — the one addition that materially expands what the tool can credibly claim.

**Boundary line:** everything S/M reuses evidence the tool already produces (next cycle). Supplier/submodule
pedigree and the on-device RTD stack need new evidence or generator work — the former belongs to the
producer side, the latter (especially Recovery) is permanently out of a verification gate's remit.
