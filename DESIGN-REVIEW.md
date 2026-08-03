# Design review — is this a clean, evidence-centric supply-chain solution?

A holistic review of the whole solution (evidence model, controls, adoptability), synthesizing three independent
reviews. Verdict-first, then the prioritized plan. Companion to [`FRAMEWORKS.md`](./FRAMEWORKS.md) (control map),
[`POLICY-EXPANSION.md`](./POLICY-EXPANSION.md) (rule set), and [`EVIDENCE-ROADMAP.md`](./EVIDENCE-ROADMAP.md).

## Verdict

**The engine is strong; the packaging and the anchoring are the gaps.** What's already good and worth keeping:
the **enforcement** (17 OPA verifier reports → a signed SLSA VSA), the **fully-open stack** (cosign keyless +
Rekor + OPA/Rego + in-toto + VSA — no proprietary lock-in), and the **honesty discipline** (every rule has a
negative fixture; `N/A`/`FUTURISTIC` are named, not hidden). The Valint review confirmed our *verification logic
is not inferior* — Valint runs OPA under the hood too.

Five concrete gaps keep it from being a *clean, evidence-centric* solution:

1. **Evidence is not uniformly in-toto.** Only E2 (SLSA provenance), E3 (reconcile), E6 (VSA-as-JSON) are proper
   in-toto Statements. E7 and the VSA are `cosign sign-blob`'d (a *detached signature*, not an attestation);
   E1/E4/E10 are bare files. (E5 isn't evidence at all — it's the signing envelope/identity.)
2. **Everything anchors to the SBOM *file* digest, not the firmware.** The attestation `subject` is
   `sha256(sbom.cdx.json)`; the SBOM's firmware component carries **0 hashes**; reconcile never records the
   image digest it carved. So we can prove "evidence about this JSON," not "evidence about firmware `sha256:X`."
3. **No framework/initiative layer.** We emit a flat set of 17 verdicts; there's no declarative
   `framework → control → rule` map, so a reviewer can't see per-framework coverage or "control SI-7 is
   satisfied by verifiers X+Y."
4. **No "missing evidence" state.** An enforcing gate collapses "attestation absent" and "attestation failed"
   into one FAIL — hiding the most important supply-chain signal (a *gap*) inside ordinary failures.
5. **CI-only.** The gate fires at build time; there's no consumer/relying-party or flash/provision-time gate,
   and the evidence doesn't yet speak the firmware vendor's own tooling.

None are deep; all have a clear path. The keystone fixes #1 and #2 at once.

---

## The clean evidence model (fixes #1, #2)

**Anchor = the firmware image digest, used as the `subject` of every image-scoped attestation.** That single
change makes evidence bind to the *artifact that gets flashed*, and turns discovery into "give me every DSSE
whose subject == the image digest."

Per-evidence target (`_type` is always `https://in-toto.io/Statement/v1`):

| E | Evidence | `predicateType` | `subject` | Signed as | Today |
|---|---|---|---|---|---|
| E1 | CycloneDX SBOM | `https://cyclonedx.org/bom` | **image digest** | `attest-blob --type cyclonedx` | bare file |
| E2 | SLSA provenance | `https://slsa.dev/provenance/v1` | image digest | attest-build-provenance | ✅ |
| E3 | Reconcile | custom `…/reconcile/v1` (or in-toto **SCAI**) | image digest | `attest-blob` | ✅ (re-point subject off SBOM) |
| E4a | CVE (grype) | `https://in-toto.io/attestation/vulns/v0.2` | image digest | `attest-blob --type vuln` | bare file |
| E4b | OpenVEX | `https://openvex.dev/ns/v0.2.0` | image digest | `attest-blob --type openvex` | bare file |
| E4c | CSAF | *(format, not a predicate)* → **reference from E4b**, don't mint a 2nd VEX attestation | — | export | bare file |
| E6 | SLSA VSA | `https://slsa.dev/verification_summary/v1` | image digest | `attest-blob` (**not** sign-blob) | ⚠ sign-blob |
| E7 | Build-tools SBOM | `https://cyclonedx.org/bom` | image digest (toolchain-tagged) | `attest-blob` (**not** sign-blob) | ⚠ sign-blob |
| E8 | CodeQL SARIF | in-toto **test-result/v0.1** (SARIF embedded) | **source commit** | `attest-blob` | ⚠ sign-blob |
| E9 | Scorecard SARIF | in-toto **SVR** (Simple Verification Result) | source commit | `attest-blob` | ⚠ sign-blob |
| E10 | CHIPSEC posture | custom `…/chipsec-posture/v1` (or SCAI) | image digest | `attest-blob` | ⚠ unsigned JSON |

Two honest spec findings: **there is no registered in-toto predicate that carries SARIF** — E8/E9 use the
generic test-result/SVR predicates (a standardized SARIF predicate would be an *upstream in-toto proposal*, not
a quick win); and **source-scoped evidence (E8/E9) must bind through the provenance, not a faked image digest** —
their `subject` is the source commit, which appears in the provenance's `resolvedDependencies` (whose subject is
the image). Don't overload the provenance with downstream evidence; `resolvedDependencies` = build inputs
(source commit, vendored submodules, E7), `byproducts` = logs.

**Discovery/binding mechanism:** attach every predicate as an **OCI referrer** of the image (Ratify model) and
have the gate *discover → DSSE-verify → dispatch by `predicateType`* — which maps 1:1 onto the existing
`verifier_reports[]` (the rego is already shaped like a Ratify executor; it's just fed from files today). Rekor
backs it now; **SCITT** is the horizon transparency layer. Then `evidence-chain-bound` generalizes from a
hardcoded 3-way string compare to a *property of ingest*: "every DSSE-verified subject == the anchor digest."

**Embedded VEX (compliance edge, your call):** CycloneDX 1.6 carries VEX natively (`vulnerabilities[].analysis`),
so we can *also* embed the disposition in E1 — one signed artifact = composition + exploitability. Honest nuance:
BSI §8.1.14 wants VEX *separate* (CSAF). So do **both** — embed in CDX for the CDX-native story, keep standalone
OpenVEX→CSAF for BSI. Serving both conventions is itself an edge.

---

## The framework/initiative layer (fixes #3, #4) — adopt Valint's *structure*, not its stack

The Valint review's core lesson: our gap is the **catalog + framework layer**, pure packaging over what we
already compute. Adopt:

- **Initiatives:** a declarative `framework → control → rule` manifest (SLSA / SSDF / 800-53 / 800-190 / CRA /
  BSI) mapping our 17 verifiers to real control IDs with "why this control" prose; fold `control_id →
  satisfied_by[]` into the VSA `predicate`. One rule set, many frameworks. **This is what powers the verifier CLI
  below.**
- **Three-state verdict:** `PASS / FAIL / MISSING_EVIDENCE(required)` — each rule declares the predicate it
  consumes (`content_body_type`, `signed`, scope); surface a "required-but-absent evidence" list in the VSA.
- **Versioned rule catalog** (`ns/name@vN` + a metadata sidecar: help, labels, typed `inputs`, evidence
  requirement) and a **standard verdict schema** + shared rego lib, so verifier #17 is boilerplate-free.
- **Per-rule `level: warn|error`** — the clean on-ramp to move the Valint lane from report → enforce one rule at
  a time; and a **`stages` completeness** initiative that fails if any expected pipeline stage produced no
  attestation (catches skipped-step attacks content checks miss).

Keep our advantages explicit: the **VSA** (open in-toto, cleaner interop than Valint's SARIF), **cosign+Rekor**
(open vs. the proprietary hub), and the **enforcing** posture.

---

## The headline capability — a consumer "supply-chain verifier" (CHIPSEC-like UX)

The money-shot that ties it together: a CLI a firmware engineer runs against *their own* firmware and gets a
**per-framework verdict**, exactly like running `chipsec_main` but for supply-chain + compliance:

```
fw-supplychain-verify OVMF.fd --evidence bundle/ --frameworks slsa,ssdf,cra,bsi,800-53
→ hash firmware → verify evidence binds to THAT digest → verify signatures (cosign/Rekor)
→ run the initiatives → scorecard:  SLSA L2 ✓ · SSDF PS.2 ✓ · CRA §II(1) ✓ · BSI ◐ · SI-7 ✓
```

It consumes exactly the three things above — the **firmware-digest anchor** (prerequisite), the **initiative
layer** (per-framework verdict), and the **relying-party** model. It's also the *consumer* half of the RATS
framing: CI produces the passport (VSA); this is a relying party appraising it.

---

## Beyond-CI: a flash/provision-time gate + firmware-vendor-native evidence (fixes #5)

**Speak the vendor's own tooling** (the more they recognize it, the more adoptable), ranked by
adoptability-per-effort:

- **Tier 1 (do first):** package the firmware as an **fwupd/LVFS `.cab` + `metainfo.xml` + Jcat signature** (the
  single biggest recognizability jump — and it feeds the flash gate); **UEFIExtract/uefi-firmware-parser** as a
  *corroborating* second carve for reconcile (OPA requires FMMT + UEFIExtract to agree); **swtpm measured-boot
  event log + PCR0–7**; SPDX + CycloneDX firmware/lifecycle profiles.
- **Tier 2:** **CoRIM/RIM reference values** generated from our build, appraised against the swtpm event log (the
  marquee RATS upgrade — "did what CI approved actually boot as expected?"); **EMBA** as an image-derived
  SBOM+CVE source; coreboot `ifdtool`/`cbfstool` (if a coreboot target is added).
- **Tier 3 (label as aspirational / real-hardware-only):** Intel Boot Guard/FIT/FSP, AMD PSB (`psptool`), UEFI
  Secure Boot **dbx** cross-check, FACT/ONEKEY ingestion — inert under QEMU, honest as "parse-and-assert on a
  real platform image."

**The flash/provision-time gate** (RATS relying party): a `flash-gate.sh` standing in for the flasher /
provisioning station that, *before writing bytes to SPI*, independently verifies signatures + the **VSA**
(`verificationResult == PASSED`) + OPA (digest ∈ approved set, reconcile match, no un-VEXed critical CVE, dbx OK),
then — only on `allow` — "flashes" (guarded `flashrom -w`) and emits a **signed provisioning attestation**; then
boots under swtpm and appraises measured boot against the CoRIM reference values. The same OPA/attestation
discipline now fires at **flash time, provisioning, and first boot** using tools the audience already owns.

---

## Upstream engagement (contribution-backed, reference-first)

- **edk2 #10507** — the `-Y SBOM` generator (fork PR #6) — held for a maintainer signal (Richard on uSWID #98).
- **CHIPSEC engagement (verified against release 2.0.7 source, not assumed).** CHIPSEC does **not** verify
  firmware signatures today — its Secure Boot module checks mechanism *posture* (Secure Boot enabled, PK/KEK/db
  present + authenticated-write + write-protected), there's no Boot Guard/FIT/KM/BPM parser, and there's zero
  crypto-verification code anywhere. So *"is this firmware artifact authentically built + backed by verifiable
  supply-chain evidence"* is a **genuine, unfilled gap** (0 prior issues/PRs/discussions across all supply-chain
  terms). Crucially, CHIPSEC **already ships the exact architectural pattern** the module needs: offline,
  image-file, PASSED/FAILED `tools/uefi/` modules that reconcile an image against an external trust oracle —
  `scan_image.py` (golden allow-list ≈ our reconcile), `scan_blocked.py` (hash/GUID deny-list), `reputation.py`
  (VirusTotal oracle), all runnable with `-i -n` (no driver). **The pitch: an evidence-verification `tools/uefi/`
  module that trusts a *signed SBOM/SLSA attestation* instead of an AV cloud** — same shape, stronger oracle,
  reusing `decode_uefi_region`/`build_efi_model`. Honest seam to own up front: it wouldn't touch CHIPSEC's
  hardware layer and adds crypto + network (Rekor) deps the project deliberately avoids — so lead with the
  `reputation.py` precedent and offer a companion-tool fallback. Open as an **[Ideas] Discussion** (the venue used
  by the existing **#1400 LVFS/HSI collaboration** thread — a receptive precedent tied to Richard Hughes'
  ecosystem), DCO sign-off, reference-first — after the firmware-digest binding is clean. Our
  `chipsec-lane/to-predicate.py` (CHIPSEC results → signed attestation) is the complementary direction and a
  ready reference.

---

## Prioritized plan

**Tier 0 — the keystone (biggest integrity payoff).** ✅ **IMPLEMENTED (2026-08-03).** `D = sha256/sha512(OVMF.fd)`
= `sha256:374472f0…c8e0ce` now drives the anchor. Done: the `-Y SBOM` generator hashes each built FD and writes the
primary image's `D` into `metadata.component.hashes` (verified: it selects `OVMF.fd` and reproduces `D`); the demo
SBOM + reconcile predicate (`image_digest`) carry `D`; a new `firmware-digest-anchor` verifier report (17th) hard-blocks
unless `SBOM D == reconcile image_digest == the deployed .fd`. Leg 1 is the generator's build-time hash; leg 2 is
`sbom-reconcile --image` independently re-hashing the carved image (a genuine second measurement); leg 3 is the
deployed image hashed at flash/verify time via `FW_IMAGE` (assumed in CI + the offline demo, which don't rebuild
OVMF). Demonstrated against the real `.fd` via `FW_IMAGE` → gate ALLOW; a mismatched deployed digest → the sole
failing report → DENY. **Still open (deeper refactor):** making
`D` the *primary in-toto `subject`* of every image-scoped attestation (the multi-subject/`resolvedDependencies`
discipline below) — that's Track A4, not yet done. The remaining Tier-0 bullets describe that follow-on:
- The `-Y SBOM` generator writes `D` into `metadata.component.hashes` (+ a real `bom-ref`) so the SBOM
  **self-declares which firmware bytes it describes**.
- `D` becomes the **primary `subject`** of every image-scoped attestation. `subject` is an *array* — use
  **multi-subject**: `[{OVMF.fd: D}, {sbom: H}]` on the provenance / SBOM / reconcile; `D` only on
  CVE/VEX/VSA/CHIPSEC/build-tools; **source-commit** on SAST/Scorecard. The firmware is the build **output**, so
  it must be a `subject` — **never `resolvedDependencies`** (that's strictly for build *inputs*, and it would
  break `gh attestation verify OVMF.fd`); the SBOM is a secondary subject / provenance `byproduct`.
- The reconcile predicate records `image_digest: D` (+ per-region digests) — the one tool that touched the `.fd`
  bytes must record which bytes it validated, not just `validated: 123`.

This unlocks the verifier CLI and adds a check the current model **cannot express**:
`SBOM.metadata.component.hashes == D == the deployed .fd` — "the SBOM describes *these* firmware bytes," not
merely "this JSON was signed." The gate's anchor digest becomes `D` (from the verified provenance/SBOM), not
`sha256(sbom.cdx.json)`. *(A firmware-security reviewer probes for exactly this first.)*

**Tier 1 — uniform in-toto + the initiative layer (days, pure packaging):**
- `sign-blob → attest-blob` for E6/E7; wrap E1/E4/E10 as DSSE Statements (subject = image digest); collapse CSAF
  into an E4b reference; drop E5 as an "evidence" row.
- Add the declarative **initiative** manifests + `control_id → satisfied_by[]`/`missing_evidence[]` in the VSA;
  versioned rule catalog + standard verdict schema; per-rule `warn|error`.
- Embed VEX in the CycloneDX (keep CSAF too).

**Tier 2 — evidence-centric gate + the verifier CLI (1–2 weeks):**
- Ingest only **DSSE-verified** payloads (confine unverified data to the `DEV_ASSUME_*` boundary); generalize
  `evidence-chain-bound` to "all verified subjects == anchor," with the E8/E9 source-commit exception via
  `resolvedDependencies`; attach evidence as **OCI referrers** (Ratify-style discovery).
- Ship **`fw-supplychain-verify`** — the consumer per-framework scorecard CLI.
- Firmware-native Tier-1 evidence: fwupd `.cab`+Jcat, UEFIExtract corroborating carve, swtpm measured boot.

**Tier 3 — flagship + horizon:** CoRIM measured-boot appraisal; `flash-gate.sh` (beyond-CI relying party); the
CHIPSEC attestable-evidence discussion; then (project-scale, name-don't-pretend) full Ratify, SCITT receipts, and
a standardized SARIF/reconcile in-toto predicate proposal.

## What to keep (don't over-rebuild)

cosign keyless + Rekor + OPA/Rego + in-toto + the signed VSA (open, no lock-in); the enforcing posture; the
per-rule negative-fixture honesty discipline. The plan is **structure and anchoring on top of a sound engine** —
not a rewrite.
