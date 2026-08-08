# Compliance map — the enforced subset

This is the **enforced subset**: the checks the OSS-lane deploy gate
([`policy/firmware.rego`](./policy/firmware.rego)) **hard-blocks the release on**. The full
framework → control → evidence → status map (every framework, with exact section numbers and honest
partial/planned/futuristic coverage) lives in [`../FRAMEWORKS.md`](../FRAMEWORKS.md); the forward plan is in
[`../EVIDENCE-ROADMAP.md`](../planning/EVIDENCE-ROADMAP.md).

Each OSS-lane check emits a normalized **verifier report** (`{name, isSuccess, message, controls}`); the gate
ANDs `isSuccess` and emits the verdict as a signed **SLSA VSA**. The **Valint lane** runs the same intent
keyless in **report mode** (non-blocking) via its rule bundle — a second, independent tool over the *same*
evidence, not a second enforcement point.

## The gate reports (what the release is blocked on)

The release is hard-blocked on **30 verifier reports**. To keep one source of truth, they are **not
re-tabulated here** — the authoritative list lives in two places that cannot drift from the gate:

- **Mechanism (canonical):** [`policy/firmware.rego`](./policy/firmware.rego) — the `verifier_reports` array
  *is* the gate; each report carries its own `controls[]` tags.
- **Prose + evidence mapping:** the "trust anchor" paragraph in [`../FRAMEWORKS.md`](../FRAMEWORKS.md) names all
  24 and the evidence atom (E1–E10) each consumes.
- **Framework → control → report (machine-readable):**
  [`initiatives/frameworks.yaml`](./initiatives/frameworks.yaml), consumed by
  [`verify-initiative.py`](./verify-initiative.py) to print per-framework, per-control coverage from a signed VSA.

The **Valint lane** mirrors the core subset (`sbom-present`, `attestation-signature`, `sbom-binding`,
`provenance-identity`, `slsa-provenance`, `reconcile`, `cve-triage`) keyless in report mode via its rule
bundle, plus whole-framework **initiative bundles** (`slsa.l1`, `slsa.l2`, `ssdf`, `sp-800-53`, `sp-800-190`).

## Honest scope

The OSS lane authenticates the builder's **keyless OIDC identity** (the signer SAN is extracted from the
Fulcio cert and *checked*, not asserted), and enforces composition (`reconcile`), the SBOM↔signed-subject
binding, the CVE/VEX gate, and — since the repo is public — **SLSA Build L2** provenance:
`actions/attest-build-provenance` generates it platform-side, `gh attestation verify` hard-gates it in CI,
**and** the `slsa-provenance` verifier report asserts it so the VSA lists it. All 25 reports are tested in
CI (one isolating negative fixture each) and recorded in the VSA. The offline demo cannot run `attest-build-provenance`, so L2 there is an opt-in
assumption (`DEV_ASSUME_SLSA`, loudly warned). SBOM-field completeness (licenses/PURLs/submodules) and
code-analysis (SAST, `codeql-sast`) evidence are mapped and being wired, not all enforced yet — see
[`../FRAMEWORKS.md`](../FRAMEWORKS.md) and [`../EVIDENCE-ROADMAP.md`](../planning/EVIDENCE-ROADMAP.md).
