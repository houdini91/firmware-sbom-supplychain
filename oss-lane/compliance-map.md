# Compliance map — the enforced subset

This is the **enforced subset**: the checks the OSS-lane deploy gate
([`policy/firmware.rego`](./policy/firmware.rego)) **hard-blocks the release on**. The full
framework → control → evidence → status map (every framework, with exact section numbers and honest
partial/planned/futuristic coverage) lives in [`../FRAMEWORKS.md`](../FRAMEWORKS.md); the forward plan is in
[`../EVIDENCE-ROADMAP.md`](../EVIDENCE-ROADMAP.md).

Each OSS-lane check emits a normalized **verifier report** (`{name, isSuccess, message, controls}`); the gate
ANDs `isSuccess` and emits the verdict as a signed **SLSA VSA**. The **Valint lane** runs the same intent
keyless in **report mode** (non-blocking) via its rule bundle — a second, independent tool over the *same*
evidence, not a second enforcement point.

## The seven gate reports (what the release is blocked on)

| Verifier report | Enforces | Control tags | Valint-lane rule |
|---|---|---|---|
| `sbom-present` | an SBOM is attached to the artifact | CRA Annex I §II(1), CISA-2026, NTIA-2021 | `sbom/require-sbom`, `ssdf/ps-3.2-archived-sbom` |
| `attestation-signature` | evidence is keyless-signed; signer identity checked | SSDF PS.2.1, in-toto DSSE | `sbom/artifact-signed`, `ssdf/ps-2-image-verifiable` |
| `sbom-binding` | SBOM digest == signed subject (no post-sign swap) | in-toto subject binding | `generic/evidence-exists` |
| `provenance-identity` | built by the expected builder + source | SLSA L1, SSDF PS.3 | `slsa/l1-provenance-exists` |
| `slsa-provenance` | SLSA **L2** provenance verified (platform-generated) | SLSA L2, SSDF PO.3.3 | `slsa/l2-provenance-authenticated` |
| `reconcile` | shipped bytes match the declared SBOM | reconcile (this project) | `generic/evidence-exists` |
| `cve-triage` | no un-triaged critical CVE | NIST 800-161, OpenVEX | `sarif/trivy/verify-cve-severity` |

Framework **initiative bundles** (whole-framework runs) live in the Valint bundle: `slsa.l1`, `slsa.l2`,
`ssdf`, `sp-800-53`, `sp-800-190` (`valint verify … --initiative-name <name>`).

## Honest scope

The OSS lane authenticates the builder's **keyless OIDC identity** (the signer SAN is extracted from the
Fulcio cert and *checked*, not asserted), and enforces composition (`reconcile`), the SBOM↔signed-subject
binding, the CVE/VEX gate, and — since the repo is public — **SLSA Build L2** provenance:
`actions/attest-build-provenance` generates it platform-side, `gh attestation verify` hard-gates it in CI,
**and** the `slsa-provenance` verifier report asserts it so the VSA lists it. All seven reports are tested in
CI and recorded in the VSA. The offline demo cannot run `attest-build-provenance`, so L2 there is an opt-in
assumption (`DEV_ASSUME_SLSA`, loudly warned). SBOM-field completeness (licenses/PURLs/submodules) and
code-analysis (SAST, `codeql-sast`) evidence are mapped and being wired, not all enforced yet — see
[`../FRAMEWORKS.md`](../FRAMEWORKS.md) and [`../EVIDENCE-ROADMAP.md`](../EVIDENCE-ROADMAP.md).
