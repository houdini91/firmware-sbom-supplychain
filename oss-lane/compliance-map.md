# Compliance map — one gate, many frameworks

The gate is a policy engine, so "supporting a compliance framework" means expressing that framework's
controls as rules over the same firmware evidence (SBOM + reconcile verdict + provenance + CVE scan). This
repo implements the **custom firmware-composition** policy end-to-end; the table shows how the same evidence
satisfies clauses of other frameworks, in both lanes.

| Control (framework) | What it asks | OSS lane — rego clause | Valint lane — rule |
|---|---|---|---|
| **SLSA L1** provenance exists | build produced provenance | `input.provenance` present | `slsa/l1-provenance-exists@v2` |
| **SLSA L2** provenance authenticated | provenance signed by a hosted builder | `signature.verified ∧ provenance.builder_id == expected` | `slsa/l2-provenance-authenticated@v2` |
| **NIST SSDF PS.2** (SP 800-218) — protect/verify software integrity | artifact is verifiable & signed | `signature.verified` | `sbom/artifact-signed@v2`, `ssdf/ps-2-image-verifiable@v1` |
| **NIST SSDF PS.3** — archive & protect each release, provide SBOM | SBOM present for the release | `sbom.present` | `ssdf/ps-3.2-archived-sbom@v1` |
| **BSI TR-03183-2** — SBOM completeness (NTIA min elements) | every component has name/version/supplier/ids | (extend `firmware.rego` with a completeness check over the SBOM) | `sbom/NTIA-compliance@v2` |
| **Composition truth** (this project) | shipped bytes == declared SBOM | `reconcile.clean` | *(reconcile verdict carried as generic evidence; gated with `generic/evidence-exists@v2`)* |
| **Known-vuln gate** | no critical CVE ships | `count(critical_cves) == 0` | `sarif/trivy/verify-cve-severity@v2` |

Framework **initiative bundles** (whole-framework runs) live in the Valint bundle under `v2/initiatives/`:
`slsa.l1`, `slsa.l2`, `ssdf`, `sp-800-53`, `sp-800-190`. Run one with
`valint verify … --initiative-name <name>`.

**Honest scope:** the OSS lane authenticates the builder's **keyless OIDC identity** over the signed
evidence (the authenticity core of SLSA L2 — the signer SAN is extracted from the Fulcio cert and checked,
not asserted), and enforces composition (reconcile), the SBOM-hash↔signed-subject binding, and the CVE/VEX
gate — all tested in CI. It does **not** yet emit a full SLSA *provenance predicate* (buildType / invocation
/ materials); adding one via `cosign attest-blob --type slsaprovenance` or `actions/attest-build-provenance`
is the documented next step. NTIA/BSI completeness and the SSDF repo-posture controls are *mapped* here (the
rules exist in the Valint bundle); wiring each end-to-end is future work, not claimed as done.
