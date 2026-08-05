# A2 + A4 — combined plan: standards-aligned evidence graph rooted at `D`

**One task** (A2 and A4 collide on `gate.sh:49-70` + `firmware.rego:537-548`, so they're
executed as a single coherent refactor), run in **two internal phases** with a green-tests
checkpoint between them. Nothing is edited until this plan is signed off.

## Context / why
Today the gate emits a **custom** predicate (`oats.tech/policy-verdict/v0.1`) whose in-toto
**primary subject is the SBOM *file* digest `H`**, not the firmware image `D`; `D` rides only
as a *secondary* `firmware-image` subject and inside some predicates. Evidence signing is a mix
of `attest-blob` (reconcile) and detached `sign-blob` (VSA, build-tools) with **no `D` subject**.
The initiative layer recomputes `control → satisfied_by[]/missing_evidence[]` *downstream* in
`verify-initiative.py` rather than carrying it in the signed predicate. Goal: a **verifiable
evidence graph rooted at `D`**, using standard in-toto/SLSA shapes.

## Locked decisions (research-backed; user-chosen 2026-08-05)
1. **Top-level = standard SLSA VSA** — `predicateType: https://slsa.dev/verification_summary/v1`
   (v1.2 schema), `subject = D`, `verificationResult` PASSED/FAILED, coarse control outcomes as
   **custom non-`SLSA_`-prefixed `verifiedLevels` tokens** (e.g. `OATS_BYTEINTEGRITY_PASS`),
   `inputAttestations[]` referencing each evidence attestation by `{uri,digest}`.
2. **Rich per-control data rides as EXTENSIONS on the standard VSA** (chosen 2026-08-05, "option B").
   in-toto/SLSA predicates are **explicitly extensible**, so the VSA carries the standard summary
   (`verificationResult`, `verifiedLevels`) *and* `verifierReports[]` + `controlAssessments[]` (with
   `description`/`citation`/`satisfied_by`/`missing_evidence`) as documented extensions. A SLSA-VSA consumer
   reads the summary; our CLI/initiative layer reads the detail. **No separate bespoke companion predicate**
   (that would be throwaway when CDXA lands) and **no consumer churn**.
   **DE-COUPLED:** a later **CDXA/SARIF** rendering (see **A2b** in TODO) is an *added format over the same
   engine + data*, **not a replacement** — the VSA-with-extensions stays. That's the deferred step.
3. **`subject = D` primary on every image-scoped attestation**, built via
   `cosign attest-blob --statement <self-built Statement>` — pin **cosign ≥ 2.6.0**;
   `--new-bundle-format` for offline verification; **never `--type custom`** (it wraps the predicate).
4. **Per-evidence predicate types:** SBOM → `cyclonedx.org/bom` (match emitter); provenance →
   `slsa.dev/provenance/v1`; reconcile/byte-integrity verdict → SVR `in-toto.io/attestation/svr/v0.2`
   (or a pinned `oats.tech/...`); CHIPSEC → `test-result/v0.1` or SCAI; VEX → `openvex.dev/ns`.
5. **Versioned rule IDs** (`oats/<name>@v1`) on the 19 reports (A2 sub-item 2).
6. **CSAF** has no in-toto predicate → referenced from the OpenVEX attestation, not a second VEX
   attestation. **E5 dropped as an evidence row** (it's the signing envelope; its 3 gate reports stay).
7. **A2b-Minimal folds INTO A2** (design agent, 2026-08-05; `planning/framework-aware-output-design.html`).
   The reuse problem is ~80% solved already (the reusable atom is the *rule*; `frameworks.yaml` already points
   many controls' `satisfied_by` at one report). So the only additions are per-control **`description`** +
   per-framework **`citation`/language** in `frameworks.yaml` (they already flow into `control_assessments` →
   the signed verdict), plus one forward-compat `canonical`/`openCre` key. **Skip Moderate** (canonical catalog +
   resolver — ceremony without payoff at 6 frameworks / 27 controls); **Full = CDXA** is the deferred end state,
   gated on the deferred verdict-format decision.
8. **Fix the drifted control vocabularies (genuine bug).** The rego `_report(...)` `controls` tags and the
   `frameworks.yaml` control ids are two un-reconciled vocabularies that have diverged (e.g. rego tags
   `component-byte-integrity` with `S2C2F-AUD-3`, but the `s2c2f` block defines no AUD-3). **Derive the rego
   tags from the manifest** (invert `satisfied_by`) so there is one source of truth. Lands in the A2 pass.

## Target graph
```
VSA (slsa.dev/verification_summary/v1)  subject=D
  ├ verificationResult, verifiedLevels:[OATS_*...]
  └ inputAttestations ──┬─ control-verdict (oats.tech/control-verdict/v1) subject=D
                        ├─ SBOM (cyclonedx) subject=D
                        ├─ provenance (slsa/provenance/v1) subject=D
                        ├─ reconcile+byte-integrity (svr) subject=D
                        ├─ chipsec (test-result) subject=D
                        └─ vex (openvex, refs CSAF) subject=D
```

---

## Phase 1 — Predicate restructure (offline; fully testable via `make test`)
The core value: standard VSA + control-verdict + `subject=D` + versioned IDs. No CI-signing yet.

**Rego — `oss-lane/policy/firmware.rego`**
- Split `policy_verdict_predicate` (`:537-548`) into:
  - `vsa_predicate` — SLSA VSA v1.2 shape (`verifier`, `resourceUri`, `policy`, `verificationResult`,
    `verifiedLevels` incl. custom `OATS_*` tokens derived from the reports, `inputAttestations`, `slsaVersion:"1.2"`).
  - `control_verdict_predicate` — `{controls:[{id,status,satisfied_by[],missing_evidence[]}]}`.
- Extend `control_assessments` (`:520-530`) → add explicit `satisfied_by` and a **new** `missing_evidence[]`
  rule (parallels `verify-initiative.py:37-43`; today rego only yields `not-applicable` status, not the absent list).
- Versioned IDs: add `id`+`version` to `_report` (`:364-370`) and the 19 call sites (`:249-361`); keep `name` for
  back-compat so `frameworks.yaml`/`verify-initiative.py` keying still resolves (map `name`→`id`).
- Generalize binding: `_evidence_chain_bound`/`_sbom_bound` (`:31`, `:189-196`) move from the SBOM-file digest `H`
  to **`D`** ("all verified subjects == anchor").

**Wrapper — `oss-lane/gate.sh:49-70`**
- Emit **two** Statements: the VSA (subject=D primary, `predicateType=slsa.dev/verification_summary/v1`) and the
  control-verdict (subject=D). VSA `inputAttestations` lists the control-verdict (Phase 2 adds the rest).
- Drop the secondary/primary `H` subject; `D` becomes primary. Keep a `firmware-image`-named ResourceDescriptor
  (digest=D) so the CLI keeps working.

**Assembler — `oss-lane/assemble_gate_input.py`**
- Re-point the subject plumbing (`:229`, `:252-254`) so `subject_digest`/`PROVENANCE_SUBJECT` reference `D`
  (and `supply-chain.yml:112`). `evidence-chain-bound` now checks all subjects == `D`.

**CLI — `cli/fw-supplychain-verify:68-72,200-203`**
- Read `D` as the primary subject (retain `firmware-image` name lookup as fallback); BOUND/MISMATCH unchanged.

**Consumers / fixtures / tests**
- `verify-initiative.py:27-43` → consume the predicate's precomputed `satisfied_by/missing_evidence` instead of recomputing.
- Regenerate the **~25 fixtures** (`oss-lane/fixtures/*`) for the new subject (`D` primary) + predicate shape + deny strings.
- `oss-lane/policy/initiatives.json` regen (`tests/test_initiatives_sync.py:5`); update `tests/run.sh`,
  `tests/pipeline-negative.sh`, `tests/test_assemble.py` for the new subject/predicate expectations.
- **Second lane:** align `supply-chain.yml:151-162` + `oss-lane/policy/cosign-reconcile.rego:21` if its subject assumption shifts.

**Phase-1 acceptance:** `make test` green; `make gate FIXTURE=clean.json` emits a valid **SLSA VSA (subject=D)** +
a **control-verdict** carrying `satisfied_by/missing_evidence`; every negative fixture still denies with the right report.

## Phase 2 — Evidence wrapping (CI signing; needs cosign ≥ 2.6.0)
- `sign-blob → attest-blob --statement` for **E6** (VSA, `supply-chain.yml:125-132`) + **E7** (build-tools, `:88-99`).
- Wrap **E1** (SBOM), **E4** (grype + OpenVEX), **E10** (CHIPSEC — `to-predicate.py:56-74`, currently a bare predicate)
  as DSSE Statements with `subject=D` and the Phase-1 predicate types; add a shared wrapper (`producers/wrap.sh`).
- Populate the VSA `inputAttestations[]` DAG with `{uri,digest}` for every evidence attestation.
- Collapse **CSAF** into an OpenVEX reference; **drop E5** as an evidence row (docs: `FRAMEWORKS.md`, `inputs/README.md`,
  `DESIGN-REVIEW.md`). Pin cosign ≥2.6.0; `--new-bundle-format` everywhere; keep predicateType conventions consistent
  with the OPA matchers.

**Phase-2 acceptance:** every emitted attestation `verify-blob-attestation`s with `subject=D`; the VSA's
`inputAttestations` resolve; CI green.

## Sequencing with binary-hardening parity
Binary-hardening edits a *different* rego region (`:114-134`) but shares the **fixtures**. Land it **after Phase 1**
(fixtures re-subjected to `D` once, then binary-hardening adds `unverifiable`/`dxe_class_total`), or fold its fixture
edits into the Phase-1 fixture regen pass.

## Verification strategy
`make test` after every sub-step of Phase 1; a schema-shape assertion for the VSA (required fields, `subject.digest.sha256==D`)
and the control-verdict; `cosign verify-blob-attestation` smoke test in Phase 2. No step lands red.

## Top risks (from the maps)
- Re-subjecting to `D` ripples to `evidence-chain-bound`, the CLI subject name, ~25 fixtures + deny-string tests, and the
  second OCI lane — all enumerated above; each has a concrete change-point.
- `test_initiatives_sync.py` breaks on any report-name churn → keep `name` stable while adding `id`.
- cosign `--statement` for `attest-blob` needs **≥2.6.0** (Phase 2 gate).
