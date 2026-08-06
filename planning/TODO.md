# TODO — prioritized punch-list

The actionable next steps, in execution order. Detail lives in [`DESIGN-REVIEW.md`](./DESIGN-REVIEW.md)
(architecture + verdict), [`EVIDENCE-ROADMAP.md`](./EVIDENCE-ROADMAP.md) (evidence lanes), and
[`POLICY-EXPANSION.md`](./POLICY-EXPANSION.md) (rules). Checkbox = do it; `⛔ blocked-by` = don't start yet.

> **STATUS 2026-08-06 — Track A (the evidence-centric core) is COMPLETE and green on `main`.**
> Shipped this cycle: multi-subject signed evidence graph (firmware `D` + file `H`, CI-validated),
> standard SLSA VSA (`verification_summary/v1`, subject=D) with per-control detail as extensions,
> framework-aware manifest-derived output (27 controls / 6 frameworks, drift-proof), binary-hardening
> parity, and a portfolio README + reconciled docs. What actually remains is small — see
> **[Remaining / deferred](#remaining--deferred)** at the bottom.

## Track A — clean, tangible, evidence-centric core (do this now)

- [~] **A1 · Firmware-digest anchor (the keystone).** Everything binds to the *firmware*, not a JSON file. **Core DONE (2026-08-03; anchor narrowed to the immutable code region 2026-08-05)** — `D = sha256:7965c317…8f37` (**OVMF_CODE.fd**, 3653632 B — the *immutable* code region, not the whole `OVMF.fd`, which folds in the mutable `OVMF_VARS` NVRAM that legitimately changes on first boot).
  - [x] Generator (edk2 `-Y SBOM`): hashes each built FD, writes the **primary (code-region) image's** `D` into `metadata.component.hashes` + `firmware:*` properties, and enumerates **every** FD (`OVMF.fd`, `OVMF_CODE.fd`, `OVMF_VARS.fd`, `MEMFD.fd`) as a `firmware:fd-image` property with its own digest+size — so a verifier can do **two-state** verification: whole-image (`OVMF.fd`, 374472f0) against a *fresh/unbooted* flash, code-region (`D`) against a *booted* image whose NVRAM has since mutated. *(FD-selection + hash verified against the real FV: prefers `*_CODE`, reproduces `D`. **Full in-build regeneration confirmed 2026-08-04; code-region re-anchor confirmed 2026-08-05** — a clean `-Y SBOM` run emits the anchor + all `firmware:*` properties end-to-end.)*
  - [x] Reconcile predicate records `image_digest: D`.
  - [x] Gate check `SBOM D == reconcile image_digest == deployed .fd` — new `firmware-digest-anchor` verifier report, hard `deny`. **Three legs, each honestly sourced:** (1) build-time generator hash in the SBOM; (2) `sbom-reconcile --image` independently re-hashes the carved image (a genuine second measurement — no longer a hand-set constant); (3) deployed leg from `FW_IMAGE` at flash/verify time (`DEV_ASSUME_FWIMAGE` in CI + offline demo, since neither rebuilds OVMF). Digests normalized (`lower(alg:hex)`), distinct empty-leg vs mismatch messages. Negative fixture `firmware-digest-mismatch` → sole failing report → DENY. Demonstrated against the real image via `FW_IMAGE` (all three legs bind the code-region `D`). Wired into `frameworks.yaml` (SR-4(3), `cisa-fw-binding`).
  - [x] **DONE (A4, 2026-08-06)** — `D` is the **primary in-toto `subject`** of every image-scoped attestation the gate builds: **multi-subject `[firmware-image:D, file:H]`** on reconcile/SBOM/VEX/CHIPSEC/build-tools/VSA (E2 provenance stays platform-generated single-subject H, a DEV_ASSUME mapping). Validated in real CI. Firmware is an output → never `resolvedDependencies`.
  - *Acceptance (met for the gate):* the gate proves the SBOM + evidence describe *these* firmware bytes; a consumer verifies "evidence about firmware `sha256:D`."
- [~] **A2 · Initiative / rule-catalog layer** (adopt Valint's *structure*).
  - [x] Declarative `framework → control → rule` manifest + per-framework coverage runner —
    `oss-lane/initiatives/frameworks.yaml` + `oss-lane/verify-initiative.py`: reads the signed VSA, reports
    PASS / FAIL / **MISSING_EVIDENCE** across 6 frameworks / ~25 controls (SLSA L2, SSDF, 800-53, 800-193, S2C2F,
    CRA/BSI/CISA). *Verified: clean VSA → all PASS; a failing report lights up the right control.*
  - [x] **DONE** — `control_id → satisfied_by[]` + `missing_evidence[]` (+ `description`/`citation`) folded into the VSA predicate's `controlAssessments[]` — framework-language output in the signed verdict.
  - [x] **Versioned rule IDs DONE** (`firmware-sbom-supplychain/<name>@v1`); rego control tags are now manifest-**derived** (drift-proof). *"Metadata sidecars + a standard verdict schema" → rolled into the deferred CDXA/SARIF format work (see Remaining).*
- [x] **A2b · Framework-aware control output — DONE (Minimal, 2026-08-06;** design doc `planning/framework-aware-output-design.html`). Every control carries `description`/`citation`/`canonical` (shared crosswalk across frameworks); the gate emits framework-language output; rego tags are manifest-derived. Full=CDXA is deferred. *Original scoping note follows.* The compliance gate
  should *reflect the controls/frameworks it covers*: each control/rule exposes its **description**, and the
  gate emits messaging in the **target framework's own language** so a reader understands what they're actually
  seeing (valint-inspired). Because many frameworks **reuse** the same underlying control, model a **control
  catalog** (id + description + per-framework phrasing) that rules reference *once*, not duplicated per framework.
  **Open design Q** — reviewed via an HTML design doc + recommendation; keep proportionate, drop if it adds
  ceremony without payoff. Ties to A2's verdict-format + rule-catalog work (2026-08-05).
- [x] **A2c · binary-hardening → byte-integrity parity** — **DONE (2026-08-05).** binary-hardening now has
  coverage-binding (`dxe_class_checked == sbom.integrity.dxe_class_total`, cherry-pick guard), a reviewed
  exemption mechanism (`data.binary_hardening_exempt`, DXE-class only; missing-NX stays a hard deny), the
  per-module manifest surfaced, + 2 new fixtures and an exemption ALLOW test. `make test` green.
- [x] **A3 · `fw-supplychain-verify` CLI** (the headline) — **DONE.** `cli/fw-supplychain-verify`: hash the
  image, bind it to the VSA's firmware-image subject, per-framework scorecard; degrades honestly to
  `MISSING_EVIDENCE` on unattested firmware. `--verify-bundle` verifies the VSA signature (cosign) first.
- [x] **A4 · Uniform in-toto wrapping — DONE (Phase 1+2, CI-validated 2026-08-06).** Standard SLSA VSA
  (`slsa.dev/verification_summary/v1`, subject=D) with `verifierReports`/`controlAssessments` as extensions;
  `attest-blob --statement` multi-subject (D+H) for E1/E3/E4/E6/E7/E10 (cosign 2.6, `--new-bundle-format`);
  CSAF collapsed into the OpenVEX reference; E5 dropped as an evidence row. The multi-subject binding preserves
  the tamper-after-signing check (`_sbom_bound` at H) *and* the firmware binding (at D).

- [x] **A5 · Repo presentation / docs polish — DONE (2026-08-06).** Portfolio README (hero, reconcile →
  byte-integrity → runtime SVG diagrams, coverage map) benchmarked vs top OSS repos + product/design/technical
  review rounds; doc drift reconciled (counts/labels), `framework-coverage.svg` embedded in FRAMEWORKS. All
  five theme-adaptive SVGs live under `docs/img/`.

## Track B — upstream engagement (queued; gated on signals)

- [x] **B1 · uSWID #98** — **MERGED 2026-08-04** by Richard Hughes (CycloneDX component-type fix; first merged contribution in his ecosystem).
- [x] **B2 · edk2 #10507 comment — POSTED 2026-08-05** (comment id 5187942854, links fork PR #6). PLUS the
  **`devel@edk2.groups.io` `[RFC]`** (Phase 1 of the engagement plan at
  `/home/mikey/research/secure_boot/edk2-engagement/`) — **SENT**; awaiting maintainer response (issue is
  ~2 yr dormant, so expect slow; watch for Kinney/Liming/Jiewen on-list).
- [ ] **B3 · CHIPSEC [Ideas] discussion** — evidence-verification `tools/uefi/` module, framed via the
  `reputation.py`/`scan_image.py` precedent (see DESIGN-REVIEW). Reference-first. **HELD** while the edk2 RFC
  is out (don't open a second upstream thread yet).

## Track C — vuln research (parallel strength-play)

- [x] **C1 · edk2 exploratory security review** (task #40) — **DONE.** Review completed; any outcome is
  handled off-repo per responsible-disclosure practice. Orthogonal proof-of-work.

## Track D — later / horizon (do NOT start now)

- [x] **D1 · R4 byte-integrity reconcile** — **DONE (phases 1–3, 122 of 123).** `producers/reconcile/byte-integrity.py`
  matches each module's shipped PE32 bytes to the SBOM hash — DXE direct, XIP/PEI via un-rebase canonicalization;
  enforced as the `component-byte-integrity` gate report; a same-GUID trojan is caught. Audit-hardened (no
  vacuous pass, crash-safe, unit-tested; **no-reloc-table canonicalization added 2026-08-04** — a true
  122/122 on a fresh self-consistent build). Write-up: [`R4-BYTE-INTEGRITY.md`](R4-BYTE-INTEGRITY.md). Merged to
  `main` in `a5c73be` (the `r4-byte-integrity-phase1` branch is fully merged).
- [ ] **D2 · Firmware-native evidence** — fwupd `.cab`+Jcat, UEFIExtract corroborating carve, swtpm→CoRIM appraisal.
- [ ] **D3 · Beyond-CI flash/provision gate; Ratify referrer store; SCITT receipts.** Project-scale.

## Remaining / deferred

Track A core is complete; these are the genuine open items (mostly small or externally-paced).

- [ ] **CDXA / SARIF verdict format (the "extra format", deferred by design).** The internal control-verdict
  model already lives in the VSA `controlAssessments[]` extensions. This ADDS a rendering — **CDXA** (canonical,
  regulatory-facing, co-locates with the CycloneDX SBOM) and/or **SARIF** (for the GitHub code-scanning UI) —
  **selectable**, digest-linked back to the VSA, **never a replacement**. Absorbs A2's "metadata sidecars +
  standard verdict schema." Two agent format-reviews are on record (CDXA-canonical + SARIF-as-derived-view).
  Do when you want the extra formats.
- [x] **Vestigial rego cleanup — DONE 2026-08-06.** Dropped the dead 5th `controls` arg on `_report(...)` and the
  19 call-site arrays (~40 lines); tags are manifest-derived. `opa check` clean, all 26 fixtures + unit tests green.
- [x] **OpenSSF Scorecard badge — FIXED 2026-08-06 (real root cause).** The badge was empty because the publish
  POST was **rejected 400 on every run** — from the run log: `workflow verification failed: scorecard job contains
  env vars` (ossf/scorecard-action#workflow-restrictions). The `scorecard.yml` job violated the publish rules: a
  job-level `env: WORKFLOW_REF`, an unapproved `sigstore/cosign-installer` action, and a raw `run:` step that
  keyless-signed the SARIF (a codeql.yml-style "signed evidence" flourish that nothing downstream consumed). The
  webapp re-verifies the publishing workflow, so those extras silently blocked publishing while the job stayed
  green. **Fix:** stripped the job to the approved minimal shape (checkout + scorecard-action + upload-sarif, no
  env, no id-token on any other job) and dropped the unused signing steps; **re-pointed the README badge at the
  current `api.scorecard.dev` / `scorecard.dev` domain** (the action publishes to `api.scorecard.dev`; the old
  `api.securityscorecards.dev` results endpoint 404s). **CONFIRMED published — score 5.7** (a second bug surfaced
  after the env-var fix: the action was pinned to the annotated-**tag object** SHA `55891bbd…`, which the webapp's
  imposter-commit check rejects because it is not a commit; repinned to the v2.4.4 **commit** `2d114668`).
- [x] **Scorecard score — honest bumps applied 2026-08-06 (5.7 baseline).** The low score is mostly a solo/new-repo
  artifact (Code-Review 0 + Contributors 0 need a 2nd human; Maintained 0 is repo age <90d — self-heals). Taken,
  no gaming: **Dependency-Update-Tool 0→10** (`.github/dependabot.yml`, github-actions + pip); **Branch-Protection
  0→Tier 1** (`gh api` set on `main`: force-push + deletion blocked, `enforce_admins`, **no** required PRs so direct
  push still works — Tier 2+ needs a PR/review flow, not worth faking solo); **Signed-Releases** ready via
  `.github/workflows/release.yml` (keyless cosign-signed tarball + .sig/.crt/.sigstore) — becomes a counted 10 once
  a `v*` tag is cut. Deferred (fiddly, low value): hash-pinning the `pip install` lines (Pinned-Dependencies 7→10).
- [ ] **B3 · CHIPSEC** — held (above), pending the edk2 RFC.
- **Off-repo:** the embargoed edk2 vuln-disclosure track (see the `edk2-candidate-findings` / disclosure notes).

## Deprioritized (don't pad)
More gate rules (diminishing returns — the gate is strong at 19). Don't add rules for coverage's sake.
