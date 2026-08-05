# TODO — prioritized punch-list

The actionable next steps, in execution order. Detail lives in [`DESIGN-REVIEW.md`](./DESIGN-REVIEW.md)
(architecture + verdict), [`EVIDENCE-ROADMAP.md`](./EVIDENCE-ROADMAP.md) (evidence lanes), and
[`POLICY-EXPANSION.md`](./POLICY-EXPANSION.md) (rules). Checkbox = do it; `⛔ blocked-by` = don't start yet.

## Track A — clean, tangible, evidence-centric core (do this now)

- [~] **A1 · Firmware-digest anchor (the keystone).** Everything binds to the *firmware*, not a JSON file. **Core DONE (2026-08-03; anchor narrowed to the immutable code region 2026-08-05)** — `D = sha256:7965c317…8f37` (**OVMF_CODE.fd**, 3653632 B — the *immutable* code region, not the whole `OVMF.fd`, which folds in the mutable `OVMF_VARS` NVRAM that legitimately changes on first boot).
  - [x] Generator (edk2 `-Y SBOM`): hashes each built FD, writes the **primary (code-region) image's** `D` into `metadata.component.hashes` + `firmware:*` properties, and enumerates **every** FD (`OVMF.fd`, `OVMF_CODE.fd`, `OVMF_VARS.fd`, `MEMFD.fd`) as a `firmware:fd-image` property with its own digest+size — so a verifier can do **two-state** verification: whole-image (`OVMF.fd`, 374472f0) against a *fresh/unbooted* flash, code-region (`D`) against a *booted* image whose NVRAM has since mutated. *(FD-selection + hash verified against the real FV: prefers `*_CODE`, reproduces `D`. **Full in-build regeneration confirmed 2026-08-04; code-region re-anchor confirmed 2026-08-05** — a clean `-Y SBOM` run emits the anchor + all `firmware:*` properties end-to-end.)*
  - [x] Reconcile predicate records `image_digest: D`.
  - [x] Gate check `SBOM D == reconcile image_digest == deployed .fd` — new `firmware-digest-anchor` verifier report, hard `deny`. **Three legs, each honestly sourced:** (1) build-time generator hash in the SBOM; (2) `sbom-reconcile --image` independently re-hashes the carved image (a genuine second measurement — no longer a hand-set constant); (3) deployed leg from `FW_IMAGE` at flash/verify time (`DEV_ASSUME_FWIMAGE` in CI + offline demo, since neither rebuilds OVMF). Digests normalized (`lower(alg:hex)`), distinct empty-leg vs mismatch messages. Negative fixture `firmware-digest-mismatch` → sole failing report → DENY. Demonstrated against the real image via `FW_IMAGE` (all three legs bind the code-region `D`). Wired into `frameworks.yaml` (SR-4(3), `cisa-fw-binding`).
  - [ ] **(→ A4)** Make `D` the **primary in-toto `subject`** of every image-scoped attestation (multi-subject `[{fd:D},{sbom:H}]` on provenance/SBOM/reconcile; `D` only on CVE/VEX/VSA/CHIPSEC/build-tools; source-commit on SAST/Scorecard). Firmware is an output → never `resolvedDependencies`. *Deeper refactor; the DSSE-subject discipline moves to Track A4.*
  - *Acceptance (met for the gate):* the gate proves the SBOM + evidence describe *these* firmware bytes; a consumer verifies "evidence about firmware `sha256:D`."
- [~] **A2 · Initiative / rule-catalog layer** (adopt Valint's *structure*).
  - [x] Declarative `framework → control → rule` manifest + per-framework coverage runner —
    `oss-lane/initiatives/frameworks.yaml` + `oss-lane/verify-initiative.py`: reads the signed VSA, reports
    PASS / FAIL / **MISSING_EVIDENCE** across 6 frameworks / ~25 controls (SLSA L2, SSDF, 800-53, 800-193, S2C2F,
    CRA/BSI/CISA). *Verified: clean VSA → all PASS; a failing report lights up the right control.*
  - [ ] Fold `control_id → satisfied_by[]` (+ `missing_evidence[]`) into the VSA `predicate` itself.
  - [ ] Versioned rule IDs (`ns/name@vN`) + metadata sidecars + a standard verdict schema.
- [ ] **A2b · Framework-aware control output (DESIGN question — do NOT over-build).** The compliance gate
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
- [ ] **A4 · Uniform in-toto wrapping.** `sign-blob → attest-blob` for E6 (VSA) + E7 (build-tools); wrap E1/E4/E10
  as DSSE Statements (`subject = D`); collapse CSAF into an E4b reference; drop E5 as an "evidence" row (it's the
  signing envelope). ⛔ blocked-by A1 (needs the D subject).

- [ ] **A5 · Repo presentation / docs polish (portfolio-facing).** Make the README + key docs **sleek and
  professional** — the GitHub-rendered docs currently read plain. Strong hero/overview, badges, tight
  structure, and clear **diagrams**. Constraint: GitHub renders **Markdown + mermaid natively** but sanitizes
  the inline-CSS/SVG HTML design docs — so use **mermaid** (architecture/data-flow/evidence-graph) and/or
  **committed SVGs**, not the HTML-design-doc approach. Aim for the *quality* of the HTML docs in
  GitHub-renderable form. (2026-08-05)

## Track B — upstream engagement (queued; gated on signals)

- [x] **B1 · uSWID #98** — **MERGED 2026-08-04** by Richard Hughes (CycloneDX component-type fix; first merged contribution in his ecosystem).
- [ ] **B2 · edk2 #10507 comment** — **UNBLOCKED (B1 merged).** Draft reviewed + ready at
  `planning/engagement/issue-10507-comment.md` (references fork PR #6). Ready to post — owner action.
- [ ] **B3 · CHIPSEC [Ideas] discussion** — evidence-verification `tools/uefi/` module, framed via the
  `reputation.py`/`scan_image.py` precedent (see DESIGN-REVIEW). Reference-first. **Unblocked (A1+A3 done); not started.**

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

## Deprioritized (don't pad)
More gate rules (diminishing returns — the gate is strong at 19). Don't add rules for coverage's sake.
