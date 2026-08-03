# TODO — prioritized punch-list

The actionable next steps, in execution order. Detail lives in [`DESIGN-REVIEW.md`](./DESIGN-REVIEW.md)
(architecture + verdict), [`EVIDENCE-ROADMAP.md`](./EVIDENCE-ROADMAP.md) (evidence lanes), and
[`POLICY-EXPANSION.md`](./POLICY-EXPANSION.md) (rules). Checkbox = do it; `⛔ blocked-by` = don't start yet.

## Track A — clean, tangible, evidence-centric core (do this now)

- [~] **A1 · Firmware-digest anchor (the keystone).** Everything binds to the *firmware*, not a JSON file. **Core DONE (2026-08-03)** — `D = sha256:374472f0…c8e0ce` (real OVMF.fd).
  - [x] Generator (edk2 `-Y SBOM`): hashes each built FD, writes the primary image's `D` into `metadata.component.hashes` + `firmware:*` properties. *(FD-selection + hash unit-verified against the real FV: picks `OVMF.fd`, reproduces `D`. Full in-build test pending a rebuild.)*
  - [x] Reconcile predicate records `image_digest: D`.
  - [x] Gate check `SBOM D == reconcile image_digest == deployed .fd` — new `firmware-digest-anchor` verifier report (17th), hard `deny`. **Three legs, each honestly sourced:** (1) build-time generator hash in the SBOM; (2) `sbom-reconcile --image` independently re-hashes the carved image (a genuine second measurement — no longer a hand-set constant); (3) deployed leg from `FW_IMAGE` at flash/verify time (`DEV_ASSUME_FWIMAGE` in CI + offline demo, since neither rebuilds OVMF). Digests normalized (`lower(alg:hex)`), distinct empty-leg vs mismatch messages. Negative fixture `firmware-digest-mismatch` → sole failing report → DENY. Demonstrated against the real `OVMF.fd` via `FW_IMAGE`. Wired into `frameworks.yaml` (SR-4(3), `cisa-fw-binding`).
  - [ ] **(→ A4)** Make `D` the **primary in-toto `subject`** of every image-scoped attestation (multi-subject `[{fd:D},{sbom:H}]` on provenance/SBOM/reconcile; `D` only on CVE/VEX/VSA/CHIPSEC/build-tools; source-commit on SAST/Scorecard). Firmware is an output → never `resolvedDependencies`. *Deeper refactor; the DSSE-subject discipline moves to Track A4.*
  - *Acceptance (met for the gate):* the gate proves the SBOM + evidence describe *these* firmware bytes; a consumer verifies "evidence about firmware `sha256:D`."
- [~] **A2 · Initiative / rule-catalog layer** (adopt Valint's *structure*).
  - [x] Declarative `framework → control → rule` manifest + per-framework coverage runner —
    `oss-lane/initiatives/frameworks.yaml` + `oss-lane/verify-initiative.py`: reads the signed VSA, reports
    PASS / FAIL / **MISSING_EVIDENCE** across 6 frameworks / ~25 controls (SLSA L2, SSDF, 800-53, 800-193, S2C2F,
    CRA/BSI/CISA). *Verified: clean VSA → all PASS; a failing report lights up the right control.*
  - [ ] Fold `control_id → satisfied_by[]` (+ `missing_evidence[]`) into the VSA `predicate` itself.
  - [ ] Versioned rule IDs (`ns/name@vN`) + metadata sidecars + a standard verdict schema.
- [ ] **A3 · `fw-supplychain-verify` CLI** (the headline). One command a firmware engineer runs on *their*
  firmware → per-framework scorecard, using their trust policy. Consumes A1 (anchor) + A2 (initiatives).
  - ⛔ blocked-by A1, A2.
- [ ] **A4 · Uniform in-toto wrapping.** `sign-blob → attest-blob` for E6 (VSA) + E7 (build-tools); wrap E1/E4/E10
  as DSSE Statements (`subject = D`); collapse CSAF into an E4b reference; drop E5 as an "evidence" row (it's the
  signing envelope). ⛔ blocked-by A1 (needs the D subject).

## Track B — upstream engagement (queued; gated on signals)

- [ ] **B1 · uSWID #98** — wait for Richard Hughes to engage. *(No action until then.)*
- [ ] **B2 · edk2 #10507 comment** — post after B1 signal; reference fork PR #6 as the example. Draft ready at
  `engagement/issue-10507-comment.md`. ⛔ blocked-by B1.
- [ ] **B3 · CHIPSEC [Ideas] discussion** — evidence-verification `tools/uefi/` module, framed via the
  `reputation.py`/`scan_image.py` precedent (see DESIGN-REVIEW). Reference-first. ⛔ blocked-by A1+A3.

## Track C — vuln research (parallel strength-play)

- [ ] **C1 · edk2 exploratory security review** (task #40). SAST (E8) triage + targeted review of parser-heavy
  code → a responsibly-disclosed finding. Different, orthogonal proof-of-work. Can run in parallel with Track A.

## Track D — later / horizon (do NOT start now)

- [ ] **D1 · R4 byte-integrity reconcile** — per-region canonical digest vs image. ⛔ blocked-by A1 (needs D).
- [ ] **D2 · Firmware-native evidence** — fwupd `.cab`+Jcat, UEFIExtract corroborating carve, swtpm→CoRIM appraisal.
- [ ] **D3 · Beyond-CI flash/provision gate; Ratify referrer store; SCITT receipts.** Project-scale.

## Deprioritized (don't pad)
More gate rules (diminishing returns — the gate is strong at 17). Don't add rules for coverage's sake.
