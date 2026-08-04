# Next plan — weekend review → edk2 upstream → role-application submission

Three audiences, one repo. Priority order below is deliberate: the **weekend reviewers** see the README + the
visuals first, so that comes first; production-readiness and the upstream/role-application framing follow.

## Track P — Presentation (do first; reviewer-facing, this weekend)
- [x] **P1 · README hero.** 5-second thesis up top ("catch a same-GUID firmware trojan by verifying the actual
  bytes on the chip against a signed SBOM"); status **badges** (CI, license, release v0.1.0); an above-the-fold
  **architecture diagram**; a **posture band** (enforced / evidence / planned) so a skimmer sees scope at a glance.
- [x] **P2 · Solution-showcase HTML** (pretty, visual, punchy) — the *whole* solution in one scroll a reviewer
  grasps in 2 minutes: the problem, the pipeline, the two novel controls (firmware-digest anchor + byte-integrity),
  framework coverage, honest scope. Linked from the README. (Companion to the byte-integrity explainer.)
- [x] **P3 · Money shots** — real, captured output: the gate ALLOW/DENY, the CLI scorecard, the same-GUID-trojan
  detection. A short "see it work" section/asset.
- [x] **P4 · Presentation review** (agents, AFTER P1–P3): a hiring reviewer + a firmware expert + a total
  newcomer pressure-test first impression, clarity, and "would this impress in 5 minutes."

## Track Q — Production readiness (edk2 discussion + role application)
- [ ] **Q1 · Confirm CI green on `main`** (the R4 merge just triggered supply-chain + pr-checks + codeql + scorecard).
- [x] **Q2 · Pin cosign + grype** in `scripts/fetch-tools.sh` (finish the "no unpinned tools" thesis; needs release SHAs).
- [x] **Q3 · interop/chipsec producer tests** (reconcile + byte-integrity already tested; close the rest).
- [ ] **Q4 · The "live in CI" boundary** — decide whether to run byte-integrity in CI against a built image, or
  keep the documented committed-offline-evidence model; make the choice explicit and defensible.

## Track E — edk2 upstream (future; gated on signals)
- [ ] **E1 · Keep fork PR #6 (the `-Y SBOM` generator) reviewable** as the reference example.
- [ ] **E2 · #10507 comment** — post after Richard engages on uSWID #98 (draft ready in `planning/engagement/`).

## Track A — role-application framing (do later, separately)
- [ ] **A1 · One-pager** — "what's novel + what I built + what I found": reconcile-to-bytes, the un-rebase, the
  GenFw diagnosis→solution, the honest-scope discipline. Ties the repo to a Hardware/Platform Security role.
- [ ] **A2 · Limitations up front** — the honest-scope framing is a strength; make it prominent, not buried.
