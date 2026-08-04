> ## ⚠️ DRAFT — internal risk register for the #10507 engagement. Nothing here is posted or sent.
> Precondition reminder: engagement is gated on Richard Hughes responding to uSWID #98 (not yet).

# Upstream engagement risks & preemption

Honest anticipation of how the #10507 comment / `-Y SBOM` PR could go wrong, and how to defuse each
*before* it does. Grounded in what the repos actually do — no rebuttal claims more than the code supports.

## R1 — Scope creep ("this is a whole supply-chain platform, not a BaseTools patch")

**The risk.** The full project is a gate + VSA + two lanes + byte-integrity + CHIPSEC + 6 frameworks. If
any of that leaks into the edk2 conversation, maintainers reasonably push back: BaseTools is a build tool,
not a firmware-signing service. `DESIGN.md` already anticipates this ("dead infrastructure").

**Preempt.**
- The upstream ask is **exactly one thing**: a `-Y SBOM` report type that consumes existing
  `-Y COMPILE_INFO` data. Say so, once, and stop.
- Reconcile / byte-integrity get **one motivating sentence** ("this is *why* per-module digests matter"),
  never code, never a diagram, never a link to the operator repo.
- Keep the operator/builder/edk2 actor boundary from `DESIGN.md` visible: edk2 provides tooling; it does
  not build or verify firmware. That boundary is the answer to almost every scope objection.

## R2 — "Why not just Richard Hughes's fwupd / uSWID path?"

**The risk.** A maintainer notes fwupd + uSWID/coSWID already carry an on-device SBOM and asks why edk2
needs its own generator.

**Preempt — the honest, load-bearing distinction (from `DESIGN.md` "Why", part 2):**
- fwupd reads an SBOM that **a cooperating builder already embedded**. That is a *distribution + on-device
  read* mechanism — it presumes the SBOM exists.
- It **cannot cover firmware that has no embedded SBOM**, and it **cannot verify** an SBOM against the
  actual image bytes. It trusts the tag; it does not check it.
- The `-Y SBOM` generator is the **producer** that makes an accurate SBOM *exist in the first place*, at
  build time, from the build's own authoritative data. It **feeds** the uSWID/coSWID embed path rather
  than competing with it — the generator's CycloneDX round-trips into coSWID (that round-trip is exactly
  what uSWID #98 fixes).
- So the two are complementary layers: **generate** (edk2, new) → **embed + read on device** (uSWID/fwupd,
  existing). Frame it as filling the hole *beneath* fwupd, and credit Richard explicitly.
- The *verify-against-bytes* reconcile is a third, operator-side layer neither edk2 nor fwupd does — but
  keep that as motivation only (see R1).

## R3 — Maintenance-burden concern ("who keeps this working as AutoGen changes?")

**The risk.** Every new BaseTools report type is surface area maintainers must carry. A generator coupled
to internal AutoGen structures could rot.

**Preempt.**
- **Minimal coupling.** The generator is a *consumer of already-emitted, machine-readable outputs*
  (`CompileInfo/module_report.json`, `<FvName>.Fv.txt`) — the same data `-Y COMPILE_INFO` produces — not a
  reach into build internals. If those reports are stable, the generator is stable.
- **Zero new dependency.** stdlib-only, CycloneDX is plain JSON. Nothing to keep pinned or updated
  (contrast: protobom is a Go tool proposed *only* for consumers, never for BaseTools — say this
  explicitly, it preempts a "new dependency" objection).
- **Small and self-contained.** It sits beside existing report types; it does not alter the build graph.
- **Offer to maintain it.** A credible "I'll respond to issues on this report type" lowers the perceived
  burden. (The libspdm refresh — merged as `tianocore/edk2#12936` — is prior evidence of follow-through.)
- Honest caveat to *volunteer*, not hide: the generator is exact only for **what's built from source**;
  prebuilt blobs (FSP, microcode, ME) have no build report and are out of scope. Stating this up front is
  a maintenance *reassurance* (bounded scope), not a weakness.

## R4 — Correctness / overclaim objections on the SBOM content

**The risk.** A reviewer inspects the example SBOM and finds asserted-not-derived data, or a component
count that doesn't reproduce.

**Preempt (resolve BEFORE posting — these are real gaps in the current state):**
- **Submodule / component-count divergence.** `generate.py` says it emits third-party submodule components
  with versions; `DESIGN.md` + the prior draft say submodules are "not emitted yet"; the committed example
  has 311 components while the narrative says the generator emits 310 (openssl added as a demo). **Pick the
  true number from a clean run and state it once.** A maintainer who counts 311 against a claimed 310 will
  distrust everything else.
- **CPE identities are DRAFT.** The curated CPE map in `generate.py` is explicitly
  `firmware:cpe_source=curated` + `firmware:cpe_review=unverified`. Do not present CPEs as CVE-ready.
  Recommended: **omit CPE emission from the first upstream cut** (per branch plan §3) so the patch makes
  no identity claim it can't defend.
- **Reproducibility.** Have a fresh-checkout build reproduce the example before pointing anyone at it;
  "310 for this specific OvmfPkgX64 DEBUG/GCC build, varies by platform" is the honest framing already in
  `DESIGN.md`.

## R5 — Responsible-disclosure / confidentiality boundary

**The risk.** The broader research touches firmware internals; an upstream comment could stray into
sensitive territory (vendor internals, ME/undisclosed-parser claims, unreleased vuln work).

**Preempt — hard boundaries for anything posted:**
- **No ME-internals claims.** `DESIGN.md` is careful: ME/FSP/microcode are "observed-but-undeclared"
  regions the generator does **not** cover and an SBOM never declares. State scope as source-built modules
  only; make **no** assertion about Management Engine internals, undocumented structures, or vendor blobs.
- **Keep vuln research (Track C) entirely separate.** The edk2 exploratory security review and any
  responsibly-disclosed finding are a *different* workstream — never reference unreleased findings in a
  public SBOM comment.
- **Defensive framing only.** The project is reference/defensive; carry that. No offensive/exploit framing,
  no "here's how to trojan firmware" language beyond the abstract same-GUID-swap motivation already public.
- **No third-party naming beyond public facts.** Credit Richard Hughes and Vincent Zimmer for their public
  work (their issues/PRs are public); assert nothing about anyone's internal roadmap.

## R6 — Provenance / "who is this person" credibility

**The risk.** An unknown contributor drops a sizable generator; maintainers are cautious.

**Preempt.**
- Lead with a **merged** prior contribution to the same tree: `tianocore/edk2#12936` (libspdm 3.7.0→3.8.2)
  is already upstreamed — evidence of working within edk2's process (DCO, list etiquette).
- One concrete working artifact per conversation (the engagement sequence in `DESIGN.md`), not a big-bang.
- Real name + DCO sign-off matching the generator's copyright line (branch plan §4).

---

## Cross-cutting: the single biggest self-inflicted risk

Posting **before** the state is reconciled. Two things would undercut the whole engagement on contact:
1. the **310/311 + submodules-or-not** inconsistency (R4), and
2. pointing at a **fork PR #6 that isn't actually reviewable / green** against edk2's real CI (branch plan
   §0 — the in-tree form isn't on this machine to confirm).

Both are fixable pre-post and both are in the pre-post checklist. Neither should be papered over in the
comment text.
