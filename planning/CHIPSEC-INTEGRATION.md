# CHIPSEC integration — next steps (A + B)

Two independent tracks that came out of the prior-art survey (see [ECOSYSTEM-PRIOR-ART.md](ECOSYSTEM-PRIOR-ART.md)).
CHIPSEC already carves a UEFI image and per-module SHA-256s it, but it (a) hashes the **as-found /
rebased** bytes, not a normalized rebase-0 form, and (b) compares against a golden-image hash set, not a
build-born SBOM. We already know how to normalize (reverse PE relocations). That gap is the whole point.

---

## Track A — CHIPSEC-fed **deploy-time reconcile** gate (build it ourselves; needs nothing upstream)

**Goal:** reuse CHIPSEC as the byte-source (image file *or* live SPI flash), run OUR normalizer, and
reconcile per-module hashes against the **signed build-born SBOM** — GUID-bound, bidirectional — emitting
a signed deploy-time report. This extends the same SBOM baseline from "at rest" (CI admission) to "on
silicon" (what's actually flashed), catching post-admission / flash-time drift the at-rest gate can't see.
Deploy-time + advisory, consistent with [ADR 0001](../docs/adr/0001-chipsec-is-a-deploy-time-collection-point.md).

### Task map (initial — refine after the verification agent lands)
- **A1 — Verify CHIPSEC (DONE — see "Verification findings" below).** Confirmed: CHIPSEC hashes the raw
  PE/TE section **as-found** (no normalization anywhere in the tree), BUT `chipsec_util uefi decode` writes the
  per-module PE/TE **bytes** to disk (`spi.py:442`) — so **Track A needs nothing from upstream.** Verified
  dynamically against our exact OVMF reference.
- **A2 — Extraction prototype.** Run CHIPSEC on our OVMF image; extract per-module PE/TE sections to disk;
  confirm we get `{FILE_GUID, bytes}` per module.
- **A3 — Reuse our normalizer.** Feed CHIPSEC-extracted bytes into the existing rebase-0 canonicalizer
  (`producers/reconcile/byte-integrity.py` pefile path). Prove the normalized hash matches the SBOM's
  declared per-module hash on the OVMF reference — i.e. **parity with our FMMT carve path** via a second,
  independent carver. (Cross-carver agreement is itself a nice robustness result.)
- **A4 — New producer. ✅ DONE.** `producers/chipsec/deploy-reconcile.py`: CHIPSEC-source → OUR normalizer
  (`canon_unrebase`/`load_sbom_hashes`/`XIP_TYPES` reused UNCHANGED from byte-integrity.py) → GUID-bound,
  bidirectional compare vs the signed SBOM → emits the `deploy-reconcile` predicate (predicateType
  `https://firmware-sbom-supplychain/deploy-reconcile/v1`, stable-namespace). Keyed by FILE_GUID (names
  collide); module TYPE from CHIPSEC's FV filetype dir via the IMMEDIATE parent (nested-FV trap). MISMATCH
  (swap) / MISSING (declared, unextracted) / UNEXPECTED (extracted, undeclared) all fail; TE / non-cleanly-
  extractable → SKIP (never counted as verified). **Verified: 122/122 on the OVMF reference (111 direct + 11
  un-rebase), image digest == anchor D.**
- **A5 — Evidence class + gate wiring. ✅ DONE.** Added the CONDITIONAL `deploy-time-reconcile` verifier_report
  to `firmware.rego`: **ABSENT** on the clean demo (no device → advisory-MISSING, `allow` unaffected, never
  SATISFIED — non-vacuity guard requires `matched>0` reconciled from real bytes); **PRESENT + clean → PASSED**
  (evidenceGrade `verified`); **PRESENT + any mismatch/missing/unexpected → FAILED → gate DENY** (byte-integrity-
  like, advisory-guarded deny). Mapped to SP 800-193 §4.3.1 (the deploy-time/on-device detection control — the
  advisory home that keeps the clean baseline **32 reports / 46 controls / 41 satisfied / 8 frameworks**
  unchanged; mapping to the non-advisory family controls, e.g. AUD-3 / SI-7(1) / SR-4(3) / cisa-hash, was
  deliberately NOT done because it would flip those currently-satisfied controls to MISSING on the demo and
  break the invariant). Assembler folds it via `DEPLOY_RECONCILE_JSON` / `DEPLOY_RECONCILE_BUNDLE` (D-anchored).
- **A6 — Live-flash path (roadmap within A).** CHIPSEC live SPI dump on real hardware → same pipeline →
  catches flash-time drift. Needs root/driver on the target; document as direction (the "runtime attestation
  next" horizon already drawn in the futuristic diagram).
- **A7 — Interop artifact.** Emit a CHIPSEC-compatible `efilist.json` from our reconcile so the two cross-check
  (prior-art survey recommendation).
- **A8 — Tests + docs + diagrams sync. ✅ DONE.** Fixtures `deploy-reconcile-clean.json` (present+clean → ALLOW)
  + `deploy-reconcile-drift.json` (one mismatch → DENY), wired into `tests/run.sh`. `tests/test_deploy_reconcile.py`
  (hermetic pure-logic: GUID-keying, nested-FV-trap, TE-skip, bidirectional reconcile — runs without pefile; plus
  the 122/122 OVMF reference assertion, run when pefile + the decode tree are reachable, else SKIP loudly). Docs:
  ADR 0001 (deploy-time byte-source consequence), FRAMEWORKS.md (§4.3.1 leg + conditional-report list),
  COMPLIANCE-MATRIX.md (§4.3.1 satisfiers + note), DESIGN.md (new "Deploy-time reconcile" section),
  frameworks.yaml §4.3.1 `satisfied_by` += `deploy-time-reconcile` (initiatives.json re-synced), data.json
  evidence_grade += `deploy-time-reconcile: verified`. Clean baseline re-verified **unchanged: 32 / 46 / 41 / 8.**

---

## Track B — Upstream **conversation / PR** with CHIPSEC (draft only; filing is user-gated)

**Ask:** add an optional **normalized (rebase-0) hash** mode to `scan_image` so its output is comparable to
build-time SBOM/coSWID hashes, not only to a same-layout golden image. Offer our normalization as the
contribution. **Mutual benefit, not a favor to us:** normalized hashes make CHIPSEC results portable across
flash layouts and align with **CISA 2026's new component-hash field** — an ecosystem win.

### Discipline (same as the uSWID / OSF engagements)
- **Verify before filing** (A1 covers this): confirm no existing issue/PR, confirm it doesn't already exist.
- **Land it credible:** file *after* Track A works, so the issue/PR ships with a "here's it running" reference.
- **Draft, don't send:** prepare the issue/PR text for review; filing stays the user's explicit call.
- **Sequencing:** we're already mid-flight upstream (uSWID #98 merged, #99/#100 open; edk2 #10507). This is a
  third thread — pace it.

---

## Verification findings (A1 — DONE, evidence-cited)

Reviewed CHIPSEC git `main` (2.0) + dynamic run on PyPI `1.13.16` (identical hashing code). Scratch:
`scratchpad/chipsec-verify/`.

- **What it hashes:** raw PE/TE section body **as-found** — `EFI_MODULE.calc_hashes()` SHA-256s
  `self.Image[off:]` (`chipsec/library/uefi/fv.py:216-227`), called with `off=HeaderSize` for exe sections
  (`spi.py:162-164`); `scan_image.py:102-105` uses that hash as the dict key. **No normalization / rebase /
  reloc-reversal exists anywhere** (whole-tree search confirmed).
- **We get the bytes:** `dump_efi_module()` writes `mod.Image[HeaderSize:]` to disk (`spi.py:439-449`) with
  `.sha256` sidecars. `chipsec_util uefi decode <img>` → per-module `.efi` files in an FV-mirrored tree +
  `<img>.UEFI.json`. **→ our normalizer runs on these bytes; zero upstream change needed.**
- **Dynamic proof:** `pip install chipsec` (1.13.16, prebuilt wheel, no driver). Ran on our reference
  `OVMF_CODE.fd` (sha256 `7965c317…62fb8f37` — the same D we anchor on) → 122 modules extracted; scan_image
  generate PASSED, 122 entries. Worked example: `PeiCore` GUID `52C05B14-…-04B50211D680`, extracted 56,256 B,
  our `sha256sum` == the `.sha256` sidecar == the `efilist.json` key. PeiCore is PE32+ with **ImageBase =
  0x830140** and a populated `.reloc` (RVA 0xDB00 size 0xC0) → a rebase-0 hash **necessarily differs** from
  CHIPSEC's as-found hash. **Normalization gap confirmed concretely on our own reference image.**
- **efilist.json schema:** `{ "<sha256>": {sha1, guid, name, type} }` — sha256 is the KEY (no `sha256`/`ver`
  value fields). For A7 interop we must key on the hash and mirror this shape.
- **Upstream:** `chipsec` org (Intel-origin, community-run), very active (daily commits, monthly releases,
  v2.0.7 2026-07-30), **GPL-2.0**, DCO `Signed-off-by` required, takes community feature PRs. **No existing
  SBOM / normalized-hash / coSWID / reproducible-hash issue or PR** — Track B is open + non-duplicative. Only
  `scan_image` issues are detection-completeness (#1296, #1790, #2197), unrelated.

### Refinements this forces
- **A2/A3 are directly unblocked with data in hand:** extract via `uefi decode`; compare the *as-found* hash
  to our SBOM's declared *rebase-0* hash → they should DIFFER (proving the gap), then normalize → should MATCH.
  PeiCore on OVMF is the ready-made first test vector.
- **A5 evidence source note:** consuming CHIPSEC = a subprocess/tool dependency (GPL-2.0 tool, invoked — not
  linked); fine for an MIT repo since we shell out to `chipsec_util`, we don't vendor its code.
- **Track B caveats (before drafting):** (1) propose an **additive** normalized-hash field — do NOT change the
  sha256-as-key schema; (2) **GPL-2.0**: a normalizer upstreamed into CHIPSEC becomes GPL — keep our own
  reconcile logic MIT on the extracted-bytes side of the boundary; (3) open a **design issue first** (no prior
  art), then a PR. Still draft-only / user-gated.

**Status:** A1–A5 + A8 DONE. Track A is built end to end: the A2/A3 prototype proved cross-carver parity
(CHIPSEC `uefi decode` → our normalizer → 122/122 vs the signed SBOM), then A4 productionized it as
`producers/chipsec/deploy-reconcile.py`, A5 wired the CONDITIONAL `deploy-time-reconcile` gate leg (SP 800-193
§4.3.1; clean baseline unchanged at 32/46/41/8), and A8 added fixtures + `test_deploy_reconcile.py` + docs.
Remaining Track-A roadmap: **A6** (live SPI dump on real hardware — needs root/driver) and **A7** (emit a
CHIPSEC-compatible `efilist.json` for cross-check). Track B (upstream normalized-hash PR) stays draft-only/user-gated.
