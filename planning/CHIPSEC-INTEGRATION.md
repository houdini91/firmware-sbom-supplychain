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
- **A1 — Verify CHIPSEC (IN PROGRESS, agent running).** Code review of `tools.uefi.scan_image` + `uefi
  decode`; confirm it hashes as-found bytes, confirm no native normalization, confirm `uefi decode` gives
  per-module PE **bytes** we can normalize; dynamic run against our OVMF `.fd`; efilist.json schema; upstream
  issue/PR scan; maintainer/contribution facts. → determines whether A needs anything from upstream (expected: no).
- **A2 — Extraction prototype.** Run CHIPSEC on our OVMF image; extract per-module PE/TE sections to disk;
  confirm we get `{FILE_GUID, bytes}` per module.
- **A3 — Reuse our normalizer.** Feed CHIPSEC-extracted bytes into the existing rebase-0 canonicalizer
  (`producers/reconcile/byte-integrity.py` pefile path). Prove the normalized hash matches the SBOM's
  declared per-module hash on the OVMF reference — i.e. **parity with our FMMT carve path** via a second,
  independent carver. (Cross-carver agreement is itself a nice robustness result.)
- **A4 — New producer.** `producers/chipsec/deploy-reconcile.py`: CHIPSEC-source → normalize → compare to the
  signed SBOM → emit a `deploy-reconcile` predicate (new predicateType `https://firmware-sbom-supplychain/deploy-reconcile/v1`,
  keeping the stable-namespace convention). GUID-bound + bidirectional (swap AND missing both fail).
- **A5 — Evidence class + gate wiring.** Add a `deploy-time-reconcile` verifier_report as a **deploy-time /
  advisory** leg (not part of CI admission, since it needs a device/live source). evidenceGrade = `verified`
  on real device readback, else absent/`sample`. Non-vacuity guard so "no device evidence" ≠ SATISFIED.
- **A6 — Live-flash path (roadmap within A).** CHIPSEC live SPI dump on real hardware → same pipeline →
  catches flash-time drift. Needs root/driver on the target; document as direction (the "runtime attestation
  next" horizon already drawn in the futuristic diagram).
- **A7 — Interop artifact.** Emit a CHIPSEC-compatible `efilist.json` from our reconcile so the two cross-check
  (prior-art survey recommendation).
- **A8 — Tests + docs + diagrams sync** (standing rule after any control/evidence change): fixtures (clean +
  drift), a `test_deploy_reconcile.py`, DESIGN.md / FRAMEWORKS.md / ADR update, counts re-synced.

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

**Status:** both A and B are logged as next steps. A1 verification agent is running; A task map above is the
working plan, to be refined once verification lands.
