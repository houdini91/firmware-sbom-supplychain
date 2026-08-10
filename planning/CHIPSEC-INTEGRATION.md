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

**Status:** A1 DONE. Track A is fully unblocked and needs nothing upstream. Next build step: A2/A3 prototype
(CHIPSEC `uefi decode` → our normalizer → cross-carver parity vs the signed SBOM, PeiCore/OVMF first).
