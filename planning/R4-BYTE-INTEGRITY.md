# R4 — byte-integrity reconcile (plan)

**Goal:** turn the reconcile verdict's `modified` field from *always-skipped* into a real
check for a tractable subset of modules, so the project's central claim — *"the SBOM
describes the shipped bytes"* — holds at the **byte** level, not just membership. This is
the single highest-impact depth item (it converts the reconcile control from `PARTIAL` to
real) and we are already most of the way there: the hard part is *characterized*, not unknown.

## The problem (why naive byte-integrity fails)

Reconcile today checks **membership**: every declared module GUID is observed as an FFS in
the carved image, no undeclared artifact. It does **not** check that a module's *bytes* match
what the build produced. A same-GUID trojan (swap a module for a malicious one with the same
FILE_GUID) passes membership.

The obvious check — hash the module's in-FV PE32 and compare to the declared build `.efi`
hash — **does not work**, and we proved it: for `AmdSevDxe` the in-image PE32 is
`50172c36…` vs the declared build output `5fe71c0c…`, even though nothing was tampered. The
in-FV image is not the build `.efi`; it is the build `.efi` after **GenFw** ran during
FDF assembly.

## Root cause — what GenFw changes (grounded in `BaseTools/Source/C/GenFw/GenFw.c`)

During `build`, GenFw rewrites each module's PE/COFF image before it is placed in the FV.
The byte-affecting operations:

| Transform | GenFw evidence | Effect on bytes |
|---|---|---|
| Zero `TimeDateStamp` | `mImageTimeStamp = 0` (:86); "zeros the time stamp fields" (:204) | PE header field differs from a fresh build |
| Zero debug data | `ZeroDebugData()` (:96), `-z/--zero` (:203) | `.debug` directory data zeroed/removed |
| Recompute/zero PE checksum | checksum loop (:2059–2065), `CheckSum=0` (:1215) | optional-header checksum differs |
| Rebase to load address | `--rebase` (:275), `RebaseImage` (:907, :970) | `.reloc`-targeted fields rewritten to the FV load address |
| Strip relocations | `-l/--stripped` (:215), `RelocationsStripped` (:945) | `.reloc` section may be removed |
| Section alignment | GenFw alignment padding | trailing/padding bytes differ |

So the declared and observed images differ deterministically. **Byte-integrity is achievable
iff we canonicalize both sides to the same normal form before hashing.**

## Approach — a common canonical form

Define `canon(image)` that maps either side to the same bytes for an unmodified module:

1. Parse PE/COFF (headers, section table, data directories).
2. Zero `TimeDateStamp` (both sides — the build `.efi` still carries the compiler stamp).
3. Zero the optional-header **checksum**.
4. Zero/strip the **debug directory** data (match GenFw's `ZeroDebugData`).
5. **Normalize the base**: rebase both images to a common base (0) with relocations applied,
   OR strip `.reloc` and zero every relocation-targeted field. *(This is the crux — see risks.)*
6. Drop alignment padding beyond the last section's raw size.
7. Hash the canonical bytes.

For an unmodified module `canon(declared .efi) == canon(observed PE32)`; a swapped or
byte-patched module diverges → `modified` → the gate DENYs.

- **Declared side** input: the build output `Build/<Plat>/<T>_<TC>/.../OUTPUT/<Name>.efi`
  (the pre-GenFw image — we apply `canon`, which subsumes GenFw's normalization).
- **Observed side** input: the `EFI_SECTION_PE32` (type `0x10`) extracted from the module's
  FFS in the carved `.fd` (already GenFw-processed — we apply the same `canon`).

## Scope — do the tractable subset first, honestly

| Module class | FFS section | Plan |
|---|---|---|
| **DXE drivers (uncompressed)** | `EFI_SECTION_PE32` (0x10) | **Phase 1–2 target.** PE32, not rebased-in-place; the canonical-form problem is solvable. |
| PEI modules | `EFI_SECTION_TE` (0x12) | **Deferred (Phase 3).** TE header (not PE), XIP/rebased to the flash address — needs the load address + TE→PE normalization. |
| Compressed modules | `EFI_SECTION_COMPRESSION` (0x01) | **Deferred (Phase 3).** Must decompress the FV section (UEFI/Tiano) before the PE32 is reachable. |

Coverage is reported, never hidden: "byte-verified N of M validated modules; the rest remain
membership-only, by class, with the reason." That honesty is the existing project posture.

## Phases

- **Phase 1 — one module, end to end.** Pick one uncompressed DXE driver (e.g. `AmdSevDxe`).
  Implement `canon`; show `canon(declared) == canon(observed)` for the unmodified module, and
  that flipping one byte in the FV image makes them diverge (tamper DETECTED). This proves the
  canonical form and closes the rebase question. *Deliverable: a passing integrity check on 1 module.*
- **Phase 2 — the DXE subset.** Apply to every uncompressed PE32 DXE module in OVMF; populate
  reconcile `modified[]` + a `byte_verified` count; add a coverage line to the verdict. Wire a
  new gate report `component-byte-integrity` (a real SI-7(1) upgrade — today `component-integrity`
  only checks that a *hash is present*, not that the bytes match). *Deliverable: byte-integrity on
  the DXE subset, enforced.*
- **Phase 3 — characterize the rest.** Decompress compressed FV sections; handle TE/PEI rebase.
  Where still infeasible, record the precise reason (as we already do for `modified_skipped`).

## Tooling

- PE/COFF parsing: Python `pefile` (or a small `construct`/struct parser) — keeps it in the
  existing Python producer style (`producers/reconcile/sbom-reconcile.py`).
- FFS/section extraction: reuse the FMMT carve or `uefi-firmware-parser`; walk the FFS section
  headers to pull the `0x10` PE32 payload for each validated GUID.
- Ground truth for `canon`: cross-check against GenFw's actual output (run GenFw on a build
  `.efi` and diff) so `canon` matches edk2's normalization exactly.
- Extend the tool: `sbom-reconcile.py --integrity --build-output <OUTPUT dir> --image <fd>`.

## Success criteria

1. Unmodified DXE module: `canon(declared) == canon(observed)` (Phase 1).
2. A 1-byte tamper (or a swapped same-GUID module) in the FV flips `modified` and DENYs via the
   gate (the money demo — a same-GUID trojan that membership misses).
3. The verdict reports byte-verified coverage honestly (verified vs membership-only, by class).

## Risks / open questions (resolve in Phase 1)

- **Rebase normalization is the crux.** The in-FV image is rebased to its flash load address;
  the build `.efi` is at a different base. Either (a) re-apply relocations to a common base on
  both sides, or (b) strip `.reloc` and zero all relocation-targeted dwords. Pick the one that
  makes `canon` deterministic; this is the main research task and the reason Phase 1 is one module.
- GenFw may apply transforms in an order or with details beyond the six above (section-alignment
  padding, `.reloc` zero-pending strip, TE conversion). Validate `canon` by diffing against a
  real GenFw run, not just by reasoning.
- Compression + TE are genuinely harder — keep them out of the enforced path until characterized.

## Why this, now

The portfolio/hiring review named this the highest-impact next build: it turns the repo's
strongest credibility signal (the GenFw *diagnosis*) into a *solution*, and makes the central
novel claim real. Even Phase 1 (one module) materially changes the story from "I know why this
is hard" to "here is a same-GUID trojan the gate catches."
