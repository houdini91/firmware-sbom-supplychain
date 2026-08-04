# R4 — byte-integrity reconcile (plan + Phase 1 results)

## ✅ Phase 1 — RESULTS (2026-08-04, branch `r4-byte-integrity-phase1`)

**Byte-integrity works for uncompressed DXE drivers with NO canonicalization — and a
same-GUID trojan is detected.** Tool: [`../producers/reconcile/byte-integrity.py`](../producers/reconcile/byte-integrity.py).

Findings that simplified the plan:
- The declared side is the SBOM's per-module SHA-256, which is the build's
  `OUTPUT/<mod>.efi` — **already GenFw-normalized** (`TimeDateStamp=0`, `CheckSum=0`,
  `ImageBase=0`, verified with pefile). OVMF does **not** rebase DXE drivers in flash
  (they keep `ImageBase=0` + `.reloc`, relocated at load by the DXE core). So the
  feared `canon()` (timestamp/checksum/debug/**rebase**) is **unnecessary for this class**.
- The observed side is the `EFI_SECTION_PE32` (type `0x10`) payload inside the module's
  FFS in the **deployed `.fd`** (FMMT decompresses the DXEFV; a hand-written FFS/section
  walker pulls the PE32). The earlier "in-image `50172c36` != declared `5fe71c0c`" note was
  an **extraction artifact** — it included the 4-byte `EFI_COMMON_SECTION_HEADER` (or hashed
  the debug image). Corrected: strip the section header and the PE32 payload is exact.
- **5/5 DXE drivers byte-identical** declared vs extracted-from-deployed-`.fd`
  (AmdSevDxe, IoMmuDxe, PlatformDxe, VirtioGpuDxe, VirtHstiDxe), and each equals the SBOM's
  already-declared hash — so integration needs **no new declared-side data**.
- **Same-GUID trojan detected:** FMMT-replaced AmdSevDxe with a 1-bit-flipped PE32 (same
  FILE_GUID) → `byte-integrity.py` reports it `MODIFIED` (`5fe71c0c` != `e0d3ec71`), exit 1,
  while the untouched IoMmuDxe stays verified. Membership reconcile passes this; byte-integrity
  does not.

**Net:** `modified` is now real for the uncompressed-DXE class.

## ✅ Phase 2 — RESULTS (2026-08-04)

Byte-integrity is now **enforced as a gate report** (`component-byte-integrity`), with honest
coverage over the PE32-carrying modules:

- Ran over all **122** module components with a GUID + declared hash on the real OVMF.fd:
  **111 byte-verified · 0 modified · 11 deferred**, `clean=true`.
- The 11 deferred are **all XIP/rebased PEI-phase modules** (9 PEIM, 1 PEI_CORE, 1 SEC) — classified from the
  SBOM's `edk2:moduleType` and reported as *needs-canonicalization (phase 3)*, **never as tampered**. This
  matters: an initial run without the classifier flagged those 11 as `modified` (false positives); the fix is
  the honest classification, so a clean image is clean.
- Producer `byte-integrity.py` emits the verdict → `inputs/byte-integrity.json` (committed evidence, like
  `chipsec.json`). The Python assembler derives `byte_integrity {ran, checked, verified, modified_count}`; the
  rego `component-byte-integrity` report requires `ran ∧ checked>0 ∧ modified_count==0` (non-vacuous), tagged
  SI-7(1)/SR-4(3)/S2C2F-AUD-3 and wired into `frameworks.yaml`. Negative fixture `byte-integrity-modified`
  isolates it. Pipeline (run.sh, CI, pipeline-negative) passes `BYTE_INTEGRITY_JSON`.
- **Same-GUID trojan, end to end:** the Phase-1 FMMT-swap demo (1-bit-flipped AmdSevDxe under the same
  FILE_GUID) → `modified_count>0` → the gate DENYs. Membership passes it; byte-integrity + the gate do not.

**Coverage is honest:** 111/122 enforced, 11 XIP deferred with the reason recorded — the SI-7(1) control now
means *the bytes match*, not merely *a hash is present*.

## ✅ Phase 3 — RESULTS (2026-08-04)

**Byte-integrity now verifies all 122 PE32-carrying modules (122/122 checked) — 122 of the 123 non-library
modules; the 123rd, `ResetVector`, is a raw blob with no PE32, covered by membership.** The 11 XIP/PEI modules
are now byte-verified via un-rebase canonicalization, not deferred.

- The only difference between a declared PEI `.efi` and its in-flash copy is the **rebase**: placing the module
  at its flash load address `L` adds `L` to every relocation-listed field, and sets `ImageBase = L`. Everything
  else is identical (confirmed with pefile: same entrypoint, same size, same 65 relocations; only `ImageBase`
  differs, e.g. `0` vs `0x83dec0`).
- `canon_unrebase()` (in `byte-integrity.py`, using `pefile`) undoes it: for each base-relocation entry subtract
  `L` from the target dword/qword, then zero `ImageBase`/`TimeDateStamp`/`CheckSum`. The relocation table lists
  exactly which bytes were shifted, so this is **exact and reversible** — and a real tamper changes code the
  relocation table doesn't cover, so it still fails.
- Verified: all **11** XIP modules (9 PEIM + 1 PEI_CORE + 1 SEC) match their declared hash after un-rebase.
  Full run over the real OVMF.fd: **checked 122 · verified 122 (111 direct + 11 un-rebase) · 0 modified ·
  0 skipped · clean**. A same-GUID swap is still caught in every class.
- Only genuinely different formats remain out of scope: **TE-format** sections and **compressed** sections
  (none in this image's checkable set). `pefile` added to `requirements.txt`; the gate report and evidence are
  unchanged in shape (the coverage number simply went to 100%).

**Net:** the reconcile-to-*bytes* claim — the project's central novel control — is now real for the **entire**
firmware image, with the rebase "crux" solved.

---

## Original plan

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
