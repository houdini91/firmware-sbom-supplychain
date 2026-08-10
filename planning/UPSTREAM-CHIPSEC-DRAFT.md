# Upstream CHIPSEC — draft proposal (Track B)

> **STATUS: DRAFT — NOT FILED.** Filing is a deliberate, owner-gated step. Open the **design issue first**
> (there is no prior art — confirmed), let maintainers weigh in, and only then a PR. Same discipline as the
> uSWID / OSF engagements. Best filed now that Track A is a working reference (`producers/chipsec/deploy-reconcile.py`).
> Repo target: <https://github.com/chipsec/chipsec> · License **GPL-2.0** · DCO `Signed-off-by` required.

## The ask (one line)
Add an **optional, additive normalized (rebase-0) module hash** to `scan_image` / the `EFI_MODULE` hash so
CHIPSEC's per-module hashes become comparable **across flash layouts and against build-time SBOMs**, not only
against a same-layout golden image.

---

## Draft ISSUE (design proposal — paste target: chipsec/chipsec » New issue » "Feature/Enhancement")

**Title:** `scan_image: optional normalized (rebase-0) module hash for cross-layout / SBOM comparison`

**Body:**

> **Summary**
> `tools.uefi.scan_image` (and `EFI_MODULE.calc_hashes`) currently SHA-256 the PE/TE section **as it sits in
> the image** — i.e. after the module was placed at its load address and its relocations applied. That hash is
> perfect for comparing an image to a *golden snapshot of the same image*, but it is **not stable across flash
> layouts** and **not comparable to a build-time hash** of the same module, because two functionally-identical
> builds placed at different addresses hash differently (ImageBase + every relocation-fixed-up byte differ).
>
> This proposes an **optional, additive** normalized (rebase-0) hash alongside the existing one: zero the
> `ImageBase` and reverse the `.reloc` fixups before hashing, so the value depends only on the module's code,
> not on where it landed. It does **not** change or replace the current `SHA256` or the `efilist.json` key.
>
> **Why (motivation)**
> - **Portability:** a normalized hash lets a module extracted from one image be recognized in another
>   (different FV packing / load address) — useful for allow/deny lists that survive re-layout.
> - **SBOM alignment:** firmware SBOM efforts (coSWID/RFC 9393, CycloneDX, the OSF embedded-SBOM spec) and
>   **CISA's 2026 SBOM Minimum Elements** now call for a per-component *hash* so "what's documented" can be
>   checked against "what's deployed." Those declared hashes are build-time / layout-independent; CHIPSEC's
>   as-found hash cannot be compared to them today. A normalized hash closes that gap and makes CHIPSEC a
>   natural verifier for firmware SBOMs.
> - No breaking change: the normalized value is additive; existing golden-image workflows are untouched.
>
> **Where it would live**
> - `EFI_MODULE.calc_hashes()` (`chipsec/library/uefi/fv.py`) computes `SHA256` over `self.Image[off:]`.
>   Add an optional `SHA256_NORM` computed over the rebase-0 form (only meaningful for `EFI_SECTIONS_EXE`).
> - `dump_efi_module()` (`chipsec/library/uefi/spi.py`) already writes a `.sha256` sidecar; add a
>   `.sha256_norm` sidecar when enabled.
> - `scan_image` (`chipsec/modules/tools/uefi/scan_image.py`) — behind a flag (e.g. `-a generate,<file>,norm`),
>   add a `sha256_norm` **value field** to each `efilist.json` entry. **Keep the sha256-as-key schema
>   unchanged** (purely additive), so existing lists and `check` behavior are unaffected.
>
> **Normalization definition (rebase-0)**
> Parse the PE, set `OptionalHeader.ImageBase = 0`, walk `IMAGE_DIRECTORY_ENTRY_BASERELOC` and undo each
> fixup, then hash. (Equivalent to hashing the module as GenFw emitted it at build, before relocation.) TE
> and non-PE / GUID-defined-compressed sections that can't be cleanly parsed are **skipped, not failed**.
>
> **Reference implementation / evidence it works**
> A working reference reconciles CHIPSEC-extracted OVMF modules against a build-time SBOM using exactly this
> rebase-0 normalization: **122/122 modules match** (111 stored rebase-0 in flash, 11 relocated in flash and
> correctly un-rebased). Happy to contribute the normalizer under GPL-2.0 with DCO sign-off.
>
> **Scope / non-goals**
> - Additive only — no change to the default hash or the `efilist.json` key.
> - Not a signing or trust mechanism; just a layout-independent identity for comparison.
> - TE-format handling can land in a follow-up; PE32/PE32+ first.
>
> Would the maintainers be open to this as a flagged feature? Happy to open a PR against an agreed shape.

---

## PR sketch (only after the issue lands positively)
1. `calc_hashes(self, off=0, normalize=False)` → also set `self.SHA256_NORM` when `normalize` and section is exe.
2. Rebase-0 helper (pefile-based): zero ImageBase + reverse `.reloc`; guarded try/except → `None` (skip) on
   TE / unparsable.
3. `dump_efi_module` → `.sha256_norm` sidecar when enabled.
4. `scan_image` `generate` → optional `sha256_norm` value field; `check` unchanged (still keys on `SHA256`).
5. Tests on a bundled sample image; docs note in the module docstring.

## Caveats to hold in mind before filing
- **GPL-2.0:** anything we upstream into CHIPSEC becomes GPL. Keep our own reconcile/normalizer MIT on our
  side of the boundary; the upstreamed copy is a separate GPL contribution. (Our normalizer is small + PE-only.)
- **DCO:** commits need `Signed-off-by` with a real name.
- **Additive, not a key change:** the sha256-as-key schema must stay; propose `sha256_norm` as a value field.
- **Non-duplicative:** confirmed no existing issue/PR on SBOM/normalized/reproducible hashing (A1 scan).
- **Sequencing:** third upstream thread (uSWID #98 merged, #99/#100 open; edk2 #10507) — pace it; issue before PR.
