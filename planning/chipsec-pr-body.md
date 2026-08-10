# scan_image / EFI_MODULE: optional normalized (rebase-0) module hash

> **Draft PR — do not merge without the design issue landing first.** Open the
> enhancement issue (see `UPSTREAM-CHIPSEC-DRAFT.md`) and let a maintainer pick
> the output shape before this is marked ready. Filed as a **draft** so CI runs
> and reviewers can see the concrete implementation the issue refers to.

## Summary

`tools.uefi.scan_image` (and `EFI_MODULE.calc_hashes`) SHA-256 the PE/TE section
**as it sits in the image** — i.e. after the module was placed at its load
address and its relocations were applied. That hash is ideal for comparing an
image to a *golden snapshot of the same image*, but it is **not stable across
flash layouts** and **not comparable to a build-time hash**: two
functionally-identical builds placed at different addresses hash differently
(ImageBase + every relocation-fixed-up byte differ).

This PR adds an **optional, additive** normalized (rebase-0) hash alongside the
existing one: zero `OptionalHeader.ImageBase` and reverse the base-relocation
fixups before hashing, so the value depends only on the module's code, not on
where it landed. **It does not change or replace the existing `SHA256`, the
`efilist.json` key, or `check` behavior.**

Motivation, prior discussion, and the design question are in the companion issue
(*"scan_image: optional normalized (rebase-0) module hash for cross-layout /
SBOM comparison"*, related to #2360). Short version:
- **Portability** — a normalized hash lets a module extracted from one image be
  recognized in another (different FV packing / load address); useful for
  allow/deny lists that survive re-layout.
- **SBOM alignment** — firmware SBOM efforts (coSWID/RFC 9393, CycloneDX, the OSF
  embedded-SBOM spec) and CISA's 2026 SBOM Minimum Elements call for a
  per-component *hash*. Those declared hashes are build-time / layout-independent
  and cannot be compared to CHIPSEC's as-found hash today. A normalized hash
  closes that gap.

A working reference (out-of-tree) reconciles CHIPSEC-extracted OVMF modules
against a build-time SBOM using exactly this rebase-0 normalization: 122/122
modules match (111 stored rebase-0 in flash, 11 relocated in flash and correctly
un-rebased).

## What changed (additive, non-breaking)

| File | Change |
| --- | --- |
| `chipsec/library/uefi/fv.py` | New dependency-free `normalize_pe_rebase0(data)` (PE32/PE32+): zero `ImageBase`, reverse `IMAGE_DIRECTORY_ENTRY_BASERELOC` fixups (HIGHLOW / DIR64). `EFI_MODULE.calc_hashes(off=0, normalize=False)` gains the flag and sets a new `EFI_MODULE.SHA256_NORM`. TE / non-PE / unparsable / unsupported-reloc → `SHA256_NORM = None` (skipped, never faked). `__str__` prints `SHA256_NORM` when present. |
| `chipsec/library/uefi/spi.py` | Executable leaf sections are hashed with `normalize=True`; `dump_efi_module()` writes an additive `.sha256_norm` sidecar when present. |
| `chipsec/modules/tools/uefi/scan_image.py` | Optional `norm` argument (`-a generate,<json>,<image>,norm`) adds a `sha256_norm` **value field** to each `efilist.json` entry. The `sha256`-as-key schema and `check` are unchanged. Module docstring updated. |
| `tests/library/test_uefi_fv_normalize.py` | Unit tests: normalized hash is stable across `ImageBase` (PE32 & PE32+), reproduces a natively base-0 build byte-for-byte, base-0 module's norm == as-found, TE / non-PE → `None`, `normalize=False` leaves `SHA256_NORM = None`. Synthetic in-memory PEs — no external firmware sample needed. |
| `tests/modules/test_scan_image_norm.py` | Unit tests: `sha256_norm` field is additive and gated on the `norm` flag; `check` still passes on a norm-annotated list and still flags a missing module. |

### Normalization definition (rebase-0)

Parse the PE, set `OptionalHeader.ImageBase = 0`, walk
`IMAGE_DIRECTORY_ENTRY_BASERELOC` and subtract the old `ImageBase` from each
`HIGHLOW`/`DIR64` fixup target, then hash. Equivalent to hashing the module as
GenFw emitted it at build, before relocation. A module already stored at
`ImageBase == 0` normalizes to itself (norm == as-found). `IMAGE_REL_BASED_ABSOLUTE`
padding entries are ignored; any other/unknown reloc type, or an unparsable
header, yields `None` (skip) rather than a wrong hash.

### Scope / non-goals

- Additive only — no change to the default hash, the `efilist.json` key, or `check`.
- Not a signing or trust mechanism; just a layout-independent identity for comparison.
- TE-format normalization is out of scope for now (PE32/PE32+ first); TE sections
  cleanly return `None`.
- No new runtime dependency: the normalizer is a small, self-contained PE parser
  (`pefile` is intentionally *not* used, as it is not a CHIPSEC dependency).

## Testing

- New unit tests: `tests/library/test_uefi_fv_normalize.py` (10) and
  `tests/modules/test_scan_image_norm.py` (4) — all pass.
- Full existing `tests/library` + `tests/modules` suites: **193 passed, 1 skipped**,
  no regressions.
- `flake8` (repo `.flake8`) and `pre-commit` (`end-of-file-fixer`,
  `trailing-whitespace`) clean on all touched/added files.
- Commits are DCO `Signed-off-by`.

## Note for reviewers (pre-existing, unrelated)

While adding the `scan_image` test I hit a **pre-existing import error unrelated
to this change**: `chipsec/modules/tools/uefi/scan_image.py` does
`from chipsec.hal.intel.spi import SPI, BIOS`, but `BIOS` is not exported by
`chipsec.hal.intel.spi` on `chipsec2` (it is already imported from
`chipsec.module_common` on the line above), so importing the module raises
`ImportError`. I kept this PR feature-only (the test shims the import locally). The one-line fix is submitted **separately** as its own PR (branch `fix/scan-image-spi-import`) so the two changes stay independent and easy to review — I'll link it here once filed.

## Open design question (from the issue)

Preference is the additive `sha256_norm` **value field** on each `efilist.json`
entry (keeps the `sha256`-as-key schema and `check` untouched) rather than a
separate `--norm` list variant. Implemented that way here; easy to reshape to
whatever the maintainers prefer.
