# Host-based libFuzzer harness — edk2 `TranslateBmpToGopBlt`

A self-contained, off-target (runs on your Linux host, not in firmware) libFuzzer
+ AddressSanitizer harness for the edk2 BMP → GOP BLT image converter. Built as a
portfolio artifact demonstrating how to lift a self-contained UEFI parser out of
the edk2 build system and fuzz it in seconds.

## What it targets and why

**Function:** `TranslateBmpToGopBlt()`
**edk2 source:** `MdeModulePkg/Library/BaseBmpSupportLib/BmpSupportLib.c`, lines
**78–434** (the `RETURN_STATUS TranslateBmpToGopBlt(...)` definition).

This routine takes a raw, attacker-controlled BMP buffer plus its size and
produces a GOP BLT (Graphics Output Protocol Block Transfer) pixel buffer. It is
reachable during boot wherever firmware renders a BMP (boot logo, setup UI, OEM
splash), so its input is genuinely untrusted. It is a textbook parser attack
surface:

- **Integer-overflow allocation math.** Output size is
  `PixelWidth * PixelHeight * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)`, with header
  fields fully attacker-controlled. The code guards every multiply/add with
  `SafeUint32Mult`/`SafeUint32Add` — precisely the checks a fuzzer should try to
  defeat or find gaps around.
- **Bounds of the input walk.** The pixel loop advances an `Image` pointer
  through the input buffer and indexes a `BmpColorMap[]` for 1/4/8-bpp palette
  modes. Any mismatch between the header-declared geometry and the real buffer
  becomes an out-of-bounds read.

It is also largely **self-contained**: its only real dependencies are two packed
structs, a couple of `SafeIntLib` helpers, and `AllocatePool`/`FreePool`. That
makes it a clean candidate for a host shim.

## Files

| File | Purpose |
|------|---------|
| `LLVMFuzzerTestOneInput.c` | The harness. Contains the **verbatim** copy of `TranslateBmpToGopBlt` (BmpSupportLib.c:78–434) plus the `LLVMFuzzerTestOneInput` entry point. |
| `shim.h` | Minimal EDK2 type/macro/library shim (`UINT8`/`UINTN`/`RETURN_STATUS`/the BMP+GOP structs/`SafeUint32Mult`/`SafeUint32Add`/`AllocatePool→malloc`/`FreePool→free`/`DEBUG→no-op`). Lets the copied body build with plain clang, no edk2 build system. |
| `build.sh` | `clang -g -O1 -fsanitize=fuzzer,address` → `./bmp_fuzzer`. |
| `gen_seeds.py` | Emits the seed corpus programmatically (no hand-committed binaries). |
| `seeds/` | Three tiny, fully-valid BMPs (1×1 24bpp, 2×2 24bpp, 4×4 8bpp-palette). |

The edk2 tree is **not modified and not built**. The struct layouts, status
encoding, and `SafeIntLib` semantics in `shim.h` are copied faithfully from
`MdePkg` so the fuzzed logic matches on-target behavior (see Limitations for the
one deliberate divergence: the allocator).

## Build & run

Requires **clang ≥ 6** with libFuzzer+ASan (verified with Ubuntu clang 18.1.3,
x86_64). On a 64-bit host:

```sh
python3 gen_seeds.py      # (re)generate seeds/
./build.sh                # produces ./bmp_fuzzer
./bmp_fuzzer -max_len=4096 seeds/
```

Replay a single input (e.g. a crash repro): `./bmp_fuzzer ./crash-<hash>`.
Verbose target `DEBUG(...)` output is compiled out by default; it is a no-op
macro, not wired to stderr, to keep fuzzing fast.

## What a crash means (bug classes)

A libFuzzer/ASan report here maps to one of:

- **heap-buffer-overflow READ** in the pixel loop — the input `Image` pointer or
  a `BmpColorMap[Index]` access ran past the end of the BMP buffer. Root cause is
  a geometry/stride/color-map mismatch that the up-front validation did not
  reject.
- **heap-buffer-overflow WRITE** into `*GopBlt` — `BltBufferSize` (the allocation)
  came out smaller than what the `Blt`/`Height`/`Width` write loop actually
  touches. This is the payoff of a defeated integer-overflow check.
- **allocation-size / OOM** signals — a header that coaxes a huge but
  non-overflowing `BltBufferSize` past the `SafeUint32*` guards.

### This harness already finds one

Out of the box, within ~20s, the fuzzer produces:

```
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
  #0 TranslateBmpToGopBlt LLVMFuzzerTestOneInput.c:323  (BmpColorMap[Index].Red)
  ... located 10 bytes after a 58-byte region
```

**Interpretation:** for an indexed-color depth (1/4/8 bpp), `BmpColorMap` is
computed as `BmpImage + sizeof(BMP_IMAGE_HEADER)`, but the check that a color map
of `4 * ColorMapNum` bytes actually *exists* only runs when
`ImageOffset > sizeof(BMP_IMAGE_HEADER)`. A mutant with `BitPerPixel = 4` and
`ImageOffset == 54` (no color-map region) therefore indexes `BmpColorMap[0..15]`
straight past the end of the buffer — an out-of-bounds read of memory adjacent to
the BMP allocation. This is faithful to on-target behavior: the same pointer math
runs in firmware and would read whatever heap follows the BMP buffer. It is a
genuine finding of the extracted logic, included here as evidence the harness
exercises the real attack surface rather than a stub. (Left as an exercise / not
"fixed" — the point of the artifact is the harness, and reporting/triage would be
the next step against a specific edk2 revision.)

## Limitations (honest)

- **Host shim ≠ on-target semantics.** This fuzzes the *extracted* function with
  host-modeled dependencies, not a real firmware execution. Control flow and
  arithmetic are identical; the environment is not.
- **`AllocatePool` → `malloc`.** The biggest deliberate divergence. Real
  `AllocatePool` has different alignment (8-byte EFI pool alignment), different
  failure behavior, and no ASan redzones. Mapping it to `malloc` is what lets
  ASan instrument the output buffer — but it means alignment-sensitive bugs and
  pool-metadata effects are **not** modeled. Over-reads/writes relative to the
  *allocation size* are modeled accurately; anything depending on the real pool
  allocator's layout is not.
- **Input is copied into an exact-size `malloc` buffer** before the call. This is
  intentional (tight ASan redzones catch over-reads past `BmpImageSize`), and it
  is a *stronger* oracle than firmware's real heap — some reported OOB reads are
  1–15 bytes past the buffer that on real hardware would land in adjacent slack
  or heap metadata. That does not make them false: they are still reads the
  validation failed to bound. Triage each against the specific edk2 revision.
- **`UINTN`/`RETURN_STATUS` are 64-bit** (LP64 host / X64 target). Building 32-bit
  would change these widths and the `MAX_BIT` error encoding; don't. IA32
  firmware would have 32-bit `UINTN` and slightly different edge behavior around
  the `(UINTN)BltBufferSize` casts.
- **`DEBUG(...)` is a no-op**, so the upstream `Temp` variable (only consumed
  inside a `DEBUG`) compiles to an "unused-but-set" warning. That warning is a
  faithful reflection of upstream code under a silent `DEBUG`, not a harness bug.
- **Single revision, single function.** Only `TranslateBmpToGopBlt` is fuzzed
  (the companion encoder `TranslateGopBltToBmp` is not attacker-reachable from a
  raw byte buffer and is omitted). Findings should be re-confirmed against the
  exact upstream commit you care about, since the validation has been hardened
  over time.
```
