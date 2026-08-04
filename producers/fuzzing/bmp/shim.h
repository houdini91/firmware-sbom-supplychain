/*
 * shim.h — Minimal, host-side (off-target) EDK2 type/macro/library shim.
 *
 * Purpose
 * -------
 * Lets the *unmodified* body of TranslateBmpToGopBlt() (copied verbatim from
 * the edk2 tree into LLVMFuzzerTestOneInput.c) compile and link with plain
 * clang + libFuzzer + AddressSanitizer, WITHOUT the edk2 build system,
 * ProcessorBind.h, or any of the real MdePkg libraries.
 *
 * Faithfulness notes (what is exact vs. approximated)
 * ---------------------------------------------------
 *  - The struct layouts (BMP_IMAGE_HEADER, BMP_COLOR_MAP,
 *    EFI_GRAPHICS_OUTPUT_BLT_PIXEL) are copied byte-for-byte from:
 *        MdePkg/Include/IndustryStandard/Bmp.h
 *        MdePkg/Include/Protocol/GraphicsOutput.h
 *    with #pragma pack(1), so sizeof(BMP_IMAGE_HEADER) == 54 and
 *    sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL) == 4 exactly as on target. These
 *    sizes drive every offset/overflow check in the target, so they MUST match.
 *
 *  - RETURN_STATUS is modeled as UINTN (== 64-bit here) and the error-encoding
 *    (MAX_BIT | code) plus EFI_ERROR() are copied from
 *    MdePkg/Include/Base.h / ProcessorBind.h (X64). This reproduces the target's
 *    error-detection semantics exactly on an LP64 host.
 *
 *  - SafeUint32Mult / SafeUint32Add reimplement the real BaseSafeIntLib logic
 *    faithfully: compute in 64-bit, and on overflow set *Result = MAX_UINT32
 *    and return RETURN_BUFFER_TOO_SMALL (see
 *    MdePkg/Library/BaseSafeIntLib/SafeIntLib.c). This is the crux of the
 *    integer-overflow attack surface, so it is reproduced, not stubbed.
 *
 *  - AllocatePool()/FreePool() are mapped to malloc()/free(). This is the main
 *    intentional divergence from on-target semantics; see README limitations.
 *    Using malloc() is what lets ASAN place redzones around the GOP BLT buffer
 *    and around the exact-size input buffer, which is how a width*height*bpp
 *    miscalculation becomes an observable heap-buffer-overflow.
 *
 *  - DEBUG(...) is compiled to nothing by default (define BMP_FUZZ_VERBOSE=1 to
 *    route it to fprintf(stderr,...)). The double-paren edk2 form DEBUG((...))
 *    is preserved so the copied function body is byte-identical.
 */
#ifndef BMP_FUZZ_SHIM_H
#define BMP_FUZZ_SHIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- EDK2 base scalar types (LP64 host mapping) ------------------------- */
typedef uint8_t   UINT8;
typedef uint16_t  UINT16;
typedef uint32_t  UINT32;
typedef uint64_t  UINT64;
typedef int32_t   INT32;
typedef char      CHAR8;
typedef unsigned char BOOLEAN;
typedef void      VOID;

/* On the real X64 target UINTN is 64-bit; match that. */
typedef uint64_t  UINTN;
typedef UINTN     RETURN_STATUS;

#ifndef NULL
#define NULL ((void *)0)
#endif
#define TRUE  ((BOOLEAN)1)
#define FALSE ((BOOLEAN)0)

/* ---- Calling-convention / parameter-direction annotations (no-ops) ------ */
#define EFIAPI
#define IN
#define OUT

/* ---- Limits (MdePkg/Include/Base.h) ------------------------------------- */
#define MAX_UINT32  ((UINT32)0xFFFFFFFFU)

/* ---- Status encoding (Base.h + X64/ProcessorBind.h) --------------------- */
#define MAX_BIT                    0x8000000000000000ULL
#define ENCODE_ERROR(StatusCode)   ((RETURN_STATUS)(MAX_BIT | (StatusCode)))
#define RETURN_ERROR(StatusCode)   (((RETURN_STATUS)(StatusCode)) >= MAX_BIT)
#define EFI_ERROR(A)               RETURN_ERROR(A)

#define RETURN_SUCCESS             ((RETURN_STATUS)(0))
#define RETURN_INVALID_PARAMETER   ENCODE_ERROR(2)
#define RETURN_UNSUPPORTED         ENCODE_ERROR(3)
#define RETURN_BUFFER_TOO_SMALL    ENCODE_ERROR(5)
#define RETURN_OUT_OF_RESOURCES    ENCODE_ERROR(9)
/* EFI_OUT_OF_RESOURCES is used verbatim in the sibling function; alias it. */
#define EFI_OUT_OF_RESOURCES       RETURN_OUT_OF_RESOURCES

/* OFFSET_OF (Base.h) */
#define OFFSET_OF(TYPE, Field)  ((UINTN) __builtin_offsetof(TYPE, Field))

/* ---- DEBUG(): no-op unless BMP_FUZZ_VERBOSE ----------------------------- */
#if defined(BMP_FUZZ_VERBOSE) && BMP_FUZZ_VERBOSE
#define DEBUG_ERROR 0
#define DEBUG_INFO  0
#define DEBUG(Expr)  do { (void)0; } while (0)  /* args vary; keep simple */
#else
#define DEBUG(Expr)
#endif

/* ---- Structures (packed, copied from edk2) ------------------------------ */
#pragma pack(1)

/* MdePkg/Include/IndustryStandard/Bmp.h */
typedef struct {
  UINT8  Blue;
  UINT8  Green;
  UINT8  Red;
  UINT8  Reserved;
} BMP_COLOR_MAP;

typedef struct {
  CHAR8   CharB;
  CHAR8   CharM;
  UINT32  Size;
  UINT16  Reserved[2];
  UINT32  ImageOffset;
  UINT32  HeaderSize;
  UINT32  PixelWidth;
  UINT32  PixelHeight;
  UINT16  Planes;
  UINT16  BitPerPixel;
  UINT32  CompressionType;
  UINT32  ImageSize;
  UINT32  XPixelsPerMeter;
  UINT32  YPixelsPerMeter;
  UINT32  NumberOfColors;
  UINT32  ImportantColors;
} BMP_IMAGE_HEADER;

#pragma pack()

/* MdePkg/Include/Protocol/GraphicsOutput.h (all UINT8 -> layout matches) */
typedef struct {
  UINT8  Blue;
  UINT8  Green;
  UINT8  Red;
  UINT8  Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

/* Compile-time assertions on the sizes that drive the target's arithmetic. */
_Static_assert(sizeof(BMP_IMAGE_HEADER) == 54,
               "BMP_IMAGE_HEADER must be 54 bytes (packed) to match target");
_Static_assert(sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL) == 4,
               "EFI_GRAPHICS_OUTPUT_BLT_PIXEL must be 4 bytes to match target");
_Static_assert(sizeof(BMP_COLOR_MAP) == 4,
               "BMP_COLOR_MAP must be 4 bytes to match target");

/* ---- SafeIntLib faithful reimplementation ------------------------------- */
/* MdePkg/Library/BaseSafeIntLib/SafeIntLib.c: 64-bit intermediate, on
 * overflow set *Result = MAX_UINT32 and return RETURN_BUFFER_TOO_SMALL. */
static inline RETURN_STATUS
SafeUint32Mult (UINT32 Multiplicand, UINT32 Multiplier, UINT32 *Result)
{
  UINT64 Intermediate;
  if (Result == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  Intermediate = ((UINT64)Multiplicand) * ((UINT64)Multiplier);
  if (Intermediate > MAX_UINT32) {
    *Result = MAX_UINT32;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *Result = (UINT32)Intermediate;
  return RETURN_SUCCESS;
}

static inline RETURN_STATUS
SafeUint32Add (UINT32 Augend, UINT32 Addend, UINT32 *Result)
{
  UINT64 Intermediate;
  if (Result == NULL) {
    return RETURN_INVALID_PARAMETER;
  }
  Intermediate = ((UINT64)Augend) + ((UINT64)Addend);
  if (Intermediate > MAX_UINT32) {
    *Result = MAX_UINT32;
    return RETURN_BUFFER_TOO_SMALL;
  }
  *Result = (UINT32)Intermediate;
  return RETURN_SUCCESS;
}

/* ---- MemoryAllocationLib shim (malloc/free) ----------------------------- */
static inline VOID *
AllocatePool (UINTN AllocationSize)
{
  /* Real AllocatePool returns NULL for size 0 in many implementations; the
   * target treats a NULL return as RETURN_OUT_OF_RESOURCES, which is a benign
   * path, so mirroring malloc() here is fine for fuzzing. */
  return malloc ((size_t)AllocationSize);
}

static inline VOID *
AllocateZeroPool (UINTN AllocationSize)
{
  return calloc ((size_t)AllocationSize, 1);
}

static inline VOID
FreePool (VOID *Buffer)
{
  free (Buffer);
}

#endif /* BMP_FUZZ_SHIM_H */
