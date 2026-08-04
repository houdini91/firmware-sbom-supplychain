#!/usr/bin/env bash
#
# build.sh — compile the host-based BMP->GOP-BLT libFuzzer harness.
#
# Requirements
# ------------
#   * clang with libFuzzer + AddressSanitizer support.
#     Verified with: Ubuntu clang 18.1.3 (x86_64).
#     Any clang >= 6.0 ships -fsanitize=fuzzer,address and will work; older
#     clang (< 6) predates the built-in libFuzzer driver and is unsupported.
#   * A 64-bit (LP64) host. shim.h models UINTN/RETURN_STATUS as 64-bit to
#     match the X64 edk2 target; building 32-bit would change those widths.
#
# Output: ./bmp_fuzzer
#
set -euo pipefail

CC="${CC:-clang}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Using compiler: $($CC --version | head -1)"

# -g       : line-accurate ASAN / libFuzzer stack traces
# -O1      : light optimization (fast fuzzing, still readable crash frames)
# -fsanitize=fuzzer,address : link libFuzzer driver + AddressSanitizer
# -fno-omit-frame-pointer   : nicer stacks
# -Wall    : the copied edk2 body should compile warning-clean under the shim
"$CC" -g -O1 \
    -fsanitize=fuzzer,address \
    -fno-omit-frame-pointer \
    -Wall \
    -I"$HERE" \
    "$HERE/LLVMFuzzerTestOneInput.c" \
    -o "$HERE/bmp_fuzzer"

echo "Built: $HERE/bmp_fuzzer"
echo "Run:   $HERE/bmp_fuzzer -max_len=4096 $HERE/seeds/"
