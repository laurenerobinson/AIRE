#!/usr/bin/env bash
# M10 optimized variant of the simple ELF fixture (same source; never executed by A.I.R.E.).
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
gcc -m64 -std=c11 -O2 -g0 -fno-pie -no-pie -Wall -Wextra -Werror \
    -o aire_test_binary_O2 ../simple_elf/aire_test_binary.c
chmod 0555 aire_test_binary_O2
sha256sum aire_test_binary_O2 > SHA256SUMS
gcc --version | head -1 > TOOLCHAIN.txt
