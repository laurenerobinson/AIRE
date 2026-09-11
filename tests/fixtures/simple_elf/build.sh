#!/usr/bin/env bash
set -euo pipefail

# Resolve the fixture directory without depending on the caller's directory.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
gcc -m64 -std=c11 -O0 -g -fno-inline -fno-pie -no-pie \
    -Wall -Wextra -Werror -o aire_test_binary aire_test_binary.c
cp -- aire_test_binary aire_test_binary_stripped
strip --strip-all aire_test_binary_stripped

# Compare complete stdout as well as exit status for each binary and operation.
for binary in ./aire_test_binary ./aire_test_binary_stripped; do
    for sample in 1 2 3; do
        case "$sample" in
            1) input=hello; expected=$'A.I.R.E. simple ELF fixture\nProcessed: HELLO\nLength: 5; checksum: 20; transformed checksum: 116\nResult: 121' ;;
            2) input=hello; expected=$'A.I.R.E. simple ELF fixture\nProcessed: HELLO\nLength: 5; checksum: 20; transformed checksum: 116\nResult: 580' ;;
            3) input=test; expected=$'A.I.R.E. simple ELF fixture\nSecret operation selected.\nProcessed: TEST\nLength: 4; checksum: 192; transformed checksum: 64\nResult: 71' ;;
        esac
        actual=$("$binary" "$input" "$sample")
        if [[ "$actual" != "$expected" ]]; then
            printf 'FAIL: %s %s %s\nExpected:\n%s\nActual:\n%s\n' \
                "$binary" "$input" "$sample" "$expected" "$actual" >&2
            exit 1
        fi
        printf 'PASS: %s %s %s\n' "$binary" "$input" "$sample"
    done
done
