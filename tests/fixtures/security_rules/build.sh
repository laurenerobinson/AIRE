#!/usr/bin/env bash
set -euo pipefail
# Compile only. Never launch any generated executable.
fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "$fixture_dir/../../.." && pwd)"
output_dir="${AIRE_SECURITY_FIXTURE_OUTPUT_DIR:-$repo_dir/build/security-rules}"
mkdir -p -- "$output_dir"
for name in unsafe_copy safe_copy dangerous_gets; do
    gcc -std=c11 -O0 -g -fno-inline -fno-builtin -fno-pie -no-pie \
        -Wall -Wextra -Werror "$fixture_dir/$name.c" -o "$output_dir/$name"
done
