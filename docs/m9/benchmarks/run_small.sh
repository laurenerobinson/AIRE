#!/usr/bin/env bash
# M9 before/after benchmark, small+medium binaries. Run from repo root.
set -euo pipefail
export GHIDRA_INSTALL_DIR=/home/laurene/tools/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
BEFORE_SRC=/home/laurene/aire_backups/m9-pre-20261110-153900/worktree/aire-server/src
OUT=docs/m9/benchmarks
BINS="tests/fixtures/simple_elf/aire_test_binary tests/fixtures/external/angr/windows_tls_x86/TLS.exe professor_samples/function_overloading/original/FunctionOverloading.exe tests/fixtures/m9/large_pe/sleigh.exe"
PYTHONPATH=$BEFORE_SRC aire-server/.venv/bin/python scripts/benchmark_m9.py $BINS --repeat 5 --no-warm sleigh.exe \
  --label before --output $OUT/before_small.json --progress $OUT/progress.jsonl
PYTHONPATH=aire-server/src aire-server/.venv/bin/python scripts/benchmark_m9.py $BINS --repeat 5 --no-warm sleigh.exe \
  --label after --output $OUT/after_small.json --progress $OUT/progress.jsonl
