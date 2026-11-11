"""Interleaved (drift-resistant) M9 before/after benchmark driver.

Each repetition runs every condition once, rotating the order (A B C, B C A,
C A B, ...) so slow machine drift affects all conditions equally. Each
condition invocation is a separate scripts/benchmark_m9.py --repeat 1 run
(new processes). Results append to docs/m9/benchmarks/progress.jsonl with
labels i-before / i-after / i-after-w1.
"""
import os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BEFORE_SRC = '/home/laurene/aire_backups/m9-pre-20261110-153900/worktree/aire-server/src'
AFTER_SRC = str(ROOT / 'aire-server/src')
OUT = ROOT / 'docs/m9/benchmarks'
CONDITIONS = {'i-before': (BEFORE_SRC, {}), 'i-after': (AFTER_SRC, {}),
              'i-after-w1': (AFTER_SRC, {'AIRE_DECOMPILE_WORKERS': '1'})}
SETS = [
    (['tests/fixtures/simple_elf/aire_test_binary', 'tests/fixtures/external/angr/windows_tls_x86/TLS.exe',
      'professor_samples/function_overloading/original/FunctionOverloading.exe'],
     ['i-before', 'i-after', 'i-after-w1'], []),
    (['tests/fixtures/m9/large_pe/sleigh.exe'], ['i-before', 'i-after'], ['--no-warm', 'sleigh.exe']),
]
repeat = int(sys.argv[1]) if len(sys.argv) > 1 else 5
for binaries, labels, extra in SETS:
    for rep in range(repeat):
        order = labels[rep % len(labels):] + labels[:rep % len(labels)]
        for label in order:
            src, env_extra = CONDITIONS[label]
            env = {**os.environ, 'PYTHONPATH': src, **env_extra,
                   'GHIDRA_INSTALL_DIR': '/home/laurene/tools/ghidra',
                   'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
            env.pop('AIRE_DECOMPILE_WORKERS', None) if 'AIRE_DECOMPILE_WORKERS' not in env_extra else None
            subprocess.run([str(ROOT / 'aire-server/.venv/bin/python'), str(ROOT / 'scripts/benchmark_m9.py'),
                            *binaries, '--repeat', '1', '--label', label, *extra,
                            '--output', str(OUT / 'interleaved' / f'{label}-{Path(binaries[0]).name}-rep{rep}.json'),
                            '--progress', str(OUT / 'progress.jsonl')], env=env, cwd=ROOT, check=True)
