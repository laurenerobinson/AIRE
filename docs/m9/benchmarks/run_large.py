"""Reduced-sample large-PE benchmark (user-approved): decompile.exe, cold only,
interleaved after/before/after/before/after (3 after + 2 before)."""
import os, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
SRC = {'i-before': '/home/laurene/aire_backups/m9-pre-20261110-153900/worktree/aire-server/src',
       'i-after': str(ROOT / 'aire-server/src')}
for rep, label in enumerate(['i-after', 'i-before', 'i-after', 'i-before', 'i-after']):
    env = {**os.environ, 'PYTHONPATH': SRC[label], 'GHIDRA_INSTALL_DIR': '/home/laurene/tools/ghidra',
           'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
    env.pop('AIRE_DECOMPILE_WORKERS', None)
    subprocess.run([str(ROOT / 'aire-server/.venv/bin/python'), str(ROOT / 'scripts/benchmark_m9.py'),
                    'tests/fixtures/m9/large_pe/decompile.exe', '--repeat', '1', '--label', label,
                    '--no-warm', 'decompile.exe',
                    '--output', str(ROOT / f'docs/m9/benchmarks/interleaved/{label}-decompile.exe-rep{rep}.json'),
                    '--progress', str(ROOT / 'docs/m9/benchmarks/progress.jsonl')], env=env, cwd=ROOT, check=True)
