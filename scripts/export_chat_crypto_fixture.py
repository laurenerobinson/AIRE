#!/usr/bin/env python3
"""Export a small, hermetic chat-routing fixture from an already-indexed store.

Copies the three M9 crypto PEs (AES-256-GCM, SHA-256, ECDSA) out of an analysis
SQLite store produced by the real PyGhidra pipeline, keeps every stored fact the
deterministic chat paths read (functions, artifacts, references, edges, thunks),
and keeps M10 instruction IR only for the source ground-truth functions so the
file stays small. No Ghidra run is needed to use or regenerate it.

    scripts/export_chat_crypto_fixture.py demo_artifacts/m10/m10.sqlite \
        tests/fixtures/chatperf/crypto_pe_index.sqlite
"""
import hashlib
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / 'tests/fixtures/m9/crypto_pe/GROUND_TRUTH.json'


def main(source, target):
    source, target = Path(source), Path(target)
    truth = json.loads(TRUTH.read_text())['programs']
    wanted = {program['sha256']: program for program in truth.values()}
    with tempfile.TemporaryDirectory(dir=target.parent if target.parent.exists() else None) as tmp:
        work = Path(tmp) / 'work.sqlite'
        src = sqlite3.connect(f'file:{source}?mode=ro', uri=True)
        dst = sqlite3.connect(work)
        src.backup(dst)
        src.close()
        dst.execute('PRAGMA foreign_keys=ON')
        rows = dst.execute('SELECT binary_id, sha256 FROM binaries').fetchall()
        keep = [binary_id for binary_id, sha in rows if sha in wanted]
        if len(keep) != len(wanted):
            raise SystemExit(f'source store lacks some crypto PEs (found {len(keep)} of {len(wanted)})')
        marks = ','.join('?' * len(keep))
        tables = [r[0] for r in dst.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            columns = [r[1] for r in dst.execute(f'PRAGMA table_info({table})')]
            if 'binary_id' in columns:
                dst.execute(f'DELETE FROM {table} WHERE binary_id NOT IN ({marks})', keep)
        for binary_id, sha in rows:
            if binary_id not in keep:
                continue
            addresses = [f['address'] for f in wanted[sha]['functions'].values()]
            ids = [f'{binary_id}:{a}' for a in addresses]
            id_marks = ','.join('?' * len(ids))
            dst.execute(f'DELETE FROM function_ir WHERE binary_id=? AND function_id NOT IN ({id_marks})',
                        [binary_id, *ids])
            # Chat fast paths read call references, references to stored strings and
            # everything owned by ground-truth functions; other data refs are dropped.
            dst.execute(f"DELETE FROM binary_references WHERE binary_id=? AND is_call=0 "
                        f"AND (source_function_id IS NULL OR source_function_id NOT IN ({id_marks})) "
                        f"AND (target_artifact_id IS NULL OR target_artifact_id NOT IN "
                        f"(SELECT artifact_id FROM artifacts WHERE binary_id=? AND type='STRING'))",
                        [binary_id, *ids, binary_id])
            dst.execute(f'UPDATE functions SET decompiled_text=NULL, assembly=NULL '
                        f'WHERE binary_id=? AND function_id NOT IN ({id_marks})', [binary_id, *ids])
        dst.commit()
        dst.execute('VACUUM')
        dst.close()
        target.parent.mkdir(parents=True, exist_ok=True)
        work.replace(target)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest = {'fixture': target.name, 'sha256': digest, 'exported_from': source.name,
                'binaries': sorted(p['binary'] for p in truth.values()),
                'ground_truth': str(TRUTH.relative_to(ROOT)),
                'note': ('Real PyGhidra index facts. Trimmed: M10 IR, decompiled text and assembly kept only for '
                         'ground-truth functions; non-call data references kept only for strings or ground-truth owners.')}
    (target.parent / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(target, target.stat().st_size, 'bytes', digest)


if __name__ == '__main__':
    main(*sys.argv[1:3])
