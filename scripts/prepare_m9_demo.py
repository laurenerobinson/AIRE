"""Seed demo_artifacts/m9/m9.sqlite for the M9 progress-check demo through the
real GUI worker path, then repeat each job to record a cache hit. Read-only on targets."""
import json, sys, time
from pathlib import Path
from aire.api.binary_library import BinaryLibrary

database = Path('demo_artifacts/m9/m9.sqlite')
library = BinaryLibrary(database, directory=database.parent / 'uploads')
report = {}
try:
    for fixture in ('professor:overloading', 'm9:large_pe_sleigh', 'local:simple-elf'):
        for attempt in ('first', 'repeat'):
            job = library.start(fixture_id=fixture)
            while True:
                row = library.job(job['job_id'])
                if row['status'] in ('completed', 'failed') and 'total_seconds' in row:
                    break
                time.sleep(0.5)
            report[f'{fixture}:{attempt}'] = {k: row.get(k) for k in (
                'status', 'error', 'cache_hit', 'analysis_seconds', 'total_seconds', 'warning_count',
                'decompile_workers', 'original_index_seconds', 'sha256')}
            print(fixture, attempt, report[f'{fixture}:{attempt}'], file=sys.stderr, flush=True)
finally:
    library.close()
Path('docs/m9/demo_preparation.json').write_text(json.dumps(report, indent=1) + '\n')
