"""Index binaries into an M10 store through the normal cache path (read-only on targets)."""
import sys
from contextlib import redirect_stdout
from pathlib import Path
from aire.analysis.cache import analyze_binary
from aire.knowledge.database import BinaryKnowledgeStore
database = Path(sys.argv[1])
with BinaryKnowledgeStore(database) as store:
    for path in sys.argv[2:]:
        with redirect_stdout(sys.stderr):
            result = analyze_binary(Path(path), store)
        meta = result.program_index.metadata
        print(path, 'cache_hit', result.cache_hit, 'ir', meta.get('instruction_ir', {}).get('functions'),
              'incomplete', len(meta.get('decompilation_incomplete') or []), f'{result.elapsed_seconds:.1f}s')
