"""Transient application prioritization from stored facts; never ML confidence.

M3 connectivity retains its independent meaning. This module reads lightweight
metadata and resolved CALLs, not ProgramIndex or whole-database code bodies.
"""
from collections import deque
from dataclasses import asdict, dataclass
import re

from aire.knowledge.retrieval import ProgramQueryService, _address_key

RELEVANCE_POLICY_VERSION = 'application-relevance-v2'
APPLICATION_ENTRIES = frozenset(('main', 'wmain', 'WinMain', 'wWinMain'))
ELF_RUNTIME = frozenset(('__do_global_dtors_aux', 'frame_dummy',
                        'register_tm_clones', 'deregister_tm_clones'))
MSVC_RUNTIME = frozenset(('pre_c_initialization', 'pre_cpp_initialization',
    'post_pgo_initialization', '__CheckForDebuggerJustMyCode', 'guard_check_icall'))
BRIDGES = frozenset(('_start', '__libc_start_main', '__scrt_common_main',
    '__scrt_common_main_seh', 'invoke_main', 'mainCRTStartup', 'wmainCRTStartup',
    'WinMainCRTStartup', 'wWinMainCRTStartup'))
RUNTIME_FAMILY = re.compile(r'^_{2,}(?:scrt_|security_|acrt_|vcrt_|crt_|libc_csu_)|^_{1,2}RTC_')
GENERIC_NAME = re.compile(r'^(?:FUN|sub|fn)_[0-9a-fA-F]+$')
ELIGIBLE = frozenset(('APPLICATION_CANDIDATE', 'UNKNOWN_INTERNAL'))
STANDARD_LIBRARY = re.compile(r'^(?:(?:public|private|protected):\s*)?(?:[\w:*<>]+\s+)*std::')


def classify(function):
    """Conservative symbol rules; no blanket double-underscore or library flag rule."""
    if function['is_external']:
        return 'EXTERNAL', 'stored external flag'
    if function['is_thunk']:
        return 'THUNK', 'stored thunk flag; forwarding is traversal only'
    name = function['current_name'].removeprefix('FID_conflict:')
    namespace = function['namespace'] or ''
    if (STANDARD_LIBRARY.match(name) or namespace == 'std' or namespace.startswith('std::')
            or name.startswith(('__cxa_', '__gxx_', '_Unwind_'))):
        return 'STANDARD_LIBRARY', 'recognized standard-library/runtime symbol or namespace: ' + name
    # MSVC x86 decoration can add one underscore to a recognized CRT symbol.
    canonical = name[1:] if name.startswith('___') else name
    if canonical in BRIDGES:
        return 'RUNTIME_BRIDGE', 'recognized startup bridge symbol: ' + name
    if (name in ELF_RUNTIME or name in MSVC_RUNTIME or RUNTIME_FAMILY.match(name)
            or any(RUNTIME_FAMILY.match(part) for part in (function['namespace'] or '').split('::'))):
        return 'RUNTIME', 'recognized compiler/runtime symbol or namespace: ' + name
    if GENERIC_NAME.fullmatch(name):
        return 'UNKNOWN_INTERNAL', 'generic stored symbol; purpose unknown'
    return 'APPLICATION_CANDIDATE', 'internal symbol without a recognized runtime pattern'


@dataclass(frozen=True)
class FunctionRelevance:
    function: dict
    classification: str
    score: int
    reasons: tuple[str, ...]
    path: tuple[dict, ...] = ()

    def to_dict(self):
        return asdict(self)


@dataclass
class RelevanceSnapshot:
    items: list[FunctionRelevance]
    edges: list[dict]
    diagnostics: dict


class ApplicationRelevanceService:
    """Metadata/graph scan and stable sorting; bounded traversal and body loading.

    Ranking inspects all lightweight graph facts for a fair global fallback.
    Traversal visits at most 256 nodes / 1024 links and depth eight. Only callers
    selecting evidence load bodies. A single literal x86 JMP in a stored thunk
    is a forwarding reference for this policy, never a synthesized CALL edge.
    """
    MAX_DEPTH = 8
    MAX_VISITS = 256
    MAX_LINKS = 1024

    def __init__(self, store):
        self.query = ProgramQueryService(store)

    def rank_application_functions(self, binary_id, *, limit=10):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('limit must be an integer between 1 and 100')
        with self.query._snapshot(binary_id) as db:
            snapshot = self._rank(db, binary_id)
        return {'policy_version': RELEVANCE_POLICY_VERSION,
                'scope': 'Heuristic prioritization, not proof of authorship, behavior or probability',
                'items': [r.to_dict() for r in snapshot.items[:limit]],
                'diagnostics': snapshot.diagnostics}

    def _rank(self, db, binary_id):
        binary = db.execute('SELECT architecture,entry_point FROM binaries WHERE binary_id=?',
                            (binary_id,)).fetchone()
        rows = db.execute('''SELECT function_id,binary_id,address,current_name,namespace,
            is_external,is_thunk,instruction_count,basic_block_count,branch_count,
            coalesce(length(decompiled_text),0)>0 AS has_decompilation,
            coalesce(length(assembly),0)>0 AS has_assembly,
            CASE WHEN is_thunk=1 AND instruction_count=1 THEN substr(assembly,1,160)
                 ELSE NULL END AS forwarding_instruction
            FROM functions WHERE binary_id=?''', (binary_id,)).fetchall()
        key = lambda f: (_address_key(f['address']), f['function_id'])
        facts = {r['function_id']: dict(r) for r in sorted(rows, key=key)}
        classes = {i: classify(f) for i, f in facts.items()}
        edges = [dict(r) for r in db.execute('''SELECT DISTINCT caller_function_id,
            callee_function_id,callsite_address,edge_type FROM function_edges
            WHERE binary_id=? AND edge_type='CALL' ''', (binary_id,))]
        edges.sort(key=lambda e: (key(facts[e['caller_function_id']]),
            key(facts[e['callee_function_id']]), _address_key(e['callsite_address'])))
        outgoing = {i: set() for i in facts}
        links = {i: [] for i in facts}
        for e in edges:
            a, b = e['caller_function_id'], e['callee_function_id']
            outgoing[a].add(b)
            links[a].append({'kind': 'CALL', 'source_id': a, 'target_id': b,
                             'callsite_address': e['callsite_address']})
        forwarding = {}
        version = db.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()[0]
        bindings = {}
        if version != '1':
            for row in db.execute('SELECT * FROM thunk_relations WHERE binary_id=? ORDER BY ordinal', (binary_id,)):
                bindings.setdefault(row['thunk_function_id'], []).append(dict(row))
        for i, rows in bindings.items():
            if len(rows) == 1 and i in facts and rows[0]['target_function_id'] in facts:
                row = rows[0]
                forwarding[i] = row['target_function_id']
                links[i].append({'kind': 'THUNK_JUMP' if row['is_direct_jump'] else 'THUNK_BINDING',
                    'source_id': i, 'target_id': row['target_function_id'],
                    'instruction_address': row['source_address'], 'source_table': 'thunk_relations',
                    'is_direct_jump': bool(row['is_direct_jump'])})
        by_address = {}
        for i, f in facts.items():
            by_address.setdefault(_address_key(f['address'])[:3], []).append(i)
        if 'x86' in (binary['architecture'] or '').lower():
            for i, f in facts.items():
                text = f.pop('forwarding_instruction') or ''
                if i in bindings:
                    continue  # Never override explicit (possibly ambiguous) stored bindings.
                match = re.fullmatch(r'\s*([^\s]+):\s+JMP\s+(0x[0-9a-fA-F]+)\s*', text)
                if not match or _address_key(match[1])[:3] != _address_key(f['address'])[:3]:
                    continue
                targets = by_address.get(_address_key(match[2])[:3], [])
                if len(targets) == 1 and targets[0] != i:
                    forwarding[i] = targets[0]
                    links[i].append({'kind': 'THUNK_JUMP', 'source_id': i,
                        'target_id': targets[0], 'instruction_address': f['address']})
        for f in facts.values():
            f.pop('forwarding_instruction', None)
        for values in links.values():
            values.sort(key=lambda e: (key(facts[e['target_id']]), e['kind'],
                                      _address_key(e.get('callsite_address', e.get('instruction_address', '')))))
        # Exact application entries, stored entry/export, then known startup
        # bridges if entry facts are unavailable. Roots are never guessed from degree.
        exact = [i for i, f in facts.items() if f['current_name'] in APPLICATION_ENTRIES
                 and classes[i][0] in ELIGIBLE]
        exports = {r[0] for r in db.execute('''SELECT address FROM artifacts
            WHERE binary_id=? AND type='EXPORT' AND value IN
            ('entry','_start','mainCRTStartup','wmainCRTStartup','WinMainCRTStartup','wWinMainCRTStartup')''', (binary_id,))}
        entries = [i for i, f in facts.items() if not f['is_external'] and
                   (f['address'] == binary['entry_point'] or f['address'] in exports)]
        exact_ids, entry_ids = set(exact), set(entries)
        all_starts = exact or entries or [i for i in facts if classes[i][0] == 'RUNTIME_BRIDGE']
        starts = all_starts[:16]
        queue = deque((i, 0, None, ()) for i in starts)
        visited, paths, boundaries = set(starts), {}, {}
        scanned, cut = 0, len(all_starts) > len(starts)
        while queue:
            parent, depth, bridge, path = queue.popleft()
            category = classes[parent][0]
            if category == 'RUNTIME_BRIDGE':
                bridge = parent
            elif category not in ('THUNK',) and category not in ELIGIBLE:
                bridge = None
            if depth >= self.MAX_DEPTH:
                cut |= bool(links[parent])
                continue
            for link in links[parent]:
                if scanned >= self.MAX_LINKS:
                    cut = True
                    break
                scanned += 1
                child = link['target_id']
                if child in visited:
                    continue
                if len(visited) >= self.MAX_VISITS:
                    cut = True
                    continue
                visited.add(child)
                child_path = path + (link,)
                paths[child] = child_path
                child_class = classes[child][0]
                if child_class in ELIGIBLE and bridge:
                    boundaries[child] = bridge
                queue.append((child, depth + 1,
                              None if child_class in ELIGIBLE else bridge, child_path))
            if scanned >= self.MAX_LINKS:
                break

        def effective(identity):
            seen = set()
            for _ in range(self.MAX_DEPTH):
                if identity not in forwarding or identity in seen:
                    break
                seen.add(identity)
                identity = forwarding[identity]
            return identity

        effective_out = {i: {effective(j) for j in js if effective(j) != i
                            and classes[effective(j)][0] in ELIGIBLE}
                         for i, js in outgoing.items()}
        app_in = {i: set() for i in facts}
        for i, js in effective_out.items():
            if classes[i][0] in ELIGIBLE:
                for j in js:
                    app_in[j].add(i)
        # A bounded second walk from the discovered application boundary also
        # follows stored forwarding references. Graph metrics remain modest.
        app_distances = {}
        app_starts = list(dict.fromkeys(exact + list(boundaries)))[:self.MAX_VISITS]
        cut |= len(set(exact) | set(boundaries)) > len(app_starts)
        frontier = deque((i, 0) for i in app_starts)
        app_seen = set(app_starts)
        app_scanned = 0
        while frontier and app_scanned < self.MAX_LINKS:
            i, depth = frontier.popleft()
            if depth >= 3:
                continue
            for j in sorted(effective_out[i], key=lambda j: key(facts[j])):
                if app_scanned >= self.MAX_LINKS or len(app_seen) >= self.MAX_VISITS:
                    cut = True
                    break
                app_scanned += 1
                if j not in app_seen:
                    app_seen.add(j)
                    app_distances[j] = depth + 1
                    frontier.append((j, depth + 1))
        items = []
        for i, f in facts.items():
            category, reason = classes[i]
            reasons = [reason]
            score = {'EXTERNAL': -200, 'THUNK': -150, 'RUNTIME': -100, 'STANDARD_LIBRARY': -100,
                     'RUNTIME_BRIDGE': -80}.get(category, 20)
            if category in ELIGIBLE:
                reasons.append('internal non-thunk (+20)')
                for enabled, points, explanation in (
                    (f['has_decompilation'], 8, 'stored decompilation available'),
                    (f['has_assembly'], 4, 'stored assembly available'),
                    ((f['instruction_count'] or 0) >= 8, 4, 'at least eight instructions'),
                    ((f['basic_block_count'] or 0) >= 2, 2, 'multiple basic blocks'),
                    (i in exact_ids, 100, 'exact stored application entry symbol'),
                    (i in entry_ids, 12, 'stored entry address/export'),
                    (i in paths, 8, 'bounded path from stored entry or recognized startup bridge'),
                ):
                    if enabled:
                        score += points
                        reasons.append(f'{explanation} (+{points})')
                if i in boundaries:
                    score += 70
                    reasons.append('first non-runtime internal after bridge ' +
                                   facts[boundaries[i]]['current_name'] + ' (+70)')
                if i in app_distances:
                    points = 40 - 8 * app_distances[i]
                    score += points
                    reasons.append(f'application-path descendant at depth {app_distances[i]} (+{points})')
                for count, points, description in (
                    (len(effective_out[i]), 3, 'non-runtime internal callees (thunks transparent)'),
                    (len(app_in[i]), 2, 'non-runtime internal callers (thunks transparent)'),
                ):
                    if count:
                        contribution = min(count, 4) * points
                        score += contribution
                        reasons.append(f'{count} {description}; capped contribution (+{contribution})')
            else:
                reasons.append('demoted as behavioral evidence; connectivity cannot override classification')
            if i in forwarding:
                reasons.append(('stored Ghidra thunk binding to ' if i in bindings else 'stored single-instruction direct JMP to ') +
                               facts[forwarding[i]]['address'] + '; traversal reference only, not a CALL edge')
            items.append(FunctionRelevance(f, category, score, tuple(reasons), paths.get(i, ())))
        items.sort(key=lambda r: (-r.score, key(r.function)))
        return RelevanceSnapshot(items, edges, {'function_count': len(facts), 'call_edge_count': len(edges),
            'traversal_start_ids': starts, 'visited_nodes': len(visited), 'scanned_links': scanned,
            'max_depth': self.MAX_DEPTH, 'max_visits': self.MAX_VISITS, 'max_links': self.MAX_LINKS,
            'traversal_truncated': cut, 'application_visited_nodes': len(app_seen),
            'application_scanned_links': app_scanned,
            'scope': 'Resolved direct CALLs and explicit stored thunk JMP references only; no path is not proof of global unreachability'})
