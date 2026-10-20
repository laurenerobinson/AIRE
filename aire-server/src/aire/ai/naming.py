"""M6 bounded, read-only naming suggestions. There is deliberately no apply API."""
import json
from pathlib import Path
import sqlite3
import time

from aire.ai.chat import AireChatService, _display
from aire.ai.chat_models import ChatError
from aire.ai.naming_models import NamingOptions, NamingResult, NameSuggestion
from aire.ai.naming_prompt import (GENERIC_NAMES, GENERATED_NAME, build_naming_prompt,
                                   parse_naming_response, response_schema)
from aire.ai.ollama_client import OllamaClient, OllamaError
from aire.knowledge.database import BinaryKnowledgeStore, KnowledgeStoreError, READABLE_SCHEMA_VERSIONS
from aire.knowledge.models import FunctionRecord
from aire.knowledge.evidence import EvidenceRequest
from aire.knowledge.retrieval import ProgramQueryService, _address_key

# Small conservative policy, not a claim to identify all runtime/library code.
RUNTIME_NAMES = frozenset({'_start', 'entry', '_init', '_fini', 'frame_dummy',
    'register_tm_clones', 'deregister_tm_clones', '__do_global_dtors_aux',
    '_dl_relocate_static_pie', '__libc_start_main', '__libc_csu_init', '__libc_csu_fini',
    '__gmon_start__', '__stack_chk_fail', 'printf', 'puts', 'strlen', 'socket',
    'memset', 'memcpy', 'malloc', 'free'})


def is_generic_name(name):
    return not name.strip() or name.lower() in GENERIC_NAMES or bool(GENERATED_NAME.fullmatch(name))


def _options(value):
    if value is None:
        return NamingOptions()
    if not isinstance(value, NamingOptions):
        raise TypeError('options must be NamingOptions')
    return value


class NamingService:
    """Reuse an M5 service's evidence builder and configured transport, not chat prose.

    The dedicated naming response uses the same one-correction retry policy.
    Caller owns the store. No schema change, executable access or Ghidra import.
    """
    def __init__(self, store, chat_service):
        if chat_service.store is not store:
            raise ValueError('Naming and chat services must use the same store')
        self.store = store
        self.chat_service = chat_service
        self.query = ProgramQueryService(store)

    @staticmethod
    def _skip(function, options, imports):
        name = function.current_name
        if options.skip_external and (function.is_external or name in imports):
            return 'external/import function'
        if options.skip_thunks and (function.is_thunk or name.lower().startswith('thunk_')):
            return 'thunk function'
        if options.skip_library and (function.is_library or name in RUNTIME_NAMES):
            return 'known library/runtime symbol'
        if options.skip_meaningful_names and not is_generic_name(name):
            return 'existing non-generic name'
        return None

    @staticmethod
    def _imports(db, binary_id):
        return {r[0] for r in db.execute('SELECT value FROM artifacts WHERE binary_id=? AND type=?',
                                       (binary_id, 'IMPORT'))}

    def find_naming_candidates(self, binary_id: str, options: NamingOptions | None = None) -> list[FunctionRecord]:
        """High-connectivity candidates: unique callers, outgoing callsites, address/ID.

        Only lightweight metadata/edge rows are scanned for ranking; bodies are
        loaded for at most max_candidates records. Counts use distinct CALL facts.
        """
        options = _options(options)
        with self.query._snapshot(binary_id) as db:
            imports = self._imports(db, binary_id)
            rows = db.execute('''SELECT f.function_id, f.current_name, f.address,
                f.is_external, f.is_thunk, f.is_library,
                (SELECT count(DISTINCT caller_function_id) FROM function_edges e
                 WHERE e.binary_id=f.binary_id AND e.callee_function_id=f.function_id
                 AND e.edge_type='CALL') AS incoming,
                (SELECT count(*) FROM (SELECT DISTINCT callee_function_id, callsite_address
                 FROM function_edges e WHERE e.binary_id=f.binary_id
                 AND e.caller_function_id=f.function_id AND e.edge_type='CALL')) AS outgoing
                FROM functions f WHERE f.binary_id=?''', (binary_id,)).fetchall()
            # Avoid loading code bodies for excluded functions.
            from types import SimpleNamespace
            rows = [r for r in rows if not self._skip(SimpleNamespace(**dict(r)), options, imports)]
            rows.sort(key=lambda r: (-r['incoming'], -r['outgoing'], _address_key(r['address']), r['function_id']))
            return [self.query._resolve(db, binary_id, r['function_id'], 'id')
                    for r in rows[:options.max_candidates]]

    def suggest_names(self, binary_id: str, function: str | FunctionRecord,
                      options: NamingOptions | None = None) -> NamingResult:
        options = _options(options)
        started = time.perf_counter()
        with self.query._snapshot(binary_id) as db:
            target = self.query._resolve(db, binary_id, function)
            skip = self._skip(target, options, self._imports(db, binary_id))
        result = NamingResult(binary_id, target.function_id, target.current_name, target.address)
        result.warnings = ['Advisory naming interpretations only; current name remains unchanged. No rename has been applied.',
            'Citation existence does not establish semantic correctness; confidence is not calibrated.',
            'Static evidence only. Character limits do not guarantee model token retention.']
        if skip:
            result.status = 'skipped'
            result.warnings.append('Excluded by naming policy: ' + skip)
            result.timing['total_seconds'] = time.perf_counter() - started
            return result
        tick = time.perf_counter()
        bundle = self.chat_service.context_builder.build(EvidenceRequest(binary_id, target.function_id,
            target_by='id', max_depth=options.max_depth,
            traversal_direction='forward' if options.max_depth > 1 else None,
            max_functions=4, max_edges=8, max_artifacts=0,
            include_strings=False, include_imports=False, include_exports=False,
            include_decompiled_text=options.include_decompiled_text, include_assembly=options.include_assembly,
            max_decompiled_chars_per_function=1200, max_assembly_chars_per_function=400,
            max_total_chars=options.max_context_chars))
        result.timing['context_build_seconds'] = time.perf_counter() - tick
        tick = time.perf_counter()
        prompt = build_naming_prompt(bundle, options)
        result.timing['prompt_build_seconds'] = time.perf_counter() - tick
        result.citations = prompt.citations
        result.context_truncations = prompt.truncations
        result.context_truncated = bool(prompt.truncations)
        result.evidence_summary = {'target_id': target.function_id,
            'functions': len(bundle.functions), 'relationships': len(bundle.edges),
            'admitted_evidence_ids': list(prompt.citations),
            'stored_facts': {i: c.fact for i, c in prompt.citations.items()},
            'artifact_policy': 'No unassociated strings/import artifacts; imports only through proven graph endpoints.'}
        result.sizes = {'context_characters': prompt.context_characters,
                        'prompt_characters': len(prompt.system) + len(prompt.text),
                        'response_characters': 0, 'total_response_characters': 0}
        result.timing.update(inference_seconds=0.0, parsing_seconds=0.0)
        for attempt in range(2):
            message = prompt.text
            if attempt:
                message += '\nFORMAT CORRECTION: Return only the required JSON. Use valid descriptive snake_case names, allowed confidence values and supplied target evidence IDs; abstain rather than invent.'
            tick = time.perf_counter()
            generated = self.chat_service.ollama_client.generate(message, system=prompt.system,
                response_schema=response_schema(options.max_suggestions_per_function))
            result.timing['inference_seconds'] += time.perf_counter() - tick
            result.attempts = attempt + 1
            result.model = generated.model
            result.sizes.update(response_characters=len(generated.text),
                total_response_characters=result.sizes['total_response_characters'] + len(generated.text),
                last_prompt_characters=len(prompt.system) + len(message),
                prompt_eval_count=generated.prompt_eval_count, eval_count=generated.eval_count)
            tick = time.perf_counter()
            try:
                result.suggestions, notes = parse_naming_response(generated.text, prompt.citations, options, target)
            except ChatError as exc:
                if attempt:
                    raise ChatError('Invalid naming response after two attempts: ' + str(exc), code=exc.code) from exc
            else:
                result.warnings.extend(notes)
                break
            finally:
                result.timing['parsing_seconds'] += time.perf_counter() - tick
        if result.context_truncated:
            result.warnings.append('Context was bounded; additional code/functions/relationships were omitted.')
        if not options.include_assembly or not options.include_decompiled_text:
            result.warnings.append('A code evidence type was explicitly disabled by the request.')
        for suggestion in result.suggestions:
            if self.query.find_functions(binary_id, suggestion.suggested_name, by='name'):
                result.warnings.append(f'Suggested name already exists in this binary: {suggestion.suggested_name}')
        result.status = 'ok' if result.suggestions else 'abstained'
        result.timing['total_seconds'] = time.perf_counter() - started
        return result

    def suggest_for_binary(self, binary_id: str, options: NamingOptions | None = None) -> list[NamingResult]:
        """Serial bounded calls. Invalid responses isolate; provider failure stops batch.

        Completed results plus the failing function are returned. No background
        work, automatic resumption or inference on remaining candidates occurs.
        """
        options = _options(options)
        results = []
        for function in self.find_naming_candidates(binary_id, options):
            tick = time.perf_counter()
            try:
                results.append(self.suggest_names(binary_id, function, options))
            except (ChatError, OllamaError, KnowledgeStoreError) as exc:
                failed = NamingResult(binary_id, function.function_id, function.current_name, function.address,
                    status='error', error={'code': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)},
                    timing={'total_seconds': time.perf_counter() - tick},
                    warnings=['Naming failed; no rename has been applied.'])
                results.append(failed)
                if isinstance(exc, OllamaError):
                    failed.warnings.append('Batch stopped after provider failure; remaining candidates were not attempted.')
                    break
        return results


def render_naming_result(result):
    lines = [f'Function: {_display(result.current_name)} @ {_display(result.function_address)}',
             'Suggestions (model interpretations):']
    for i, s in enumerate(result.suggestions, 1):
        lines.extend([f'{i}. {_display(s.suggested_name)}', f'   Confidence: {s.confidence}',
                      '   Evidence: ' + ' '.join(s.evidence_ids), '   Rationale: ' + _display(s.rationale)])
    if not result.suggestions:
        lines.append('None (' + result.status + ').')
    if result.error:
        lines.append('Error: ' + _display(result.error['message']))
    if result.context_truncated:
        lines.append('Context truncated: additional evidence was omitted.')
    lines.extend('Note: ' + _display(w) for w in result.warnings)
    lines.append('Current name remains unchanged. No rename has been applied.')
    return '\n'.join(lines)


class _ReadOnlyNamingStore(BinaryKnowledgeStore):
    """CLI adapter: reuse M2 read APIs without initialization or a writable handle."""
    def __init__(self, path):
        self.path = Path(path).resolve()
        self._connection = None
        try:
            self._connection = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True,
                                               isolation_level=None)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute('PRAGMA query_only=ON')
            version = self._connection.execute(
                "SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()
            if version is None or version[0] not in READABLE_SCHEMA_VERSIONS:
                raise KnowledgeStoreError('Existing A.I.R.E. schema version is unsupported')
        except (sqlite3.Error, KnowledgeStoreError) as exc:
            self.close()
            raise KnowledgeStoreError(f'Cannot open existing analysis read-only: {exc}') from exc


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Advisory local function naming over existing analysis; no write-back')
    parser.add_argument('database', type=Path)
    parser.add_argument('binary_id')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--function')
    mode.add_argument('--candidates', action='store_true')
    mode.add_argument('--batch', action='store_true')
    parser.add_argument('--limit', type=int, default=5)
    parser.add_argument('--model')
    parser.add_argument('--context-chars', type=int, default=5000)
    parser.add_argument('--no-assembly', action='store_true')
    parser.add_argument('--include-meaningful', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        if not args.database.is_file():
            raise ValueError('Database must already exist; index and persist separately')
        options = NamingOptions(max_candidates=args.limit, max_context_chars=args.context_chars,
            include_assembly=not args.no_assembly, skip_meaningful_names=not args.include_meaningful)
        with _ReadOnlyNamingStore(args.database) as store:
            service = NamingService(store, AireChatService(store, OllamaClient(model=args.model)))
            if args.candidates:
                candidates = service.find_naming_candidates(args.binary_id, options)
                print(json.dumps([{'function_id': f.function_id, 'current_name': f.current_name,
                                   'address': f.address} for f in candidates], ensure_ascii=True))
                return 0
            results = (service.suggest_for_binary(args.binary_id, options) if args.batch else
                       [service.suggest_names(args.binary_id, args.function, options)])
        print(json.dumps([r.to_dict() for r in results], ensure_ascii=True) if args.json else
              '\n\n'.join(render_naming_result(r) for r in results))
        return int(any(r.error for r in results))
    except (ValueError, ChatError, OllamaError, KnowledgeStoreError) as exc:
        print(json.dumps({'error': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
