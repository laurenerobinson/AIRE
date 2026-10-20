"""M5 single-question evidence -> local model -> validated advisory response."""
import json
from copy import deepcopy
from pathlib import Path
import time
import re

from aire.ai.chat_models import ChatError, ChatRequest, ChatResponse
from aire.ai.context_builder import ContextBuilder
from aire.ai.evidence_selector import OverviewContextBuilder, OVERVIEW_POLICY, TARGET_POLICY
from aire.ai.ollama_client import OllamaClient, OllamaError
from aire.ai.prompt_builder import build_prompt, parse_response, RESPONSE_SCHEMA
from aire.knowledge.database import BinaryKnowledgeStore, KnowledgeStoreError
from aire.ai.chat_models import Claim
from aire.analysis.assembly_semantics import REGISTER, parse_instructions


def validate_multiply_register_claims(claims, bundle, citations):
    """Reject absent registers in explicit multiply explanations for one cited x86 function.

    This is a narrow contradiction check, not operand/data-flow verification.
    One-operand IMUL has implicit registers and is deliberately excluded.
    """
    if not re.search(r'(?:x86|amd64|i[3-6]86)', bundle.binary.architecture or '', re.I):
        return
    by_id = {f.function.function_id: f.function for f in bundle.functions}
    for claim in claims:
        text = claim.claim.upper()
        mnemonic = re.search(r'\b(IMUL|MULSD|MULSS)\b', text)
        if (not mnemonic or not re.search(r'\b(?:REGISTERS?|OPERANDS?)\b', text)
                or re.search(r'\b(?:NOT|NO|NEVER|WITHOUT|UNUSED)\b', text)):
            continue
        ids = {citations[i].provenance.source_id for i in claim.evidence_ids
               if citations[i].kind in ('FUNC', 'CROSSCHECK')}
        if (len(ids) != 1 or not (function := by_id.get(next(iter(ids))))
                or not function.assembly or function.assembly_truncated):
            continue
        instructions, malformed, bounded = parse_instructions(function.assembly)
        if malformed or bounded:
            continue
        matching = [i for i in instructions if i['mnemonic'] == mnemonic[1]]
        if not matching or any(len(i['operands']) < 2 for i in matching):
            continue
        mentioned = {t for t in re.findall(r'\b[A-Z][A-Z0-9]*\b', text) if REGISTER.fullmatch(t)}
        observed = {t for i in instructions for operand in i['operands']
                    for t in re.findall(r'\b[A-Z][A-Z0-9]*\b', operand) if REGISTER.fullmatch(t)}
        if mentioned - observed:
            raise ChatError('Multiply explanation names registers absent from the cited assembly: ' +
                            ', '.join(sorted(mentioned - observed)), code='unsupported_grounding')


def check_operation_contradictions(summary, interpretations, bundle, citations):
    """Only reject positive sqrt assertions about a proven local multiply return.

    Calls, truncation, branches, unsupported code and ambiguous function scope
    disable this guard. Absence of SQRT alone is never enough.
    """
    strong = {}
    for report in bundle.metadata.get('function_crosschecks', ()):
        c = report['control_flow_summary']
        coverage = report['coverage']
        candidates = report['data_flow_summary']['return_register_candidates']
        if (report['cross_check_status'] == 'AGREEMENT' and report['sqrt_instruction_present'] is False and
                not c['call_count'] and not c['conditional_branch_count'] and not c['unconditional_branch_count'] and
                c['return_count'] == 1 and not coverage['assembly']['unsupported_mnemonics'] and
                any(r['operation_family'].endswith('multiplication') and r.get('likely_pattern') == 'value_squared' for r in candidates)):
            strong[report['function']['function_id']] = report
    warnings = []
    def conflict(claim):
        text = claim.claim
        if re.search(r'\b(?:not|never|no)\b[^.!?\n]{0,60}\bsquare\s+root\b', text, re.I):
            return False
        if not re.search(r'\b(?:computes?|calculates?|returns?|performs?)\s+(?:(?:a|the|an)\s+)?(?:scalar\s+)?(?:double(?:-precision)?\s+)?square\s+root\b', text, re.I):
            return False
        referenced = {citations[i].provenance.source_id for i in claim.evidence_ids
                      if citations[i].kind in ('FUNC', 'CROSSCHECK')}
        applicable = referenced & set(strong)
        # A claim citing another function or multiple functions is ambiguous.
        if len(applicable) != 1 or len(referenced) != 1:
            return False
        report = strong[next(iter(applicable))]
        subject = r'(?:this function|the function|`?' + re.escape(report['function']['current_name']) + r'`?)'
        return bool(re.search(r'(?:^|[.!?]\s*)' + subject + r'\s+(?:computes?|calculates?|returns?|performs?)\b', text, re.I))
    if conflict(summary):
        warnings.append('AI interpretation conflicts with deterministic assembly evidence: square-root summary was replaced by the supported local multiplication observation.')
        summary = Claim('Stored assembly and decompilation locally agree on same-value multiplication (likely squaring); this does not establish full function equivalence.', summary.evidence_ids)
    retained = []
    for claim in interpretations:
        if conflict(claim):
            warnings.append('AI interpretation conflicts with deterministic assembly evidence: a square-root interpretation was omitted; the supported returned computation is multiplication.')
        else:
            retained.append(claim)
    return summary, retained, warnings


class SummaryPreview:
    """Decode only the public summary string from partial structured output.

    Preview is explicitly provisional; strict response/citation parsing still
    gates the final answer. Other fields, including reasoning, never stream.
    """
    def __init__(self, emit):
        self.emit, self.raw, self.last = emit, '', ''

    def __call__(self, chunk):
        self.raw += chunk
        match = re.search(r'"summary"\s*:\s*\{\s*"claim"\s*:\s*"', self.raw)
        if not match:
            return
        tail = self.raw[match.end():]
        end, escaped = len(tail), False
        for i, ch in enumerate(tail):
            if not escaped and ch == '"':
                end = i
                break
            escaped = not escaped if ch == '\\' else False
        for trim in range(min(12, end + 1)):
            try:
                value = json.loads('"' + tail[:end - trim] + '"')
            except ValueError:
                continue
            if value != self.last:
                self.last = value
                self.emit(value)
            break


def validate_compact_claims(claims, bundle):
    """Reject a few explicit contradictions observed in small-model output.

    This is not general semantic verification. It checks explicit named calls
    and absence/linkage assertions unsupported by the bounded evidence contract.
    """
    names = {f.function.current_name for f in bundle.functions}
    names.update(e.caller.current_name for e in bundle.edges)
    names.update(e.callee.current_name for e in bundle.edges)
    pairs = {(e.caller.current_name, e.callee.current_name) for e in bundle.edges}
    for claim in claims:
        text = claim.claim
        if re.search(r'\b(?:statically linked|dynamically linked|no external dependencies|no other operations|does not perform any other)\b', text, re.I):
            raise ChatError('Bounded evidence cannot establish linkage or exclusive behavior', code='unsupported_grounding')
        if re.search(r'`?main`?[^.\n]{0,70}\bentry\s*point\b[^.\n]{0,40}\bbinary\b', text, re.I):
            main = next((f.function for f in bundle.functions if f.function.current_name == 'main'), None)
            if main is None or main.address != bundle.binary.entry_point:
                raise ChatError('The stored entry point does not establish main as binary entry', code='unsupported_grounding')
        for caller in names:
            pattern = r'(?<!\w)`?' + re.escape(caller) + r'`?(?:\s+function)?[^.!?\n]{0,140}?\b(?:calls|invokes)\s+(?:the\s+)?(?:function\s+)?`?([A-Za-z_][A-Za-z0-9_:]*)'
            for match in re.finditer(pattern, text):
                callee = match[1]
                if callee in names and (caller, callee) not in pairs:
                    raise ChatError('Named call claim does not match supplied stored CALL edges', code='unsupported_grounding')


class AireChatService:
    def __init__(self, store, ollama_client):
        self.store = store
        self.ollama_client = ollama_client
        self.context_builder = ContextBuilder(store)
        self.overview_builder = OverviewContextBuilder(store)

    def ask(self, binary_id=None, question=None, target=None, *, request=None, debug=False,
            evidence_bundle=None, require_behavior_grounding=False, compact=False, on_text=None, **options):
        """Explicit target selects exact M4 evidence; no target means overview.

        No implicit question parsing or model retrieval. ChatError carries a code
        for response failures; exact resolution errors retain M3 error types.
        Debug raw output is opt-in and is never logged automatically.
        """
        if request is not None:
            if binary_id is not None or question is not None or target is not None or options:
                raise ValueError('Pass either request= or individual request fields')
            if not isinstance(request, ChatRequest):
                raise TypeError('request must be ChatRequest')
        else:
            request = ChatRequest(binary_id, question, target, **options)
        started = time.perf_counter()
        tick = time.perf_counter()
        builder = self.context_builder if request.target is not None else self.overview_builder
        policy = TARGET_POLICY if request.target is not None else OVERVIEW_POLICY
        if evidence_bundle is None:
            bundle = builder.build(request.evidence_request())
        else:
            from aire.knowledge.evidence import EvidenceBundle
            if not isinstance(evidence_bundle, EvidenceBundle):
                raise ValueError('evidence_bundle must be EvidenceBundle')
            if (evidence_bundle.binary.binary_id != request.binary_id or
                    evidence_bundle.request_summary.get('target') != request.target):
                raise ValueError('Evidence bundle binary/target does not match request')
            if any(p.binary_id != request.binary_id for p in evidence_bundle.provenance):
                raise ValueError('Evidence provenance belongs to a different binary')
            bundle = evidence_bundle
            policy = bundle.metadata.get('selection_policy', policy)
        timings = {'context_build_seconds': time.perf_counter() - tick}
        tick = time.perf_counter()
        prompt = build_prompt(request.question, bundle, policy=policy, compact=compact) if compact else build_prompt(request.question, bundle, policy=policy)
        code_ids = (prompt.code_source_ids if compact else
                    {f.function.function_id for f in bundle.functions
                     if f.function.decompiled_text or f.function.assembly})
        crosscheck_ids = {r['function']['function_id'] for r in bundle.metadata.get('function_crosschecks', ())
                          if r['likely_operation_families']}
        behavior_ids = [identity for identity, citation in prompt.citations.items()
                        if citation.kind == 'EDGE' or
                        (citation.kind == 'CROSSCHECK' and citation.provenance.source_id in crosscheck_ids) or
                        (citation.kind == 'FUNC' and citation.provenance.source_id in code_ids)]
        if require_behavior_grounding and not behavior_ids:
            raise ChatError('Behavior explanation needs visible code or call evidence',
                            code='insufficient_evidence')
        response_schema = RESPONSE_SCHEMA
        if evidence_bundle is not None:
            # Agent synthesis can constrain the provider grammar to the exact
            # retrieved catalog. Parsing remains the authority, including for
            # providers that ignore schema constraints.
            response_schema = deepcopy(RESPONSE_SCHEMA)
            properties = response_schema['properties']
            citation_ids = list(prompt.citations)
            for ids_schema in (properties['fact_ids'],
                    properties['summary']['properties']['evidence_ids'],
                    properties['interpretations']['items']['properties']['evidence_ids']):
                ids_schema['items']['enum'] = citation_ids
                ids_schema['uniqueItems'] = True
                # A single exact reference per claim avoids duplicate-ID
                # generation in small local models. Multiple interpretations
                # can still cite different catalog entries.
                ids_schema['maxItems'] = 1
            properties['fact_ids']['items']['enum'] = [i for i, c in prompt.citations.items() if c.kind != 'CROSSCHECK']
            if require_behavior_grounding:
                for ids_schema in (properties['summary']['properties']['evidence_ids'],
                        properties['interpretations']['items']['properties']['evidence_ids']):
                    ids_schema['items']['enum'] = behavior_ids
            properties['summary']['properties']['evidence_ids']['minItems'] = 1
            properties['interpretations']['items']['properties']['evidence_ids']['minItems'] = 1
            properties['interpretations']['maxItems'] = 3
            properties['uncertainties']['maxItems'] = 3
            if compact:
                properties['fact_ids']['maxItems'] = 3
                properties['summary']['properties']['evidence_ids']['maxItems'] = 3
                properties['interpretations']['maxItems'] = 2
                # Bound prose generation as well as evidence; keep the existing deadline.
                properties['summary']['properties']['claim']['maxLength'] = 400
                properties['interpretations']['items']['properties']['claim']['maxLength'] = 300
                properties['uncertainties']['items']['maxLength'] = 160
                if request.target:
                    properties['summary']['properties']['evidence_ids']['maxItems'] = 1
                    properties['interpretations']['maxItems'] = 1
                    properties['uncertainties']['maxItems'] = 1
        timings['prompt_build_seconds'] = time.perf_counter() - tick
        raw_responses, sizes = [], {'context_characters': prompt.context_characters,
                                    'm4_rendered_characters': len(bundle.render_text()),
                                    'prompt_characters': len(prompt.system) + len(prompt.text)}
        timings.update(inference_seconds=0.0, parsing_seconds=0.0)
        for attempt in range(2):
            message = prompt.text
            if require_behavior_grounding:
                message += ('\nCite code-bearing FUNC or EDGE for behavioral claims.' if compact else
                            '\nBEHAVIOR GROUNDING: Cite code-bearing FUNC or stored CALL EDGE IDs for '
                            'summary and interpretations. Name concrete stored functions and relationships; '
                            'use metadata and artifacts only for stored facts. Eligible IDs: ' +
                            json.dumps(behavior_ids) + '.')
            if attempt:
                # Do not echo adversarial/malformed model text into the next request.
                message += '\nFORMAT CORRECTION: Return only valid JSON matching RESPONSE FORMAT. Use only listed evidence IDs and allowed confidence values.'
            tick = time.perf_counter()
            generation_options = {}
            if on_text and getattr(self.ollama_client, 'supports_streaming', False):
                if attempt:
                    on_text('')
                generation_options['on_chunk'] = SummaryPreview(on_text)
            result = self.ollama_client.generate(message, system=prompt.system, response_schema=response_schema,
                                                 **generation_options)
            for key, value in result.timing.items():
                if value is not None:
                    if key == 'first_output_seconds':
                        timings.setdefault(key, value)
                    else:
                        timings[key] = timings.get(key, 0.0) + value
            timings['inference_seconds'] += time.perf_counter() - tick
            raw_responses.append(result.text)
            tick = time.perf_counter()
            try:
                summary, facts, interpretations, uncertainties = parse_response(result.text, prompt.citations)
                summary, interpretations, semantic_warnings = check_operation_contradictions(summary, interpretations, bundle, prompt.citations)
                uncertainties.extend(semantic_warnings)
                validate_multiply_register_claims([summary], bundle, prompt.citations)
                if compact:
                    validate_compact_claims([summary], bundle)
                retained = []
                for interpretation in interpretations:
                    try:
                        validate_multiply_register_claims([interpretation], bundle, prompt.citations)
                        if compact:
                            validate_compact_claims([interpretation], bundle)
                    except ChatError as exc:
                        uncertainties.append('An unsupported interpretation was omitted: ' + str(exc))
                    else:
                        retained.append(interpretation)
                interpretations = retained
                if require_behavior_grounding and any(not set(claim.evidence_ids) & set(behavior_ids)
                        for claim in [summary] + interpretations):
                    raise ChatError('Behavior explanation lacks code or call-relationship references',
                                    code='unsupported_grounding')
            except ChatError as exc:
                if attempt:
                    raise ChatError('Invalid structured model response after two attempts: ' + str(exc),
                                    code=exc.code, raw_responses=raw_responses if debug else ()) from exc
            else:
                break
            finally:
                timings['parsing_seconds'] += time.perf_counter() - tick
        # Deterministic caveats cannot be removed by model text or omitted output.
        uncertainties.append('Static evidence only; no target execution or vulnerability confirmation occurred.')
        uncertainties.append('Citation existence is validated; model prose is interpretation, not semantically verified fact.')
        uncertainties.append('Character bounds are not token counts; model context retention is not independently verified.')
        if prompt.truncations:
            uncertainties.append('Context was bounded; additional functions, artifacts, diagnostics, or text were omitted.')
        if not request.include_decompiled_text or not request.include_assembly:
            uncertainties.append('One or more code evidence types were disabled by the request.')
        timings['total_chat_seconds'] = time.perf_counter() - started
        sizes.update(response_characters=len(result.text),
                     total_response_characters=sum(map(len, raw_responses)),
                     last_prompt_characters=len(prompt.system) + len(message),
                     prompt_eval_count=result.prompt_eval_count, eval_count=result.eval_count)
        return ChatResponse(request.question, request.binary_id, request.target, summary, facts,
            interpretations, uncertainties, prompt.citations, prompt.truncations, result.model,
            timings, sizes, bundle, attempt + 1, result.text if debug else None, policy)


def _display(value):
    """Escape terminal control characters in untrusted binary/model text."""
    return ''.join(ch if ch.isprintable() else f'\\u{ord(ch):04x}' for ch in str(value))


def render_response(response):
    lines = ['A.I.R.E. Analysis', '', 'Summary (model interpretation)',
             _display(response.summary.claim), 'Evidence: ' + ' '.join(response.summary.evidence_ids),
             '', 'Verified stored facts']
    for fact in response.facts:
        lines.append('- ' + _display(fact.claim) + ' [' + '] ['.join(fact.evidence_ids) + ']')
    if not response.facts:
        lines.append('- No facts selected by the model.')
    lines.extend(['', 'Model interpretation'])
    for claim in response.interpretations:
        lines.append('- ' + _display(claim.claim) + f' Confidence: {claim.confidence}. [' +
                     '] ['.join(claim.evidence_ids) + ']')
    lines.extend(['', 'Uncertainty'])
    lines.extend('- ' + _display(value) for value in response.uncertainties)
    if response.context_truncated:
        lines.extend(['', 'Context note: Context was bounded; additional evidence was omitted.'])
    referenced = set(response.summary.evidence_ids)
    for claim in response.facts + response.interpretations:
        referenced.update(claim.evidence_ids)
    lines.extend(['', 'Evidence provenance'])
    for identity in sorted(referenced):
        citation = response.citations[identity]
        source = citation.provenance
        lines.append(f'- {identity}: {_display(source.source_table)} at {_display(source.address)}; '
                     f'source={_display(source.source_id)}')
    lines.extend(['', 'Model: ' + _display(response.model)])
    for report in response.evidence_bundle.metadata.get('function_crosschecks', ()):
        lines.extend(['', 'Deterministic local assembly / decompiler cross-check',
            _display(report['function']['current_name']) + ': ' + report['cross_check_status'],
            'Instruction semantics: ' + ', '.join(report['likely_operation_families'])])
        lines.extend('- ' + _display(str(row)) for row in report['agreements'])
        lines.extend('- ' + _display(s) for s in report['disagreements'] + report['uncertainties'])
    return '\n'.join(lines)


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Read-only local chat over an existing A.I.R.E. database')
    parser.add_argument('database', type=Path)
    parser.add_argument('binary_id')
    parser.add_argument('question')
    parser.add_argument('--target')
    parser.add_argument('--model')
    parser.add_argument('--host')
    parser.add_argument('--allow-remote-host', action='store_true')
    parser.add_argument('--depth', type=int, default=1)
    parser.add_argument('--no-assembly', action='store_true')
    parser.add_argument('--no-decompile', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        if not args.database.is_file():
            raise ValueError('Database must already exist; index and persist the binary first')
        client = OllamaClient(host=args.host, model=args.model, allow_remote_host=args.allow_remote_host)
        with BinaryKnowledgeStore(args.database) as store:
            response = AireChatService(store, client).ask(args.binary_id, args.question, args.target,
                max_depth=args.depth, include_assembly=not args.no_assembly,
                include_decompiled_text=not args.no_decompile)
        print(json.dumps(response.to_dict(), ensure_ascii=True) if args.json else render_response(response))
        return 0
    except (ValueError, ChatError, OllamaError, KnowledgeStoreError) as exc:
        print(json.dumps({'error': getattr(exc, 'code', type(exc).__name__), 'message': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
