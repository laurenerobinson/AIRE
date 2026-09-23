"""M5 single-question evidence -> local model -> validated advisory response."""
import json
from pathlib import Path
import time

from aire.ai.chat_models import ChatError, ChatRequest, ChatResponse
from aire.ai.context_builder import ContextBuilder
from aire.ai.evidence_selector import OverviewContextBuilder, OVERVIEW_POLICY, TARGET_POLICY
from aire.ai.ollama_client import OllamaClient, OllamaError
from aire.ai.prompt_builder import build_prompt, parse_response, RESPONSE_SCHEMA
from aire.knowledge.database import BinaryKnowledgeStore, KnowledgeStoreError


class AireChatService:
    def __init__(self, store, ollama_client):
        self.store = store
        self.ollama_client = ollama_client
        self.context_builder = ContextBuilder(store)
        self.overview_builder = OverviewContextBuilder(store)

    def ask(self, binary_id=None, question=None, target=None, *, request=None, debug=False, **options):
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
        bundle = builder.build(request.evidence_request())
        timings = {'context_build_seconds': time.perf_counter() - tick}
        tick = time.perf_counter()
        prompt = build_prompt(request.question, bundle, policy=policy)
        timings['prompt_build_seconds'] = time.perf_counter() - tick
        raw_responses, sizes = [], {'context_characters': prompt.context_characters,
                                    'm4_rendered_characters': len(bundle.render_text()),
                                    'prompt_characters': len(prompt.system) + len(prompt.text)}
        timings.update(inference_seconds=0.0, parsing_seconds=0.0)
        for attempt in range(2):
            message = prompt.text
            if attempt:
                # Do not echo adversarial/malformed model text into the next request.
                message += '\nFORMAT CORRECTION: Return only valid JSON matching RESPONSE FORMAT. Use only listed evidence IDs and allowed confidence values.'
            tick = time.perf_counter()
            result = self.ollama_client.generate(message, system=prompt.system, response_schema=RESPONSE_SCHEMA)
            timings['inference_seconds'] += time.perf_counter() - tick
            raw_responses.append(result.text)
            tick = time.perf_counter()
            try:
                summary, facts, interpretations, uncertainties = parse_response(result.text, prompt.citations)
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
