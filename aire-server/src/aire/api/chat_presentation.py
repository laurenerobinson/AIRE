"""Analyst presentation of validated results; audit records stay intact."""
from aire.ai.chat import _display


def security_summary(data):
    if data.get('findings'):
        return f"{len(data['findings'])} static security finding(s) warrant review; these are not confirmed vulnerabilities."
    evaluations = data.get('evaluations', [])
    if evaluations and all(e['status'] == 'NOT_APPLICABLE' for e in evaluations):
        return 'No currently supported dangerous-API patterns were detected.'
    return 'Security check coverage is incomplete or inconclusive; review the expanded checks.'


def present(result):
    response = result.response
    raw_answer = result.answer
    stored_answer = raw_answer.startswith('A.I.R.E. stored graph results')
    graph_query = stored_answer and any(r['tool'] in ('get_callers', 'get_callees', 'rank_functions') for r in result.tool_results)
    security_query = stored_answer and any(r['tool'] == 'security_findings' for r in result.tool_results)
    evidence, relationships, security = [], [], []
    lines = []
    if response:
        lines += ['### What this binary appears to do' if response.target is None else '### Function analysis',
                  '', _display(response.summary.claim)]
        if response.interpretations:
            lines += ['', '### How it works', '']
            lines += ['- ' + _display(c.claim) for c in response.interpretations]
        for identity, citation in response.citations.items():
            if citation.kind == 'CROSSCHECK':
                continue  # Derived observations are displayed separately below.
            evidence.append({'label': citation.fact, 'evidence_id': identity,
                             'provenance': vars(citation.provenance)})
        for edge in response.evidence_bundle.edges:
            relationships.append({'label': f'{edge.caller.current_name} → {edge.callee.current_name} @ {edge.edge.callsite_address}',
                                  'provenance': vars(edge.provenance)})
        reports = response.evidence_bundle.metadata.get('function_crosschecks', ())
        if reports:
            lines += ['', '### Decompiler / assembly cross-check', '']
            for report in reports:
                lines.append('- `' + _display(report['function']['current_name']) + '`: ' + report['cross_check_status'] +
                             ' (local operations): ' + ', '.join(report['likely_operation_families']))
                for agreement in report['agreements'][:2]:
                    if agreement.get('likely_pattern'):
                        lines.append('  Same locally tracked value multiplied by itself; decompiler agrees (likely squaring).')
                lines += ['- ' + _display(s) for s in report['disagreements'] + report['uncertainties'][:1]]
            lines += ['Local agreement is not full function equivalence; input origin is not established.']
        contradictions = [s for s in response.uncertainties if s.startswith('AI interpretation conflicts')]
        lines += ['', *contradictions] if contradictions else []
        if response.target is None:
            bundle = response.evidence_bundle
            priority = set(bundle.metadata.get('priority_function_ids', ()))
            connected = {e.callee.function_id for e in bundle.edges if e.caller.function_id in priority}
            functions = sorted([f.function for f in bundle.functions
                         if not f.function.is_external and not f.function.is_thunk],
                         key=lambda f: (f.function_id not in priority, f.function_id not in connected, f.address))[:6]
            if functions:
                lines += ['', '### Important functions', ''] + [
                    f'- `{_display(f.current_name)}` @ {f.address}' for f in functions]
    elif result.status in ('completed', 'partial') and raw_answer.startswith('A.I.R.E. stored graph results'):
        lines = ['### Static security review' if security_query else '### Call relationships', '']
    else:
        lines = [raw_answer.split('\n\nRetrieved tool facts')[0]]
    observations = []
    next_function = None
    for item in result.tool_results:
        if not item.get('ok'):
            continue
        name, data = item['tool'], item['data']
        if name in ('get_callers', 'get_callees'):
            for edge in data['items']:
                caller, callee = edge['caller']['function'], edge['callee']['function']
                label = f"{caller['current_name']} → {callee['current_name']} @ {edge['callsite_address']}"
                if label not in {r['label'] for r in relationships}:
                    relationships.append({'label': label, 'provenance': edge['provenance']})
                if name == 'get_callees' and not callee['is_external'] and not callee['is_thunk'] and not next_function:
                    next_function = callee['current_name']
            if not response and graph_query and not security_query:
                lines += ['- ' + r['label'] for r in relationships]
                if not data['items']:
                    lines.append('No matching stored CALL edges. Unresolved or runtime calls remain possible.')
        elif name == 'rank_functions' and data['items']:
            row = data['items'][0]
            observations.append(f"`{row['function']['current_name']}` ranks highest by {data['metric'].replace('_', ' ')} "
                                f"({row[data['metric']]}) in the stored CALL graph. Connectivity is a starting point for review.")
            if not response and graph_query and not security_query:
                lines += ['### Connectivity ranking', ''] + [
                    f"- {r['function']['current_name']} @ {r['function']['address']}: {r[data['metric']]}"
                    for r in data['items']]
        elif name == 'get_artifacts' and data['items'] and data['items'][0]['artifact']['type'] == 'IMPORT':
            observations.append('Stored imports include ' + ', '.join(
                '`' + _display(r['artifact']['value']) + '`' for r in data['items'][:8]) + '.')
        elif name == 'security_findings':
            security.append(data)
            observations.append(security_summary(data))
        if not response:
            for row in data.get('provenance', []) if isinstance(data.get('provenance'), list) else []:
                if isinstance(row, dict):
                    evidence.append({'label': f"{row['source_table']} @ {row.get('address') or 'binary scope'}",
                                     'evidence_id': row['source_id'], 'provenance': row})
    if observations:
        lines += ['', '### Interesting observations', ''] + ['- ' + s for s in observations]
    if next_function and response:
        lines += ['', '### Suggested next step', '', f'Inspect `{_display(next_function)}` in the stored call path.',
                  '', f'Want me to explain `{_display(next_function)}` next?']
    sources = len(response.citations) if response else (
        len({row['evidence_id'] for row in evidence}) or len(relationships))
    footer = f'Static analysis only · {sources} evidence sources · No target execution'
    if response and response.context_truncated:
        footer += ' · Some additional evidence was omitted'
    result.answer = '\n'.join(lines)
    result.presentation = {'footer': footer, 'interpretation': bool(response),
        'evidence': evidence, 'relationships': relationships, 'security': security,
        'raw': {'answer': raw_answer, 'response': response.to_dict() if response else None,
                'tool_results': result.tool_results}}
    return result
