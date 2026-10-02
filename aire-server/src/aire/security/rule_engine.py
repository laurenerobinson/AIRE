"""M7 deterministic, offline security rules over immutable stored-fact snapshots."""
from pathlib import Path
import json
import sqlite3
import time

from aire.knowledge.database import BinaryKnowledgeStore, KnowledgeStoreError, SCHEMA_VERSION
from aire.security.contracts import SecurityRule, RuleMetadata, RuleRegistry
from aire.security.facts import load_rule_facts
from aire.security.findings import (SecurityScanResult, RuleEvaluation, RuleFailure,
    EvaluationState, EvidenceStrength, SecurityEvidence, SecurityFinding, stable_id)


def default_registry():
    from aire.security.rules import UnboundedCopyRule, DangerousApiRule
    registry = RuleRegistry()
    registry.register(UnboundedCopyRule())
    registry.register(DangerousApiRule())
    return registry


def _validate(evaluation, facts, metadata):
    if not isinstance(evaluation, RuleEvaluation):
        raise ValueError('Rule must return RuleEvaluation')
    if (evaluation.binary_id, evaluation.rule_id, evaluation.rule_version) != (
            facts.binary_id, metadata.rule_id, metadata.version):
        raise ValueError('Evaluation binary/rule/version mismatch')
    evaluation.__post_init__()
    catalog = {e.evidence_id: e for e in facts.evidence}
    def evidence(items):
        for item in items:
            if not isinstance(item, SecurityEvidence) or catalog.get(item.evidence_id) != item:
                raise ValueError('Evidence is not an exact item from the supplied fact snapshot')
    evidence(evaluation.supporting_evidence)
    evidence(evaluation.contradicting_evidence)
    known = {f.function_id for f in facts.functions}
    ids = set()
    for finding in evaluation.findings:
        if not isinstance(finding, SecurityFinding):
            raise ValueError('Expected SecurityFinding')
        finding.__post_init__()
        if (finding.binary_id, finding.rule_id, finding.rule_version, finding.cwe_id) != (
                facts.binary_id, metadata.rule_id, metadata.version, metadata.cwe_id):
            raise ValueError('Finding binary/rule/version/CWE mismatch')
        if finding.primary_function_id not in known or not finding.supporting_evidence:
            raise ValueError('Finding requires a known primary function and supporting evidence')
        if not any(e.function_id == finding.primary_function_id and
                   finding.primary_address in (e.address, e.callsite) for e in finding.supporting_evidence):
            raise ValueError('Primary location must be represented by supporting evidence')
        if evaluation.status == EvaluationState.SIGNAL and finding.status != EvaluationState.SIGNAL:
            raise ValueError('SIGNAL evaluation cannot carry a stronger finding state')
        evidence(finding.supporting_evidence)
        evidence(finding.contradicting_evidence)
        if finding.finding_id in ids:
            raise ValueError('Duplicate finding ID')
        ids.add(finding.finding_id)
    if evaluation.status == EvaluationState.CANDIDATE and not any(
            f.status == EvaluationState.CANDIDATE for f in evaluation.findings):
        raise ValueError('CANDIDATE evaluation requires a CANDIDATE finding')


class RuleEngine:
    """Single fact snapshot, sorted rules, isolated failures; no persistence.

    Rules receive immutable facts, never the store or a model. Registered Python
    code is trusted application code, not a sandbox for untrusted plugins.
    """
    def __init__(self, store, registry=None):
        self.store = store
        self.registry = default_registry() if registry is None else registry
        if not isinstance(self.registry, RuleRegistry):
            raise TypeError('registry must be RuleRegistry')

    def scan_binary(self, binary_id, rule_ids=None) -> SecurityScanResult:
        selected = self.registry.select(rule_ids)
        started = time.perf_counter()
        facts = load_rule_facts(self.store, binary_id)
        timing = {'fact_load_seconds': time.perf_counter() - started, 'per_rule_seconds': {}}
        evaluations, findings, errors = [], [], []
        for rule in selected:
            tick = time.perf_counter()
            metadata = rule.metadata
            try:
                evaluation = rule.evaluate(facts)
                _validate(evaluation, facts, metadata)
            except Exception as exc:
                # Do not turn failures into NOT_APPLICABLE or insufficient evidence.
                errors.append(RuleFailure(metadata.rule_id, metadata.version, type(exc).__name__, str(exc)))
            else:
                evaluations.append(evaluation)
                findings.extend(evaluation.findings)
            finally:
                timing['per_rule_seconds'][metadata.rule_id] = time.perf_counter() - tick
        timing['total_scan_seconds'] = time.perf_counter() - started
        counts = {'selected': len(selected), 'evaluated': len(evaluations), 'failed': len(errors),
                  **{state.value: sum(e.status == state for e in evaluations) for state in EvaluationState}}
        warnings = ['Static stored-fact scope only; signals/candidates are not confirmed vulnerabilities or exploitability estimates.']
        if facts.warnings:
            warnings.append(f'The stored index contains {len(facts.warnings)} diagnostics; unresolved calls are not inferred.')
        if errors:
            warnings.append('One or more rules failed; the scan is incomplete. See errors.')
        return SecurityScanResult(binary_id, evaluations, findings, errors, counts, timing, warnings)


def _display(value):
    return ''.join(c if c.isprintable() else f'\\u{ord(c):04x}' for c in str(value))


def render_scan(result):
    lines = [f'A.I.R.E. security signals for {_display(result.binary_id)}',
             f'Rules evaluated: {result.rule_counts["evaluated"]}; failed: {result.rule_counts["failed"]}']
    for evaluation in result.evaluations:
        lines.extend(['', f'[{evaluation.rule_id} v{evaluation.rule_version}]',
                      f'Status: {evaluation.status.value}', _display(evaluation.message)])
        for finding in evaluation.findings:
            lines.extend([f'CWE: {finding.cwe_id}', f'Evidence strength: {finding.evidence_strength.value}',
                'Function: ' + _display(finding.primary_function_id), 'Location: ' + _display(finding.primary_address),
                _display(finding.message), 'Evidence:'])
            lines.extend('- ' + _display(e.description) + ' [' + e.evidence_id + ']' for e in finding.supporting_evidence)
            lines.append('Contradicting evidence:')
            lines.extend(['- ' + _display(e.description) for e in finding.contradicting_evidence] or ['- None recorded; this is not proof of absence.'])
            lines.append('Assumptions:')
            lines.extend('- ' + _display(a) for a in finding.assumptions)
            lines.append('Limitations:')
            lines.extend('- ' + _display(l) for l in finding.limitations)
        if not evaluation.findings:
            lines.extend('- ' + _display(e.description) for e in evaluation.supporting_evidence)
            lines.extend('Limit: ' + _display(l) for l in evaluation.limitations)
    for error in result.errors:
        lines.append(f'Rule error [{_display(error.rule_id)}]: {_display(error.error_type)}: {_display(error.message)}')
    lines.extend('Note: ' + _display(w) for w in result.warnings)
    return '\n'.join(lines)


class _ReadOnlyRuleStore(BinaryKnowledgeStore):
    """Existing-database CLI adapter; deliberately bypass M2 schema creation."""
    def __init__(self, path):
        self.path = Path(path).resolve()
        self._connection = None
        try:
            self._connection = sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True, isolation_level=None)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute('PRAGMA query_only=ON')
            version = self._connection.execute("SELECT value FROM schema_metadata WHERE key='schema_version'").fetchone()
            if version is None or version[0] != str(SCHEMA_VERSION):
                raise KnowledgeStoreError('Unsupported existing schema version')
        except (sqlite3.Error, KnowledgeStoreError) as exc:
            self.close()
            raise KnowledgeStoreError(f'Cannot open analysis read-only: {exc}') from exc


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='Read-only deterministic security signals; no model or execution')
    parser.add_argument('database', type=Path)
    parser.add_argument('binary_id')
    parser.add_argument('--rule', action='append', dest='rule_ids')
    parser.add_argument('--list-rules', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.list_rules:
            print(json.dumps([m.to_dict() for m in default_registry().list_rules()]))
            return 0
        with _ReadOnlyRuleStore(args.database) as store:
            result = RuleEngine(store).scan_binary(args.binary_id, args.rule_ids)
        print(json.dumps(result.to_dict(), ensure_ascii=True) if args.json else render_scan(result))
        return int(bool(result.errors))
    except (ValueError, KnowledgeStoreError) as exc:
        print(json.dumps({'error': type(exc).__name__, 'message': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
