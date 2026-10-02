"""Two API signals over exact stored imports/functions/CALLs, not code-text guesses."""
import json
from aire.security.contracts import SecurityRule, RuleMetadata
from aire.security.findings import (EvaluationState as State, EvidenceStrength, EvidenceType,
                                     SecurityFinding, RuleEvaluation, stable_id)

LIMITATIONS = (
    'Destination capacity and source length have not been proven.',
    'External input control, reachability and runtime API binding have not been established.',
    'No argument, taint, source/sink flow or surrounding bounds-check analysis is performed.',
    'This is a security signal requiring analyst review, not a confirmed vulnerability.',
)
REQUIRED = ('analysis_completed', 'imports_enabled', 'direct_calls_enabled',
            'exact_import_and_external_function', 'resolved_internal_CALL')


class _ImportedApiRule(SecurityRule):
    api: str
    api_note: str

    def evaluate(self, facts):
        meta = self.metadata
        coverage = tuple(e for e in facts.evidence if e.type == EvidenceType.ANALYSIS_METADATA)
        assumptions = ('Stored loader/import/function identities are treated as static observations, not runtime binding proof.',)
        def evaluation(status, message, evidence=(), findings=(), extra=()):
            return RuleEvaluation(facts.binary_id, meta.rule_id, meta.version, status, message,
                tuple(findings), tuple(evidence), (), assumptions,
                LIMITATIONS + ('Absence applies only to the stored analyzed facts; it is not a safety assessment.',) + tuple(extra))
        if not facts.coverage_ready:
            return evaluation(State.INSUFFICIENT_EVIDENCE,
                'Required analysis/import/direct-call extraction metadata is absent or disabled.', coverage)
        by_id = {f.function_id: f for f in facts.functions}
        pairs = []
        for f in facts.functions:
            if not f.is_external or f.current_name != self.api:
                continue
            for a in facts.imports:
                allowed = (self.api, f'{f.namespace}::{self.api}') if f.namespace else (self.api,)
                if a.address == f.address and a.value in allowed:
                    pairs.append((f, a))
        prerequisites = [facts.source('artifacts', a.artifact_id) for a in facts.imports
                         if a.value == self.api or a.value.endswith('::' + self.api)]
        prerequisites += [facts.source('functions', f.function_id) for f in facts.functions
                          if f.current_name == self.api and (f.is_external or f.is_thunk)]
        if not prerequisites:
            return evaluation(State.NOT_APPLICABLE, f'No exact {self.api} import/external/thunk prerequisite is stored.', coverage)
        findings = []
        for call in facts.calls:
            caller, callee = by_id[call.caller_function_id], by_id[call.callee_function_id]
            if caller.is_external or caller.is_thunk or callee.current_name != self.api:
                continue
            matches = [(f, a) for f, a in pairs if f.function_id == callee.function_id or
                       (callee.is_thunk and not callee.is_external and callee.namespace
                        and callee.namespace != 'Global' and callee.namespace == f.namespace)]
            if not matches:
                continue
            # Deterministic canonical external/import pair; no synthesized edge.
            external, artifact = sorted(matches, key=lambda pair: (pair[0].function_id, pair[1].artifact_id))[0]
            evidence = [facts.source('functions', caller.function_id),
                        facts.source('functions', callee.function_id),
                        facts.source('function_edges', call.source_id),
                        facts.source('artifacts', artifact.artifact_id)]
            local_limits = list(LIMITATIONS)
            local_assumptions = list(assumptions)
            if callee.is_external:
                strength = EvidenceStrength.MEDIUM
                message = f'Resolved CALL to external {self.api} at {call.callsite_address}. '
            else:
                evidence.append(facts.source('functions', external.function_id))
                strength = EvidenceStrength.LOW
                message = (f'Resolved CALL to import-named thunk {self.api} at {call.callsite_address}; '
                           'an exact matching external import is stored. ')
                local_limits.append('Thunk-to-external binding is not persisted; no such edge is inferred.')
                local_assumptions.append('API association uses exact thunk name/namespace plus a matched external import; analyst verification is required.')
            message += self.api_note + ' Additional source/destination and input-control analysis is required.'
            discriminator = json.dumps([self.api, callee.function_id], separators=(',', ':'))
            identity = stable_id('FINDING', facts.binary_id, meta.rule_id, meta.version,
                                 caller.function_id, call.callsite_address, discriminator)
            findings.append(SecurityFinding(identity, facts.binary_id, meta.rule_id, meta.version,
                meta.cwe_id, meta.title, State.SIGNAL, strength, caller.function_id,
                call.callsite_address, message, discriminator, evidence, [], local_assumptions, local_limits))
        if findings:
            return evaluation(State.SIGNAL, f'{len(findings)} resolved {self.api} call signal(s); analyst review required.',
                              prerequisites, findings)
        return evaluation(State.INSUFFICIENT_EVIDENCE,
            f'{self.api} prerequisite exists, but no qualifying internal resolved CALL with corroborated API identity is stored.',
            prerequisites, extra=('Import presence, unresolved calls, and ordinary same-named functions are not call evidence.',))


class UnboundedCopyRule(_ImportedApiRule):
    api = 'strcpy'
    api_note = 'The strcpy API does not enforce destination bounds.'
    metadata = RuleMetadata('AIRE-CWE-120-UNBOUNDED-COPY', '1.0.0',
        'Unbounded-copy API call signal',
        'Exact strcpy import and resolved call signal; no buffer overflow is established.',
        'CWE-120', 'Buffer Copy without Checking Size of Input', REQUIRED, ('static', 'api-call', 'copy'))


class DangerousApiRule(_ImportedApiRule):
    api = 'gets'
    api_note = 'The gets API has no destination-size argument.'
    metadata = RuleMetadata('AIRE-CWE-242-DANGEROUS-API', '1.0.0',
        'Inherently dangerous API call signal',
        'Exact gets import and resolved call signal; no exploitability determination.',
        'CWE-242', 'Use of Inherently Dangerous Function', REQUIRED, ('static', 'api-call', 'input'))
