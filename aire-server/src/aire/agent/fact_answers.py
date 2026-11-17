"""Deterministic answers to factual crypto / API / call-graph questions (no model).

Supported questions are answered entirely from stored, validated facts through
the read-only AgentTools registry: ``crypto_evidence`` (exact crypto API call
sites, operation categories from a fixed API table, identifier strings,
callers), ``get_callers`` / ``get_callees`` (stored CALL edges) and the M10
deterministic function evidence. Operation roles come from the API that is
called, never from function names or model text, so an encryption function
cannot be reported as decryption or vice versa.

Routing is deliberately conservative. A question is claimed only when its
wording is factual (which / what / where / find / list / show / does ...) and
names a supported subject. Evaluative or explanatory questions (why, how,
explain, secure, vulnerable, ...) return ``None`` so the existing M10 and model
paths handle them unchanged. Ambiguous targets are reported, not guessed.
"""
from dataclasses import dataclass, field
import re

from aire.agent.runner import render_tool_facts
from aire.ai.chat import _display
from aire.analysis.file_structure import LEVEL_TEXT
from aire.security.crypto_evidence import LIMITATIONS, classify_api

LABELS = {
    'encryption': 'Encryption', 'decryption': 'Decryption',
    'encryption_or_decryption': 'Encryption or decryption (direction is chosen at run time; not established statically)',
    'hashing': 'Hashing', 'signing': 'Signature creation', 'verification': 'Signature verification',
    'key_handling': 'Key handling', 'key_derivation': 'Key derivation', 'key_agreement': 'Key agreement',
    'random': 'Random generation', 'provider': 'Provider setup', 'configuration': 'Configuration',
    'cleanup': 'Cleanup', 'other': 'Other crypto API',
}
STRUCTURE_LABEL = {'full': 'Valid', 'partial': 'Damaged (partial analysis)', 'none': 'Invalid (no reliable analysis)',
                   'unverified': 'Unverified'}
DISPLAY_ORDER = ('encryption', 'decryption', 'encryption_or_decryption', 'hashing', 'signing', 'verification',
                 'key_handling', 'key_derivation', 'key_agreement', 'random')

_OPERATIONS = (
    ('encryption', r'\bencrypt\w*|\bencipher\w*'),
    ('decryption', r'\bdecrypt\w*|\bdecipher\w*'),
    ('hashing', r'\bhash(?:es|ed|ing)?\b|\bdigests?\b|\bsha-?\s?(?:1|224|256|384|512)\b|\bmd5\b'),
    ('key_handling', r'\b(?:crypto\w*|encryption|decryption|signing|verification|symmetric|asymmetric|aes|rsa|ecdsa|'
                     r'ecc|private|public|session) keys?\b|\bkey ?pairs?\b|\bkey generation\b'),
    ('key_derivation', r'\bderiv\w* (?:a |the )?keys?\b|\bkey derivation\b|\bpbkdf2?\b'),
)
# Signatures. In a reverse-engineering tool a bare "signature" is usually a C
# prototype and "signed"/"sign-extend"/"sign flag" are integer semantics, so bare
# sign/verify verbs count only inside signature context: an explicit digital or
# algorithm signature, a signing/verification verb aimed at a signature, or the
# sign/verify pair itself ("sign and verify", "signing and verification").
_SIGNATURE = re.compile(r'\b(?:digital|ecdsa|rsa|dsa|ed25519|cryptographic|crypto) signatures?\b')
_SIGN_EXPLICIT = re.compile(r'\bsigns\b|\bsigning\b|\bsign (?:the |a |an )?(?:data|message|digest|hash|payload|file|input)\b|'
                            r'\bsignatures? (?:creation|generation)\b|'
                            r'\b(?:creat|generat|produc|comput|mak)\w*\b[^.?!]{0,40}\b(?:digital |ecdsa |rsa )?signatures?\b')
_VERIFY_EXPLICIT = re.compile(r'\bverif\w*\b[^.?!]{0,40}\bsignatures?\b|\bsignatures? (?:verification|check\w*|validation)\b|'
                              r'\b(?:check|validat)\w*\b[^.?!]{0,30}\b(?:digital |ecdsa |rsa )?signatures?\b|'
                              r'\bverif\w* (?:the |a )?(?:signed|ecdsa|rsa|digital)\b')
_SIGN_BARE = re.compile(r'\bsign(?:s|ing|ed)?\b(?![-\s]*(?:extend\w*|extension|bits?|flags?|integers?|ints?|chars?|values?|'
                        r'compar\w*|arithmetic|bytes?|words?|numbers?|overflow|of\b))')
_VERIFY_BARE = re.compile(r'\bverif(?:y|ies|ied|ying|ication)\b')
_PROTOTYPE = re.compile(r'\bfunction signatures?\b|\bsignatures? of (?:the |this |a )?(?:function|fun_|method|routine|[a-z_]+\()')


def signature_operations(lower):
    """['signing'] / ['verification'] / both, from a normalized lower-case question."""
    if _PROTOTYPE.search(lower) and not (_SIGNATURE.search(lower) or _SIGN_BARE.search(lower.replace('signature', ''))):
        return []
    sign, verify = bool(_SIGN_EXPLICIT.search(lower)), bool(_VERIFY_EXPLICIT.search(lower))
    bare_sign = bool(_SIGN_BARE.search(lower.replace('signature', '')))
    bare_verify = bool(_VERIFY_BARE.search(lower))
    context = bool(_SIGNATURE.search(lower)) or sign or verify or (bare_sign and bare_verify)
    if context:
        sign, verify = sign or bare_sign, verify or bare_verify
    if _SIGNATURE.search(lower) and not (sign or verify):
        sign = verify = True  # "the digital signature": creation and verification both answer it
    return [op for op, on in (('signing', sign), ('verification', verify)) if on]


_FILE = re.compile(
    r"\bwhat(?: is|'s) (?:this|the|that) (?:file|binary|executable|sample|program|exe|image)\b|"
    r'\bwhat (?:kind|type|sort) of (?:file|binary|executable|sample|program)\b|'
    r'\b(?:file|binary|executable) (?:format|type|structure|integrity|condition|validity|identity)\b|'
    r'\bis (?:this|the|that) (?:file|binary|executable|sample|pe|program|exe) (?:a |an )?'
    r'(?:valid|corrupt\w*|damaged|malformed|broken|truncated|intact|dll|pe|exe\w*|executable)\b|'
    r'\b(?:corrupt\w*|damaged|malformed|truncated|tampered)\b[^.?!]{0,30}\b(?:file|binary|executable|pe|structure|headers?)\b|'
    r'\b(?:file|binary|executable|pe|structure|headers?)\b[^.?!]{0,30}\b(?:corrupt\w*|damaged|malformed|truncated)\b|'
    r'\bstructur(?:e|al) (?:validation|condition|issues?|problems?|warnings?|errors?|damage|integrity)\b|'
    r'\bpe (?:headers?|structure|validation)\b')
_GENERIC = re.compile(r'\bcryptograph\w*|\bcrypto\b|\bciphers?\b|\bcrypt(?:o)?\s*api\b')
_ALGORITHM = re.compile(r'\b(aes(?:-?(?:128|192|256))?|sha-?\s?(?:1|224|256|384|512)|md5|ecdsa|rsa|gcm|cbc|ecdh)\b')
_ALGORITHM_OPS = {'aes': ('encryption', 'decryption'), 'gcm': ('encryption', 'decryption'),
                  'cbc': ('encryption', 'decryption'), 'sha': ('hashing',), 'md5': ('hashing',),
                  'ecdsa': ('signing', 'verification'), 'rsa': ('encryption', 'decryption', 'signing', 'verification'),
                  'ecdh': ('key_agreement', 'key_handling')}
_FACTUAL = re.compile(r'\b(?:which|what|where|find|list|show|identify|locate|name|give|does|do|is there|are there|any)\b')
_REJECT = re.compile(r'\bwhy\b|\bhow\b(?! many)|\bexplain\w*|\bdescrib\w*|\bsummar\w*|\bsecur\w*|\bsafe\w*|\bweak\w*|'
                     r'\bvulnerab\w*|\bstrength\b|\bstrong\b|\bcorrect\w*|\bbugs?\b|\bshould\b|\bpurpose\b|\bintent\w*|'
                     r'\bflaw\w*|\battack\w*|\bexploit\w*|\brisk\w*')
_EVIDENCE = re.compile(r'\b(?:show|give|list|display|what is)\b[^.?!]{0,30}\bevidence\b|\bevidence (?:for|of|behind|supporting)\b')
_CALLEES = re.compile(r'\bwhat (?:\w+ ){0,3}(?:does|do|did) [^.?!]{0,40}\bcall\b|\bcallees?\b|\bfunctions? (?:it|this function) calls\b|'
                      r'\bcalled by (?:it|this|this function|the function)\b')
_CALLERS = re.compile(r'\b(?:who|what|which)\b[^.?!]{0,30}\b(?:calls?|invokes?)\b|\bcallers?\b|\bthat (?:calls?|invokes?)\b|'
                      r'\bis called\b|\bcalled from\b|\bwhere is [^.?!]{0,40}\b(?:called|used|invoked)\b|\bxrefs? to\b|\buses? of\b')
_API_WORDS = re.compile(r'\bapis?\b|\bapi calls?\b|\bimports?\b|\blibrary calls?\b|\bimported functions?\b')
_THIS = re.compile(r'\b(?:this|that|the current|current|selected|the selected) function\b')
_IT = re.compile(r'\b(?:it|this|that)\b')
_TOKEN = re.compile(r'[A-Za-z_][A-Za-z0-9_]{2,}|\b0x[0-9a-fA-F]{4,16}\b|\b[0-9a-fA-F]{6,16}\b')
_NOT_API = re.compile(r'(?i)sha-?\d+|md5|hmac|aes\d*|rsa|ecdsa|ecdh')
# Question words never treated as function names, even if a binary defines one.
_STOP = frozenset('''which what where when who whom whose find list show identify locate name give does did
    do this that the function functions call calls called caller callers callee callees api apis make makes
    perform performs data input program binary there any and for from with into evidence stored code'''.split())


def api_tokens(question):
    return list(dict.fromkeys(t for t in re.findall(r'[A-Za-z_][A-Za-z0-9_]{3,}', question)
                              if classify_api(t) and not _NOT_API.fullmatch(t)))


class FactQuestionError(ValueError):
    """A supported factual question that needs information the user must supply."""


@dataclass
class FactAnswer:
    intent: str
    answer: str
    tool_results: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    relationships: list = field(default_factory=list)
    selected: dict | None = None  # function to make current, when exactly one is answered
    limitations: list = field(default_factory=list)  # full text; the answer shows a one-line note
    tool_facts: str = ''  # rendered tool output with full identifiers (expandable, stored)
    facts: dict = field(default_factory=dict)  # structured verified facts for the UI and tests

    @property
    def summary(self):
        first = next((line for line in self.answer.split('\n') if line.strip()), '')
        return re.sub(r'[*`]', '', first.replace('**Answer:**', '')).lstrip('#- ').strip()


def _code(value):
    return '`' + _display(value).replace('`', "'") + '`'


def _addr(value):
    return _code('0x' + value if re.fullmatch(r'[0-9a-fA-F]+', str(value)) else value)


def classify(question):
    """Pure text routing. Returns a routing dict, or None when not a supported factual question."""
    if not isinstance(question, str):
        return None
    lower = ' '.join(question.lower().split())
    if _REJECT.search(lower):
        return None
    operations = [name for name, pattern in _OPERATIONS if re.search(pattern, lower)]
    signature_ops = signature_operations(lower)
    # Keep operations in question order is not needed; DISPLAY_ORDER decides layout.
    operations = [op for op in DISPLAY_ORDER if op in set(operations) | set(signature_ops)]
    algorithms = [m.group(1).replace(' ', '') for m in _ALGORITHM.finditer(lower)]
    if not operations:
        for algorithm in algorithms:
            key = next((k for k in _ALGORITHM_OPS if algorithm.startswith(k)), None)
            operations += [op for op in _ALGORITHM_OPS.get(key, ()) if op not in operations]
    generic = bool(_GENERIC.search(lower))
    apis = api_tokens(question)
    factual = bool(_FACTUAL.search(lower))
    this = bool(_THIS.search(lower))
    base = {'operations': operations, 'algorithms': algorithms, 'apis': apis, 'this_function': this, 'generic': generic,
            'pronoun': bool(_IT.search(lower)), 'tokens': list(dict.fromkeys(_TOKEN.findall(question)))}
    if _FILE.search(lower) and not (operations or apis):
        return {'intent': 'file_identity', **base}
    if _EVIDENCE.search(lower):
        return {'intent': 'evidence', **base}
    if _CALLEES.search(lower) and not apis and not (operations and not this):
        return {'intent': 'callees', **base}
    if apis and (factual or _CALLERS.search(lower)):
        return {'intent': 'crypto_api', **base}
    if _API_WORDS.search(lower) and factual and (this or not (operations or generic)):
        return {'intent': 'function_apis', **base}
    if (operations or generic or algorithms) and factual:
        return {'intent': 'crypto_operations', **base}
    if _CALLERS.search(lower):
        return {'intent': 'callers', **base}
    return None


class FactAnswerer:
    """Answer one routed question with validated read-only tools for one binary."""

    def __init__(self, tools, session, binary=None, structure=None):
        self.tools, self.session = tools, session
        self.binary = binary or {}
        self.structure = structure  # aire.analysis.file_structure.assess() result, or None
        self.results = []

    # ----------------------------------------------------------- tools
    def _run(self, name, arguments):
        result = self.tools.registry.run(name, arguments)
        self.results.append(result)
        if not result['ok']:
            raise FactQuestionError(result['error']['message'])
        return result['data']

    def _crypto(self):
        cached = next((r for r in self.results if r['tool'] == 'crypto_evidence'), None)
        return cached['data'] if cached else self._run('crypto_evidence', {'limit': 100})

    # ----------------------------------------------------------- targets
    def _explicit_functions(self, tokens):
        """Stored functions named in the question (exact name, FUN_ name, or address)."""
        found, ambiguous = {}, []
        for token in tokens:
            candidates = [token]
            hexa = re.fullmatch(r'(?:0x|fun_)?([0-9a-fA-F]{4,16})', token, re.IGNORECASE)
            if hexa:
                candidates += [hexa.group(1).lower().zfill(8)[-8:], 'FUN_' + hexa.group(1).lower().zfill(8)[-8:]]
            for candidate in dict.fromkeys(candidates):
                matches = [f for f in self.tools.query.find_functions(self.session.binary_id, candidate)
                           if not f.is_external]
                internal = [f for f in matches if not f.is_thunk] or matches
                if len(internal) == 1:
                    found.setdefault(internal[0].function_id, internal[0])
                    break
                if len(internal) > 1:
                    ambiguous.append((token, internal))
                    break
            if len(found) >= 3:
                break
        if ambiguous and not found:
            token, matches = ambiguous[0]
            raise FactQuestionError(f'"{token}" matches {len(matches)} stored functions (' + ', '.join(
                f'{m.current_name} at 0x{m.address}' for m in matches[:4]) + '); name one by address.')
        return list(found.values())

    @staticmethod
    def _function_tokens(routed, strict=False):
        """Candidate function selectors. Strict mode (binary-wide crypto questions) only
        accepts identifier-like tokens, so a stored function literally named "hash"
        cannot silently narrow "which function performs a hash?" to itself."""
        tokens = [t for t in routed['tokens'] if t not in routed['apis'] and t.lower() not in _STOP]
        return [t for t in tokens if re.search(r'[_0-9]', t)] if strict else tokens

    def _targets(self, routed, *, allow_pronoun=True, strict=False):
        functions = self._explicit_functions(self._function_tokens(routed, strict))
        if functions:
            return [vars(f) for f in functions]
        if routed['this_function'] or (allow_pronoun and routed['pronoun']):
            if self.session.current_function_id:
                return [self._run('get_function', {'function': self.session.current_function_id})['function']]
        raise FactQuestionError('Select a function from Functions, or name it (e.g. FUN_0041d160 or 0x0041d160) '
                                'in the question.')

    # ----------------------------------------------------------- answers
    def answer(self, routed):
        result = getattr(self, '_answer_' + routed['intent'])(routed)
        result.answer = re.sub(r'\n{3,}', '\n\n', result.answer).strip()
        return result

    def _context(self):
        """One compact context line (binary identity + structural condition) placed after the answer."""
        binary = self.binary
        name = binary.get('program_name') or 'selected binary'
        sha = (binary.get('sha256') or self.session.binary_id or '')[:16]
        lines = [f'**Binary:** {_code(name)} · SHA-256 {_code(sha + "…")}']
        structure = self.structure
        if structure and structure['status'] != 'full':
            codes = ', '.join(dict.fromkeys(i['code'] for i in structure['issues'] if i['severity'] != 'info'))
            lines.append(f"**Structural condition:** {STRUCTURE_LABEL[structure['status']]}"
                         + (f' ({_display(codes)})' if codes else '') + ' — results may be incomplete. '
                         'Ask "Is this file corrupted?" for details.')
        return lines

    @staticmethod
    def _names(rows):
        return ', '.join(f"{_code(r['name'])} ({_addr(r['address'])})" for r in rows)

    @staticmethod
    def _cell(value):
        return str(value).replace('|', '\\|')

    def _callsite_evidence(self, row, callsite):
        return {'label': f"{callsite['api']} call @ 0x{callsite['address']} in {row['name']} ({callsite['operation']})",
                'evidence_id': callsite['source_id'],
                'provenance': {'source_table': callsite['source_table'], 'source_id': callsite['source_id'],
                               'address': callsite['address'], 'binary_id': self.session.binary_id}}

    def _caller_relationship(self, caller, row):
        return {'label': f"{caller['name']} → {row['name']} @ {caller['callsite']}",
                'provenance': {'source_table': caller['source_table'], 'source_id': caller['source_id'],
                               'address': caller['callsite'], 'binary_id': self.session.binary_id}}

    def _crypto_facts(self, data, rows):
        filtered = {**data, 'functions': rows}
        return render_tool_facts([{'ok': True, 'tool': 'crypto_evidence', 'data': filtered}])

    def _role_rows(self, rows, operation, evidence, relationships):
        """Table rows + structured facts for one operation; roles come only from the called API."""
        table, facts = [], []
        for row in rows:
            calls = [c for c in row['callsites'] if c['operation'] == operation]
            if not calls:
                continue
            apis = ', '.join(f"{_code(c['api'])} @ {_addr(c['address'])}" for c in calls[:6])
            callers = ', '.join(f"{_code(c['name'])} @ {_addr(c['callsite'])}" for c in row['callers'][:3]) or '—'
            table.append(f"| {LABELS.get(operation, operation)} | {_code(row['name'])} {_addr(row['address'])} | "
                         f"{apis} | {callers} |")
            facts.append({'role': operation, 'function': row['name'], 'function_id': row['function_id'],
                          'address': row['address'], 'apis': [c['api'] for c in calls],
                          'callsites': [c['address'] for c in calls],
                          'callers': [{'name': c['name'], 'callsite': c['callsite']} for c in row['callers']]})
            evidence += [self._callsite_evidence(row, call) for call in calls]
            for caller in row['callers'][:4]:
                relationship = self._caller_relationship(caller, row)
                if relationship['label'] not in {r['label'] for r in relationships}:
                    relationships.append(relationship)
        return table, facts

    def _identifier_lines(self, data, routed, rows):
        wanted = [a.replace('-', '').upper() for a in routed['algorithms']]
        found = []
        for row in data['functions']:
            for item in row['identifier_strings']:
                meaning = item['meaning'].replace('-', '').replace(' ', '').upper()
                if wanted and not any(meaning.startswith(w) or w.startswith(meaning) for w in wanted):
                    continue
                if not wanted and row not in rows:
                    continue
                found.append(f"{_code(row['name'])} references {_code(item['value'])} ({_display(item['meaning'])}) "
                             f"at {_addr(item['address'])}")
        if wanted and not found:
            return ['**Algorithm:** no stored identifier string for ' + ', '.join(_code(a.upper()) for a in
                    routed['algorithms']) + ' is referenced by a crypto-calling function, so the algorithm is not '
                    'established by this evidence.']
        if not found:
            return []
        note = (' An identifier referenced by one function does not prove which key or handle another uses.'
                if wanted else '')
        return ['**Algorithm identifiers (exact stored strings):** ' + '; '.join(found) + '.' + note]

    TABLE_HEAD = ['| Role | Function | API call @ call site | Called by |', '|---|---|---|---|']
    VERIFIED_NOTE = ('*Verified from exact stored call sites; roles come from the called API, not from names or AI. '
                     'Static evidence only — see Limitations.*')

    def _answer_crypto_operations(self, routed):
        data = self._crypto()
        rows = data['functions']
        present = [op for op in DISPLAY_ORDER if op in data['summary']['operations']]
        operations = list(routed['operations']) or present
        if routed.get('generic'):  # "crypto or hashing": requested operations plus every one present
            operations += [op for op in present if op not in operations]
        if 'encryption' in operations or 'decryption' in operations:
            operations = operations + ['encryption_or_decryption']
        scope = None
        if routed['this_function'] or self._explicit_functions(self._function_tokens(routed, strict=True)):
            scope = self._targets(routed, allow_pronoun=False, strict=True)
            scope_ids = {f['function_id'] for f in scope}
            scoped_rows = [r for r in rows if r['function_id'] in scope_ids]
        else:
            scoped_rows = rows
        evidence, relationships, facts, table, sentence, missing = [], [], [], [], [], []
        answered = []
        for operation in dict.fromkeys(operations):
            found_rows, found_facts = self._role_rows(scoped_rows, operation, evidence, relationships)
            if operation == 'encryption_or_decryption' and not found_rows:
                continue
            label = LABELS.get(operation, operation)
            if found_rows:
                table += found_rows
                facts += found_facts
                matched = [r for r in scoped_rows if any(c['operation'] == operation for c in r['callsites'])]
                answered += matched
                sentence.append(f"{label.split(' (')[0].lower()} in {self._names(matched)}")
            else:
                missing.append(label.split(' (')[0].lower())
                table.append(f'| {label} | — | No stored call site to a known {label.lower()} API | — |')
        unique = list({r['function_id']: r for r in answered}.values())
        where = f"{self._names(scope)}" if scope else 'this binary'
        if sentence:
            text = '**Answer:** ' + '; '.join(sentence)[0].upper() + '; '.join(sentence)[1:] + '.'
            if missing:
                text += f" No {', '.join(missing)} call site is stored in {where}."
        elif rows:
            text = (f"**Answer:** No {', '.join(missing) or 'requested'} call site is stored in {where}. Crypto operations "
                    'present: ' + ', '.join(LABELS[op].lower() for op in present) + '.')
        else:
            text = (f"**Answer:** No function in this binary has a stored call site to a known crypto API "
                    f"({data['summary']['crypto_api_imports']} crypto API imports stored).")
        lines = [text, '']
        if table:
            lines += self.TABLE_HEAD + table + ['']
        if scope and not answered:
            for item in [o for o in data['orchestrators'] if o['function_id'] in {f['function_id'] for f in scope}]:
                lines.append(f"{_code(item['name'])} calls crypto-calling functions at " +
                             ', '.join(_addr(a) for a in item['calls']) + ' (stored CALL edges).')
        lines += self._identifier_lines(data, routed, answered or scoped_rows)
        lines += [''] + self._context() + ['', self.VERIFIED_NOTE]
        selected = ({'function_id': unique[0]['function_id'], 'current_name': unique[0]['name'],
                     'address': unique[0]['address']} if len(unique) == 1 else None)
        return FactAnswer('crypto_operations', '\n'.join(lines), self.results, evidence, relationships, selected,
                          list(LIMITATIONS), self._crypto_facts(data, unique or scoped_rows), {'roles': facts})

    def _answer_crypto_api(self, routed):
        data = self._crypto()
        evidence, relationships, answered, table, sentence, facts = [], [], [], [], [], []
        imports = {i['api'].lower(): i for i in data['imports']}
        for api in routed['apis']:
            key = api.lower()
            matches = [(row, [c for c in row['callsites'] if c['api'].lower() == key]) for row in data['functions']]
            matches = [(row, calls) for row, calls in matches if calls]
            family, operation = classify_api(api)
            label = LABELS.get(operation, operation).lower()
            if matches:
                for row, calls in matches:
                    callers = ', '.join(f"{_code(c['name'])} @ {_addr(c['callsite'])}" for c in row['callers'][:3]) or '—'
                    table.append(f"| {_code(api)} ({label}) | {_code(row['name'])} {_addr(row['address'])} | " +
                                 ', '.join(_addr(c['address']) for c in calls) + f' | {callers} |')
                    evidence += [self._callsite_evidence(row, c) for c in calls]
                    relationships += [self._caller_relationship(c, row) for c in row['callers'][:4]]
                    facts.append({'api': api, 'operation': operation, 'function': row['name'],
                                  'address': row['address'], 'callsites': [c['address'] for c in calls]})
                    answered.append(row)
                sentence.append(f"{_code(api)} ({label}) is called by {self._names([r for r, _ in matches])}")
            elif key in imports:
                sentence.append(f"{_code(api)} is imported ({_display(imports[key]['dll'] or 'unknown DLL')}) but no "
                                'stored call site was found; it may be called through an unresolved computed pointer')
            else:
                sentence.append(f'{_code(api)} is not among the stored crypto API imports of this binary')
        lines = ['**Answer:** ' + '. '.join(sentence) + '.', '']
        if table:
            lines += ['| API | Calling function | Call site(s) | Called by |', '|---|---|---|---|'] + table + ['']
        lines += self._context() + ['', self.VERIFIED_NOTE]
        unique = list({r['function_id']: r for r in answered}.values())
        selected = ({'function_id': unique[0]['function_id'], 'current_name': unique[0]['name'],
                     'address': unique[0]['address']} if len(unique) == 1 else None)
        return FactAnswer('crypto_api', '\n'.join(lines), self.results, evidence, relationships, selected,
                          list(LIMITATIONS[:3]), self._crypto_facts(data, unique) if unique else '', {'apis': facts})

    def _graph(self, routed, tool):
        targets = self._targets(routed)
        relationships, results, lines, facts = [], [], [], []
        callers = tool == 'get_callers'
        for target in targets:
            data = self._run(tool, {'function': target['function_id'], 'limit': 20})
            results.append({'ok': True, 'tool': tool, 'data': data})
            name = f"{_code(target['current_name'])} ({_addr(target['address'])})"
            others = [(item['caller']['function'] if callers else item['callee']['function']) for item in data['items']]
            unique = list({o['function_id']: o for o in others}.values())
            noun = 'caller' if callers else 'callee'
            if data['items']:
                listed = ', '.join(_code(o['current_name']) for o in unique[:6]) + (' …' if len(unique) > 6 else '')
                lines.append(f"**Answer:** {name} has {len(unique)} stored {noun}{'s' if len(unique) != 1 else ''}"
                             f" ({len(data['items'])} call site{'s' if len(data['items']) != 1 else ''}): {listed}.")
            else:
                lines.append(f'**Answer:** {name} has no stored {noun}s. Indirect, computed or runtime calls are '
                             'not excluded.')
            if data['items']:
                lines += ['', '| Call | Call site | ' + ('Caller' if callers else 'Callee') + ' address |', '|---|---|---|']
            for item in data['items']:
                caller, callee = item['caller']['function'], item['callee']['function']
                other = caller if callers else callee
                kind = ' (import thunk)' if other['is_thunk'] else ' (external)' if other['is_external'] else ''
                lines.append(f"| {self._cell(_display(caller['current_name']))} → {self._cell(_display(callee['current_name']))} | "
                             f"{_addr(item['callsite_address'])} | {_addr(other['address'])}{kind} |")
                relationships.append({'label': f"{caller['current_name']} → {callee['current_name']} @ {item['callsite_address']}",
                                      'provenance': item['provenance']})
                facts.append({'caller': caller['current_name'], 'callee': callee['current_name'],
                              'callsite': item['callsite_address']})
            if data['truncated']:
                lines.append('Additional stored edges were omitted by the 20-edge limit.')
            lines.append('')
        lines += self._context() + ['', '*Verified from resolved stored CALL edges (no AI model). '
                                        'Calls through computed pointers or callbacks are not resolved.*']
        selected = targets[0] if len(targets) == 1 else None
        return FactAnswer('callers' if callers else 'callees', '\n'.join(lines), self.results, [], relationships,
                          selected, ['Calls through computed pointers or callbacks are not resolved as CALL edges.'],
                          render_tool_facts(results), {'edges': facts})

    def _answer_callers(self, routed):
        return self._graph(routed, 'get_callers')

    def _answer_callees(self, routed):
        return self._graph(routed, 'get_callees')

    def _answer_function_apis(self, routed):
        targets = self._targets(routed)
        data = self._crypto()
        evidence, relationships, lines, facts = [], [], [], []
        for target in targets:
            callees = self._run('get_callees', {'function': target['function_id'], 'limit': 50})
            crypto_row = next((r for r in data['functions'] if r['function_id'] == target['function_id']), None)
            rows, seen, internal = [], set(), []
            if crypto_row:
                for call in crypto_row['callsites']:
                    seen.add((call['api'].lower(), call['address']))
                    operation = LABELS.get(call['operation'], call['operation']).lower()
                    rows.append(f"| {_code(call['api'])} | {_addr(call['address'])} | {operation} | "
                                f"{_display(call['dll'] or 'import')} |")
                    evidence.append(self._callsite_evidence(crypto_row, call))
                    facts.append({'function': target['current_name'], 'api': call['api'], 'callsite': call['address'],
                                  'operation': call['operation']})
            for item in callees['items']:
                callee = item['callee']['function']
                relationships.append({'label': f"{target['current_name']} → {callee['current_name']} @ {item['callsite_address']}",
                                      'provenance': item['provenance']})
                if callee['is_thunk'] or callee['is_external']:
                    if (callee['current_name'].lower(), item['callsite_address']) not in seen:
                        rows.append(f"| {_code(callee['current_name'])} | {_addr(item['callsite_address'])} | import call | — |")
                        facts.append({'function': target['current_name'], 'api': callee['current_name'],
                                      'callsite': item['callsite_address'], 'operation': None})
                else:
                    internal.append(f"{_code(callee['current_name'])} @ {_addr(item['callsite_address'])}")
            apis = list(dict.fromkeys(f['api'] for f in facts if f['function'] == target['current_name']))
            name = f"{_code(target['current_name'])} ({_addr(target['address'])})"
            lines.append(f"**Answer:** {name} calls {len(apis)} imported API{'s' if len(apis) != 1 else ''}"
                         + (': ' + ', '.join(_code(a) for a in apis[:8]) if apis else '') + '.' +
                         (' No stored call to an imported API was found.' if not apis else ''))
            if rows:
                lines += ['', '| API | Call site | Operation | DLL |', '|---|---|---|---|'] + rows
            if internal:
                lines += ['', '**Internal calls:** ' + ', '.join(internal)]
            if callees['truncated']:
                lines.append('Additional stored edges were omitted by the tool limit.')
            lines.append('')
        lines += self._context() + ['', '*Verified from stored call references and CALL edges (no AI model).*']
        selected = targets[0] if len(targets) == 1 else None
        return FactAnswer('function_apis', '\n'.join(lines), self.results, evidence, relationships, selected,
                          ['Calls through computed pointers without a stored import binding are not listed.',
                           'Parameters are not validated.'], '', {'api_calls': facts})

    def _inventory(self):
        """Counts of stored facts (independent of the file name)."""
        with self.tools.query._snapshot(self.session.binary_id) as db:
            functions, external = db.execute('SELECT COUNT(*), COALESCE(SUM(is_external), 0) FROM functions '
                                              'WHERE binary_id=?', (self.session.binary_id,)).fetchone()
            artifacts = dict(db.execute('SELECT type, COUNT(*) FROM artifacts WHERE binary_id=? GROUP BY type',
                                        (self.session.binary_id,)).fetchall())
            edges = db.execute('SELECT COUNT(*) FROM function_edges WHERE binary_id=?',
                               (self.session.binary_id,)).fetchone()[0]
            warnings = db.execute('SELECT COUNT(*) FROM warnings WHERE binary_id=?',
                                  (self.session.binary_id,)).fetchone()[0]
        return {'functions': functions, 'external': external, 'edges': edges, 'warnings': warnings,
                'imports': artifacts.get('IMPORT', 0), 'strings': artifacts.get('STRING', 0),
                'exports': artifacts.get('EXPORT', 0)}

    def _answer_file_identity(self, routed):
        structure = self.structure or {'status': 'unverified', 'reason': 'Structural validation was not run.',
                                       'issues': [], 'impacts': [], 'summary': ''}
        status = structure['status']
        binary = self.binary
        codes = ', '.join(dict.fromkeys(i['code'] for i in structure['issues'] if i['severity'] != 'info'))
        kind_text = structure.get('format') if status != 'unverified' and structure.get('format') else 'File'
        if structure.get('is_dll') is not None and status != 'unverified':
            kind_text += ' DLL' if structure['is_dll'] else ' executable'
        lines = [f"**Answer:** {_display(kind_text)} — structure {STRUCTURE_LABEL[status].lower()}"
                 + (f' ({_display(codes)})' if codes else '') + f'. {LEVEL_TEXT[status]}', '',
                 f"**File:** {_code(binary.get('program_name') or 'selected binary')} "
                 f"(SHA-256 {_code((binary.get('sha256') or '')[:16] + '…')}). "
                 'The file name is only a label; it is not used as evidence.']
        if structure.get('format') and status != 'unverified':
            kind = ''
            if structure.get('is_dll') is not None:
                kind = ', DLL image (IMAGE_FILE_DLL set)' if structure['is_dll'] else \
                       ', executable image (IMAGE_FILE_DLL not set)'
            arch = ', '.join(str(v) for v in (structure.get('architecture'),
                                               f"{structure['bits']}-bit" if structure.get('bits') else None) if v)
            lines.append(f"**Format (from headers):** {_display(structure['format'])}" +
                         (f' — {_display(arch)}' if arch else '') + kind)
        if status == 'unverified':  # the answer line states the condition; only the reason adds information
            lines.append('**Why unverified:** ' + _display(structure.get('reason', '')))
        detected = [i for i in structure['issues'] if i['severity'] != 'info']
        notes = [i for i in structure['issues'] if i['severity'] == 'info']
        if detected:
            lines += ['', '**Detected conditions:**']
            for issue in detected[:12]:
                where = f", file offset {_addr(format(issue['offset'], 'x'))}" if issue.get('offset') is not None else ''
                lines.append(f"- {_code(issue['code'])} ({issue['severity']}{where}): {_display(issue['message'])}")
            if len(detected) > 12:
                lines.append(f'- {len(detected) - 12} more condition(s) omitted.')
        if notes:
            lines.append('**Informational (not damage):** ' + '; '.join(_display(i['message']) for i in notes[:4]))
        unreliable = list(structure['impacts'])
        for group in structure.get('unnamed_import_groups', []):
            unreliable.append(f"Import descriptor {_display(group['descriptor'])} has no valid DLL name, so its "
                              f"{group['functions']} imported function(s) cannot be attributed to a library.")
        if unreliable:
            lines += ['', '**Missing or unreliable evidence:**'] + ['- ' + _display(u) for u in unreliable]
        inventory = self._inventory()
        lines += ['', f"**Stored analysis facts:** {inventory['functions']} functions ({inventory['external']} external), "
                      f"{inventory['edges']} call edges, {inventory['imports']} imports, {inventory['exports']} exports, "
                      f"{inventory['strings']} strings, {inventory['warnings']} analyzer warnings."]
        if status == 'none' and inventory['functions']:
            lines.append('These stored facts come from a file whose headers are invalid; treat them as unreliable.')
        # Behavior: only independent code evidence (exact crypto API call sites), never names.
        data = self._crypto()
        ops = [op for op in DISPLAY_ORDER if op in data['summary']['operations']]
        lines += ['', '**Program behavior (stored code evidence only):**']
        if ops and status != 'none':
            for op in ops:
                lines.append(f'- {LABELS[op]}: ' + ', '.join(_addr(a) for a in data['summary']['operations'][op][:6])
                             + ' (exact crypto API call sites)')
        else:
            lines.append('- No crypto API call sites are stored.' if status != 'none' else
                         '- Not described: the structure is invalid.')
        lines.append('- No program purpose is stated. A.I.R.E. does not infer behavior from the file name or from '
                     'damaged structures; ask about specific functions, imports, strings or call relationships '
                     'for verified details.' if status != 'full' else
                     '- For an evidence-grounded interpretation of overall behavior, ask "What does this binary do?".')
        if routed.get('overview'):
            lines += ['', '**Why no AI overview:** the structure is ' + STRUCTURE_LABEL[status].lower() +
                      ', so a whole-program interpretation could rest on missing or misattributed evidence. '
                      'Verified facts are shown instead.']
        evidence = [{'label': f"structure {i['code']} ({i['severity']})" +
                              (f" @ file offset 0x{i['offset']:x}" if i.get('offset') is not None else ''),
                     'evidence_id': f"{self.session.binary_id}:structure:{i['code']}:{i.get('offset')}",
                     'provenance': {'source_table': 'pe_structure_validation', 'source_id': i['code'],
                                    'address': None, 'binary_id': self.session.binary_id}}
                    for i in structure['issues']]
        return FactAnswer('file_identity', '\n'.join(lines), self.results, evidence, [], None,
                          ['Structural validation re-reads the original file only when its SHA-256 matches the '
                           'analyzed file.', 'Behavior is described only from exact stored crypto API call sites.'],
                          '', {'structure': {k: structure.get(k) for k in ('status', 'format', 'architecture', 'bits',
                                                                           'is_dll', 'summary', 'reason')},
                               'issues': structure['issues']})

    def _answer_evidence(self, routed):
        from aire.agent import assembly_answers as aa
        targets = self._targets(routed)[:1]
        target = targets[0]
        data = self._crypto()
        evidence, relationships, facts = [], [], []
        row = next((r for r in data['functions'] if r['function_id'] == target['function_id']), None)
        name = f"{_code(target['current_name'])} ({_addr(target['address'])})"
        if row:
            ops = ', '.join(dict.fromkeys(LABELS.get(c['operation'], c['operation']).lower() for c in row['callsites']))
            lines = [f"**Answer:** {name} has {len(row['callsites'])} crypto API call site"
                     f"{'s' if len(row['callsites']) != 1 else ''} ({ops}); instruction-level evidence follows.", '',
                     '| API | Call site | Operation |', '|---|---|---|']
            for call in row['callsites']:
                lines.append(f"| {_code(call['api'])} | {_addr(call['address'])} | "
                             f"{LABELS.get(call['operation'], call['operation']).lower()} |")
                evidence.append(self._callsite_evidence(row, call))
                facts.append({'api': call['api'], 'callsite': call['address'], 'operation': call['operation']})
            lines += [''] + self._identifier_lines(data, {'algorithms': [], 'operations': ['any']}, [row]) + ['']
        else:
            lines = [f'**Answer:** {name} has no crypto API call sites; instruction-level evidence follows.', '']
        try:
            text, tool, cited = aa.answer_function(self.tools._ai(), target['function_id'])
        except (KeyError, ValueError) as exc:
            lines.append('M10 instruction evidence is unavailable for this function: ' + _display(str(exc)[:200]))
        else:
            lines += [text.replace('### Function analysis (deterministic evidence)', '**Instruction-level evidence (M10):**', 1)]
            if tool:
                self.results.append({'ok': True, 'tool': tool['tool'], 'data': tool['data']})
            evidence += [{'label': f'instruction @ 0x{a}', 'evidence_id': f'{self.session.binary_id}:{a}',
                          'provenance': {'source_table': 'function_ir', 'source_id': target['function_id'],
                                         'address': a, 'binary_id': self.session.binary_id}}
                         for a in sorted(cited)[:60]]
        lines += [''] + self._context()
        return FactAnswer('evidence', '\n'.join(lines), self.results, evidence, relationships, target,
                          list(LIMITATIONS[:3]), self._crypto_facts(data, [row]) if row else '', {'call_sites': facts})


def answer(tools, session, question, binary=None, structure=None):
    """Return a FactAnswer, or None if the question is not a supported factual form."""
    routed = classify(question)
    if routed is None:
        return None
    return FactAnswerer(tools, session, binary, structure).answer(routed)
