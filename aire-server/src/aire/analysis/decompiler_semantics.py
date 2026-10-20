"""Small bounded expression recognizer for decompiler C, never a C/C++ parser."""
import re

MAX_CHARS = 32000
MAX_TOKENS = 4096
MAX_OBSERVATIONS = 64
TOKEN = re.compile(r'0x[0-9a-fA-F]+|\d+(?:\.\d+)?|[A-Za-z_$][\w$]*|==|!=|<=|>=|<<|>>|&&|\|\||[^\s]')
TYPES = re.compile(r'^(?:(?:const|unsigned|signed|long|short)\s+)*(?:int|char|double|float|float\d+|undefined\d*|u?int\d*_t|void|bool)(?:\s*\*)*$')
OPERATORS = {'*': 'multiplication', '/': 'division', '+': 'addition', '-': 'subtraction',
             '&': 'bitwise_and', '|': 'bitwise_or', '^': 'bitwise_xor', '<<': 'shift_left',
             '>>': 'shift_right', '==': 'comparison', '!=': 'comparison', '<': 'comparison',
             '>': 'comparison', '<=': 'comparison', '>=': 'comparison'}
PRECEDENCE = {'|': 1, '^': 2, '&': 3, '==': 4, '!=': 4, '<': 5, '>': 5, '<=': 5,
              '>=': 5, '<<': 6, '>>': 6, '+': 7, '-': 7, '*': 8, '/': 8}


def extract_decompiler(text):
    bounded = (text or '')[:MAX_CHARS]
    # Remove comments and quoted data before looking for operations. Preserve offsets.
    clean = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
                   lambda m: ' ' * len(m[0]), bounded, flags=re.S)
    matches = list(TOKEN.finditer(clean))[:MAX_TOKENS + 1]
    tokens = [m[0] for m in matches[:MAX_TOKENS]]
    observations, calls = [], []
    parse_gaps = 0

    def add(operation, left=None, right=None, *, returned=False, offset=0):
        if len(observations) >= MAX_OBSERVATIONS:
            return
        same = left is not None and left == right and not contains_unknown_call(left)
        row = {'operation': operation, 'same_operand': same, 'in_return_expression': returned,
               'offset': offset}
        if same and operation == 'multiplication':
            row['likely_pattern'] = 'value_squared'
        if right and right[0] == 'literal':
            row['constant_operand'] = right[1]
        observations.append(row)

    def contains_unknown_call(node):
        if not isinstance(node, tuple):
            return False
        if node and node[0] == 'call' and node[1] not in ('CONCAT44', 'CONCAT22', 'CONCAT11'):
            return True
        return any(contains_unknown_call(x) for x in node)

    def expression(start, end, returned, depth=0, minimum=0):
        if depth > 24 or start >= end:
            raise ValueError('expression bound')
        pos, token = start + 1, tokens[start]
        if token == '(':
            closing = pos
            while closing < min(end, pos + 8) and tokens[closing] != ')':
                closing += 1
            cast = ' '.join(tokens[pos:closing])
            if closing < end and TYPES.fullmatch(cast):
                child, pos = expression(closing + 1, end, returned, depth + 1, 9)
                left = ('cast', cast, child)
            else:
                left, pos = expression(pos, end, returned, depth + 1)
                if pos >= end or tokens[pos] != ')':
                    raise ValueError('unclosed group')
                pos += 1
        elif token in ('-', '+', '~', '!', '*', '&'):
            child, pos = expression(pos, end, returned, depth + 1, 9)
            left = ('unary', token, child)
        elif re.fullmatch(r'[A-Za-z_$][\w$]*', token):
            left = ('variable', token)
            if pos < end and tokens[pos] == '(':
                args, pos = [], pos + 1
                while pos < end and tokens[pos] != ')':
                    arg, pos = expression(pos, end, returned, depth + 1)
                    args.append(arg)
                    if pos < end and tokens[pos] == ',':
                        pos += 1
                    else:
                        break
                if pos >= end or tokens[pos] != ')':
                    raise ValueError('unclosed call')
                pos += 1
                left = ('call', token, tuple(args))
                if token in ('sqrt', 'sqrtf', '__builtin_sqrt', '__builtin_sqrtf'):
                    add('square_root', returned=returned, offset=matches[start].start())
                elif token not in ('CONCAT44', 'CONCAT22', 'CONCAT11') and len(calls) < 32:
                    calls.append({'name': token, 'offset': matches[start].start(), 'in_return_expression': returned})
        elif re.fullmatch(r'0x[0-9a-fA-F]+|\d+(?:\.\d+)?', token):
            left = ('literal', token)
        else:
            raise ValueError('unsupported expression')
        while pos < end and tokens[pos] in PRECEDENCE and PRECEDENCE[tokens[pos]] >= minimum:
            op, location = tokens[pos], pos
            right, pos = expression(pos + 1, end, returned, depth + 1, PRECEDENCE[op] + 1)
            add(OPERATORS[op], left, right, returned=returned, offset=matches[location].start())
            left = ('binary', op, left, right)
        return left, pos

    # Each bounded expression begins at a return, assignment or condition.
    # There is no inference from function names, comments, literals or prototypes.
    starts = [(n + 1, token == 'return') for n, token in enumerate(tokens) if token in ('return', '=', 'if')][:128]
    for start, returned in starts:
        end = start
        while end < min(len(tokens), start + 256) and tokens[end] not in (';', '{', '}'):
            end += 1
        before = len(observations), len(calls)
        try:
            _, pos = expression(start, end, returned)
            if pos != end:
                raise ValueError('unrecognized expression tail')
        except (ValueError, RecursionError):
            # Don't retain observations from only half of an unsupported expression.
            del observations[before[0]:]
            del calls[before[1]:]
            parse_gaps += 1
    return {'observations': observations, 'calls': sorted(calls, key=lambda r: (r['offset'], r['name'])),
            'returns_expression': any(token == 'return' for token in tokens),
            'conditional_expression_count': tokens.count('if'),
            'coverage': {'bounded': len(text or '') > MAX_CHARS or len(matches) > MAX_TOKENS or len(starts) == 128,
                         'unrecognized_expressions': parse_gaps,
                         'observations_bounded': len(observations) == MAX_OBSERVATIONS}}
