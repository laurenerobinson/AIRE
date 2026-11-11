"""Deterministic cryptographic-operation evidence from stored static facts.

Answers "which functions perform encryption/decryption/hashing/signing/
verification/key handling, and how do we know?" without names, models or code
text guesses. Evidence is limited to exact stored facts:

* a call reference (``binary_references.is_call``) from an instruction owned by
  a function to an IMPORT artifact or external function of a known crypto API;
* a direct CALL edge into an import thunk whose stored thunk chain ends at such
  an external function;
* algorithm-identifier strings (e.g. CNG ``"SHA256"``, ``"ChainingModeGCM"``)
  referenced from instructions owned by the same function;
* direct CALL edges from other internal functions into those functions.

Every item carries its source table and stored ID for citation. This is static
evidence of API use, not proof of runtime reachability, correct parameters,
key secrecy or cryptographic strength.
"""
import re

EVIDENCE_VERSION = 1  # part of GUI answer-cache keys

FAMILIES = (
    ('cng', re.compile(r'^BCrypt')),
    ('ncrypt', re.compile(r'^NCrypt')),
    ('cryptoapi', re.compile(r'^Crypt[A-Z]')),
    ('openssl', re.compile(r'^(EVP_|SHA\d+_|SHA\d+$|MD5_?|AES_|RSA_|ECDSA_|EC_KEY_|HMAC|RAND_|PKCS5_)')),
)

# Exact API -> operation category. Unknown APIs in a crypto family are
# reported as 'other' rather than guessed.
OPERATIONS = {
    # Windows CNG (bcrypt.dll)
    'BCryptOpenAlgorithmProvider': 'provider', 'BCryptCloseAlgorithmProvider': 'cleanup',
    'BCryptSetProperty': 'configuration', 'BCryptGetProperty': 'configuration',
    'BCryptGenerateSymmetricKey': 'key_handling', 'BCryptGenerateKeyPair': 'key_handling',
    'BCryptFinalizeKeyPair': 'key_handling', 'BCryptImportKey': 'key_handling',
    'BCryptImportKeyPair': 'key_handling', 'BCryptExportKey': 'key_handling',
    'BCryptDuplicateKey': 'key_handling', 'BCryptDestroyKey': 'cleanup',
    'BCryptDeriveKey': 'key_derivation', 'BCryptDeriveKeyPBKDF2': 'key_derivation',
    'BCryptKeyDerivation': 'key_derivation', 'BCryptSecretAgreement': 'key_agreement',
    'BCryptEncrypt': 'encryption', 'BCryptDecrypt': 'decryption',
    'BCryptCreateHash': 'hashing', 'BCryptHashData': 'hashing', 'BCryptFinishHash': 'hashing',
    'BCryptHash': 'hashing', 'BCryptDuplicateHash': 'hashing', 'BCryptDestroyHash': 'cleanup',
    'BCryptSignHash': 'signing', 'BCryptVerifySignature': 'verification',
    'BCryptGenRandom': 'random',
    # NCrypt (ncrypt.dll)
    'NCryptEncrypt': 'encryption', 'NCryptDecrypt': 'decryption', 'NCryptSignHash': 'signing',
    'NCryptVerifySignature': 'verification', 'NCryptOpenStorageProvider': 'provider',
    'NCryptOpenKey': 'key_handling', 'NCryptCreatePersistedKey': 'key_handling',
    'NCryptFinalizeKey': 'key_handling', 'NCryptImportKey': 'key_handling',
    'NCryptExportKey': 'key_handling', 'NCryptDeleteKey': 'cleanup', 'NCryptFreeObject': 'cleanup',
    # Legacy CryptoAPI (advapi32.dll / crypt32.dll)
    'CryptAcquireContextA': 'provider', 'CryptAcquireContextW': 'provider',
    'CryptReleaseContext': 'cleanup', 'CryptEncrypt': 'encryption', 'CryptDecrypt': 'decryption',
    'CryptCreateHash': 'hashing', 'CryptHashData': 'hashing', 'CryptGetHashParam': 'hashing',
    'CryptDestroyHash': 'cleanup', 'CryptSignHashA': 'signing', 'CryptSignHashW': 'signing',
    'CryptVerifySignatureA': 'verification', 'CryptVerifySignatureW': 'verification',
    'CryptGenKey': 'key_handling', 'CryptImportKey': 'key_handling', 'CryptExportKey': 'key_handling',
    'CryptDeriveKey': 'key_derivation', 'CryptDestroyKey': 'cleanup', 'CryptGenRandom': 'random',
    'CryptProtectData': 'encryption', 'CryptUnprotectData': 'decryption',
}
OPENSSL_PREFIXES = (
    ('EVP_EncryptInit', 'encryption'), ('EVP_EncryptUpdate', 'encryption'), ('EVP_EncryptFinal', 'encryption'),
    ('EVP_DecryptInit', 'decryption'), ('EVP_DecryptUpdate', 'decryption'), ('EVP_DecryptFinal', 'decryption'),
    ('EVP_CipherInit', 'encryption_or_decryption'), ('EVP_DigestSign', 'signing'),
    ('EVP_DigestVerify', 'verification'), ('EVP_PKEY_sign', 'signing'), ('EVP_PKEY_verify', 'verification'),
    ('EVP_Digest', 'hashing'), ('SHA', 'hashing'), ('MD5', 'hashing'), ('HMAC', 'hashing'),
    ('RAND_', 'random'), ('PKCS5_PBKDF2', 'key_derivation'), ('EVP_PKEY_keygen', 'key_handling'),
    ('ECDSA_sign', 'signing'), ('ECDSA_verify', 'verification'), ('RSA_sign', 'signing'),
    ('RSA_verify', 'verification'),
)

# CNG algorithm/property identifiers (stored as UTF-16 strings) and common
# OpenSSL cipher names. Exact matches only.
ALGORITHM_IDENTIFIERS = {
    'AES': 'AES', 'DES': 'DES', '3DES': '3DES', 'RC4': 'RC4', 'RSA': 'RSA', 'DSA': 'DSA',
    'ECDSA_P256': 'ECDSA P-256', 'ECDSA_P384': 'ECDSA P-384', 'ECDSA_P521': 'ECDSA P-521', 'ECDSA': 'ECDSA',
    'ECDH_P256': 'ECDH P-256', 'ECDH_P384': 'ECDH P-384', 'ECDH': 'ECDH',
    'SHA1': 'SHA-1', 'SHA256': 'SHA-256', 'SHA384': 'SHA-384', 'SHA512': 'SHA-512', 'MD5': 'MD5',
    'ChainingModeGCM': 'GCM mode', 'ChainingModeCBC': 'CBC mode', 'ChainingModeECB': 'ECB mode',
    'ChainingModeCCM': 'CCM mode', 'ChainingModeCFB': 'CFB mode', 'ChainingMode': 'chaining-mode property',
    'AuthTagLength': 'authentication-tag property', 'ObjectLength': 'object-length property',
    'HashDigestLength': 'digest-length property', 'KeyLength': 'key-length property',
    'ECCPUBLICBLOB': 'ECC public key blob', 'ECCPRIVATEBLOB': 'ECC private key blob',
    'RSAPUBLICBLOB': 'RSA public key blob', 'RSAPRIVATEBLOB': 'RSA private key blob',
    'aes-128-gcm': 'AES-128-GCM', 'aes-256-gcm': 'AES-256-GCM', 'aes-256-cbc': 'AES-256-CBC',
    'chacha20-poly1305': 'ChaCha20-Poly1305', 'sha256': 'SHA-256',
}
PRIMARY = ('encryption', 'decryption', 'encryption_or_decryption', 'hashing', 'signing',
           'verification', 'key_handling', 'key_derivation', 'key_agreement', 'random')
LIMITATIONS = (
    'Static evidence of crypto API call sites only; runtime reachability and success are not established.',
    'Parameters (keys, nonces, buffer sizes, algorithm handles passed as constants) are not validated.',
    'Calls made through computed pointers without a stored import binding are not attributed.',
    'Statically linked or hand-written crypto without imports/identifier strings is not detected.',
    'Algorithm attribution relies on exact identifier strings referenced by the same function.',
)


def classify_api(name):
    """(family, operation) for an API symbol, or None if not a known crypto API."""
    base = name.rsplit('::', 1)[-1]
    family = next((label for label, pattern in FAMILIES if pattern.search(base)), None)
    if family is None:
        return None
    if base in OPERATIONS:
        return family, OPERATIONS[base]
    if family == 'openssl':
        for prefix, operation in OPENSSL_PREFIXES:
            if base.startswith(prefix):
                return family, operation
    return family, 'other'


def _split(value):
    dll, _, api = value.rpartition('::')
    return (dll or None), api


def crypto_evidence(db, binary_id, limit=100):
    """Build the evidence report from one consistent read-only SQLite snapshot."""
    functions = {row[0]: {'function_id': row[0], 'address': row[1], 'name': row[2],
                          'is_external': bool(row[3]), 'is_thunk': bool(row[4])}
                 for row in db.execute('SELECT function_id,address,current_name,is_external,is_thunk '
                                       'FROM functions WHERE binary_id=? ORDER BY ordinal', (binary_id,))}
    imports, strings = {}, {}
    for artifact_id, kind, address, value in db.execute(
            "SELECT artifact_id,type,address,value FROM artifacts WHERE binary_id=? "
            "AND type IN ('IMPORT','STRING') ORDER BY ordinal", (binary_id,)):
        if kind == 'IMPORT':
            classified = classify_api(value)
            if classified:
                dll, api = _split(value)
                imports[artifact_id] = {'artifact_id': artifact_id, 'address': address, 'api': api, 'dll': dll,
                                        'family': classified[0], 'operation': classified[1], 'called': False}
        elif value in ALGORITHM_IDENTIFIERS:
            strings[artifact_id] = (address, value)
    import_by_address = {row['address']: row for row in imports.values()}
    # External functions carrying a crypto API name, bound to their import row.
    external = {}
    for function in functions.values():
        if function['is_external']:
            row = import_by_address.get(function['address'])
            if row is None and classify_api(function['name']):
                family, operation = classify_api(function['name'])
                row = {'artifact_id': None, 'address': function['address'], 'api': function['name'],
                       'dll': None, 'family': family, 'operation': operation, 'called': False}
            if row is not None:
                external[function['function_id']] = row
    thunk_target = dict(db.execute('SELECT thunk_function_id,target_function_id FROM thunk_relations '
                                   'WHERE binary_id=?', (binary_id,)))

    def resolve_thunk(function_id):
        seen = set()
        while function_id in thunk_target and function_id not in seen and len(seen) < 8:
            seen.add(function_id)
            function_id = thunk_target[function_id]
        return function_id

    per_function = {}

    def add_callsite(function_id, row, callsite):
        caller = functions.get(function_id)
        if caller is None or caller['is_external'] or caller['is_thunk']:
            return
        entry = per_function.setdefault(function_id, {'callsites': {}, 'strings': {}})
        key = (callsite['address'], row['api'])
        entry['callsites'].setdefault(key, {**callsite, 'api': row['api'], 'dll': row['dll'],
                                            'family': row['family'], 'operation': row['operation'],
                                            'import_artifact_id': row['artifact_id']})
        row['called'] = True

    references = db.execute(
        'SELECT reference_id,source_address,target_function_id,target_artifact_id,source_function_id,'
        'source_instruction,is_call,reference_type FROM binary_references WHERE binary_id=? ORDER BY ordinal',
        (binary_id,)).fetchall()
    for reference_id, source, target_fn, target_art, owner, instruction, is_call, kind in references:
        if owner is None:
            continue
        if is_call:
            row = imports.get(target_art)
            if row is None and target_fn is not None:
                row = external.get(resolve_thunk(target_fn))
            if row is not None:
                add_callsite(owner, row, {'address': source, 'instruction': instruction, 'reference_type': kind,
                                          'evidence': 'call reference to import',
                                          'source_table': 'binary_references', 'source_id': reference_id})
        elif target_art in strings:
            entry = per_function.setdefault(owner, {'callsites': {}, 'strings': {}})
            address, value = strings[target_art]
            entry['strings'].setdefault((source, value), {
                'address': source, 'string_address': address, 'value': value,
                'meaning': ALGORITHM_IDENTIFIERS[value], 'instruction': instruction,
                'source_table': 'binary_references', 'source_id': reference_id,
                'artifact_id': target_art})

    edges = db.execute('SELECT caller_function_id,callee_function_id,callsite_address FROM function_edges '
                       'WHERE binary_id=? ORDER BY ordinal', (binary_id,)).fetchall()
    for caller, callee, callsite in edges:
        target = resolve_thunk(callee)
        row = external.get(target)
        if row is not None:
            add_callsite(caller, row, {'address': callsite, 'instruction': None, 'reference_type': 'CALL',
                                       'evidence': 'direct CALL into import thunk chain',
                                       'source_table': 'function_edges',
                                       'source_id': f'{caller}->{callee}@{callsite}'})

    crypto_ids = {fid for fid, entry in per_function.items() if entry['callsites']}
    callers = {}
    for caller, callee, callsite in edges:
        if callee in crypto_ids and caller in functions and not functions[caller]['is_thunk']:
            callers.setdefault(callee, []).append({
                'function_id': caller, 'address': functions[caller]['address'],
                'name': functions[caller]['name'], 'callsite': callsite,
                'source_table': 'function_edges', 'source_id': f'{caller}->{callee}@{callsite}'})

    rows = []
    for function_id in sorted(crypto_ids, key=lambda fid: functions[fid]['address']):
        entry = per_function[function_id]
        callsites = sorted(entry['callsites'].values(), key=lambda c: (c['address'], c['api']))
        operations = sorted({c['operation'] for c in callsites},
                            key=lambda op: (PRIMARY.index(op) if op in PRIMARY else len(PRIMARY), op))
        rows.append({
            **{k: functions[function_id][k] for k in ('function_id', 'address', 'name')},
            'operations': operations,
            'primary_operations': [op for op in operations if op in PRIMARY],
            'apis': sorted({c['api'] for c in callsites}),
            'algorithm_identifiers': sorted({s['meaning'] for s in entry['strings'].values()}),
            'callsites': callsites,
            'identifier_strings': sorted(entry['strings'].values(), key=lambda s: (s['address'], s['value'])),
            'callers': callers.get(function_id, []),
            'provenance': {'source_table': 'functions', 'source_id': function_id,
                           'address': functions[function_id]['address']},
        })
    # Orchestrators: internal functions whose direct callees include crypto functions.
    orchestrators = {}
    for caller, callee, callsite in edges:
        if callee in crypto_ids and caller in functions and caller not in crypto_ids \
                and not functions[caller]['is_thunk']:
            orchestrators.setdefault(caller, set()).add(callee)
    summary_ops = {}
    for row in rows:
        for op in row['operations']:
            summary_ops.setdefault(op, []).append(row['address'])
    imported = sorted(imports.values(), key=lambda r: (r['family'], r['api']))
    return {
        'binary_id': binary_id,
        'summary': {
            'crypto_api_imports': len(imported),
            'crypto_api_imports_called': sum(r['called'] for r in imported),
            'functions_with_crypto_calls': len(rows),
            'operations': {op: addresses for op, addresses in sorted(summary_ops.items())},
            'families': sorted({r['family'] for r in imported}),
        },
        'imports': imported,
        'functions': rows[:limit],
        'truncated': len(rows) > limit,
        'orchestrators': [{'function_id': fid, 'address': functions[fid]['address'],
                           'name': functions[fid]['name'],
                           'calls': sorted(functions[c]['address'] for c in callees)}
                          for fid, callees in sorted(orchestrators.items(),
                                                     key=lambda item: functions[item[0]]['address'])],
        'limitations': list(LIMITATIONS),
    }
