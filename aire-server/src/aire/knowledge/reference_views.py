"""Pure views of persisted reference evidence; no Ghidra or target-file reads."""


def require_references(index):
    version = index.metadata.get('reference_facts_version')
    if type(version) is not int or version not in (1, 2):
        raise ValueError('Reference facts are absent; run fresh indexing with include_references=True')


def string_references(index, values):
    require_references(index)
    functions = {function.function_id: function.address for function in index.functions}
    by_artifact = {}
    for reference in index.references:
        if reference.target_artifact_id is not None:
            by_artifact.setdefault(reference.target_artifact_id, []).append({
                'from': reference.source_address, 'type': reference.reference_type,
                'function': functions.get(reference.source_function_id),
                'instruction': reference.source_instruction if reference.source_instruction is not None else 'None',
            })
    return [{'value': artifact.value, 'address': artifact.address,
             'xrefs': by_artifact.get(artifact.artifact_id, [])}
            for artifact in index.artifacts if artifact.type == 'STRING' and artifact.value in values]


def direct_jump_thunks(index):
    require_references(index)
    # Keep the demos' original literal JMP rule, while the core also retains
    # independently reported indirect/external thunk bindings.
    return [{'address': thunk.source_address, 'target': thunk.target_address,
             'instruction': thunk.source_instruction}
            for thunk in index.thunks if thunk.is_direct_jump and thunk.source_instruction
            and thunk.source_instruction.split()[0] == 'JMP']


def referenced_reads(index):
    require_references(index)
    result = {}
    for reference in index.references:
        if reference.is_read and reference.data_hex is not None:
            result.setdefault(reference.source_address, []).append({
                'address': reference.target_address, 'raw': bytes.fromhex(reference.data_hex)})
    return result


def referenced_bytes_at(index, address):
    require_references(index)
    values = {reference.data_hex for reference in index.references
              if reference.target_address == address and reference.data_hex is not None}
    if len(values) != 1:
        raise ValueError(f'No unique stored referenced bytes at {address}')
    return bytes.fromhex(values.pop())
