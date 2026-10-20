"""Resolved direct CALL references only; no inferred indirect targets."""
from aire.knowledge.models import FunctionEdge
from aire.pyghidra.extractor import function_id, read_fact
from aire.profiling import profiled


@profiled('call_graph')
def build_call_edges(program, functions, binary, warnings):
    known = {str(f.getEntryPoint()) for f in functions}
    edges = {}
    for function in functions:
        if function.isExternal():
            continue
        caller = function_id(binary, str(function.getEntryPoint()))
        def collect():
            for instruction in program.getListing().getInstructions(function.getBody(), True):
                flow = instruction.getFlowType()
                if not flow.isCall():
                    continue
                site = str(instruction.getAddress())
                if flow.isComputed():
                    warnings.append(f'Indirect call at {site}; omitted from direct-call graph')
                    continue
                resolved = False
                for reference in instruction.getReferencesFrom():
                    if not reference.getReferenceType().isCall():
                        continue
                    target = str(reference.getToAddress())
                    if target in known:
                        callee = function_id(binary, target)
                        edges[(caller, callee, site)] = FunctionEdge(caller, callee, site, 'CALL')
                        resolved = True
                if not resolved:
                    warnings.append(f'Unresolved direct call at {site}; no edge emitted')
        read_fact(warnings, f'Calls from {function.getEntryPoint()} {function.getName()}', collect)
    return list(edges.values())
