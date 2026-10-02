#!/usr/bin/env python3
"""Static, hash-pinned professor demo. No target execution, database or LLM.

Uses the unchanged M1 indexer and a disposable PyGhidra session for string
xrefs/thunks, which M1 does not store. Analysis affects temporary programs only;
neither session saves its program. This script writes only to stdout/stderr
and automatically cleaned temporary Ghidra directories. The default is a concise
professor presentation; --full adds unabridged technical evidence.
"""
import argparse
from contextlib import contextmanager, redirect_stdout
import os
import re
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "professor_samples/function_overloading_elf"
SOURCE = ROOT / "FunctionOverloading"
TARGET = SAMPLE / "original/FunctionOverloading"
EXPECTED = "be3d58ba6ba922f2e8499025dc28a65d9cc97fe5ca6332310ced1622b7e115e3"
STRINGS = ("square of integer ", "square of double ")
sys.path.insert(0, str(ROOT / "aire-server/src"))
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "tools/ghidra"))
if not os.environ.get("JAVA_HOME") and (Path.home() / "tools/jdk-21").is_dir():
    os.environ["JAVA_HOME"] = str(Path.home() / "tools/jdk-21")

from aire.pyghidra.indexer import index_binary, sha256_file


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def collect_xrefs():
    """Read actual references; never identify a function by decompiler text alone.

    Called after index_binary has initialized PyGhidra. Use its existing JVM,
    but an independent disposable project; do not patch the production indexer.
    """
    import pyghidra
    from java.lang import Object
    from ghidra.program.model.data import StringDataInstance

    strings, thunks = [], []
    with tempfile.TemporaryDirectory(prefix="aire_demo_xrefs_") as directory:
        with pyghidra.open_project(directory, "xrefs", create=True) as project:
            with pyghidra.program_loader().project(project).source(str(TARGET)).load() as loaded:
                consumer = Object()
                program = loaded.getPrimaryDomainObject(consumer)
                try:
                    pyghidra.analyze(program)
                    listing = program.getListing()
                    manager = program.getFunctionManager()
                    references = program.getReferenceManager()
                    for data in listing.getDefinedData(True):
                        if not StringDataInstance.isString(data):
                            continue
                        value = str(StringDataInstance.getStringDataInstance(data).getStringValue())
                        if value not in STRINGS:
                            continue
                        refs = []
                        for ref in references.getReferencesTo(data.getAddress()):
                            function = manager.getFunctionContaining(ref.getFromAddress())
                            instruction = listing.getInstructionAt(ref.getFromAddress())
                            refs.append({"from": str(ref.getFromAddress()),
                                         "type": str(ref.getReferenceType()),
                                         "function": str(function.getEntryPoint()) if function else None,
                                         "instruction": str(instruction)})
                        strings.append({"value": value, "address": str(data.getAddress()), "xrefs": refs})
                    for function in manager.getFunctions(True):
                        if not function.isThunk():
                            continue
                        target = function.getThunkedFunction(False)
                        instruction = listing.getInstructionAt(function.getEntryPoint())
                        if target is None or instruction is None:
                            continue
                        # Keep only an independently verified literal jump to this target.
                        if str(instruction.getMnemonicString()) != "JMP":
                            continue
                        if target.getEntryPoint() not in list(instruction.getFlows()):
                            continue
                        thunks.append({"address": str(function.getEntryPoint()),
                                       "target": str(target.getEntryPoint()),
                                       "instruction": str(instruction)})
                    info = program.getOptions("Program Information")
                    metadata = {str(n): str(info.getValueAsString(n)) for n in info.getOptionNames()}
                    # Capture real memory READ references. The caller's instruction
                    # sequence selects the double constant later; no fixed PIE VA.
                    reads = {}
                    memory = program.getMemory()
                    for instruction in listing.getInstructions(True):
                        if "qword ptr" not in str(instruction):
                            continue
                        for ref in instruction.getReferencesFrom():
                            if not ref.getReferenceType().isRead():
                                continue
                            address = ref.getToAddress()
                            block = memory.getBlock(address)
                            if (block is None or not block.isInitialized() or
                                    not block.contains(address.add(7))):
                                continue
                            raw = bytes(int(memory.getByte(address.add(i))) & 255
                                        for i in range(8))
                            reads.setdefault(str(instruction.getAddress()), []).append(
                                {"address": str(address), "raw": raw})
                    # Read ELF64 dynamic metadata from Ghidra's loaded memory.
                    # ET_DYN alone also describes shared libraries; use DF_1_PIE.
                    dynamic = memory.getBlock(".dynamic")
                    if dynamic is not None:
                        for offset in range(0, int(dynamic.getSize()) - 15, 16):
                            raw = bytes(int(memory.getByte(dynamic.getStart().add(offset + i)))
                                        & 255 for i in range(16))
                            tag, value = struct.unpack("<QQ", raw)
                            if tag == 0:
                                break
                            if tag == 0x6ffffffb:  # DT_FLAGS_1
                                metadata["ELF DF_1_PIE"] = str(bool(value & 0x08000000)).lower()
                    interpreter = memory.getBlock(".interp")
                    if interpreter is not None:
                        raw = bytes(int(memory.getByte(interpreter.getStart().add(i))) & 255
                                    for i in range(int(interpreter.getSize())))
                        metadata["ELF interpreter"] = raw.split(b"\0", 1)[0].decode("ascii")
                    return strings, thunks, metadata, reads
                finally:
                    program.release(consumer)


def direct_callers(index, function):
    by_id = {f.function_id: f for f in index.functions}
    return [(by_id[e.caller_function_id], e.callsite_address)
            for e in index.function_edges
            if e.edge_type == "CALL" and e.callee_function_id == function.function_id]


RULE = "=" * 72


@contextmanager
def quiet_java_banner():
    """Filter only Java's exact options announcement, including native stderr.

    Keep the environment/JVM options unchanged. Forward every other line to the
    original stderr, including startup failures and Ghidra diagnostics. Restore
    stderr and drain the pipe even when indexing raises an exception.
    """
    options = os.environ.get("_JAVA_OPTIONS")
    if options is None or "\n" in options or "\r" in options:
        yield
        return
    announcement = b"Picked up _JAVA_OPTIONS: " + os.fsencode(options) + b"\n"
    sys.stderr.flush()
    saved = os.dup(2)
    read_fd, write_fd = os.pipe()

    def forward():
        with os.fdopen(read_fd, "rb") as stream:
            for line in stream:
                if line != announcement:
                    remaining = memoryview(line)
                    while remaining:
                        remaining = remaining[os.write(saved, remaining):]

    reader = threading.Thread(target=forward, name="demo-stderr", daemon=True)
    reader.start()
    try:
        os.dup2(write_fd, 2)
        os.close(write_fd)
        yield
    finally:
        sys.stderr.flush()
        os.dup2(saved, 2)
        reader.join()
        os.close(saved)


def section(number, title):
    print(f"\n[{number}] {title}")


def field(label, value):
    print(f"    {label + ':':<20} {value}")


def block(text, indent="      "):
    # Full evidence is verbatim apart from indentation; do not wrap C or ASM.
    for line in text.strip("\n").splitlines():
        print(indent + line)


def show_lines(function, addresses, *, visible=True, compact=False):
    lines = {line.split(":", 1)[0]: line for line in (function.assembly or "").splitlines()}
    for address in addresses:
        require(address in lines, f"Missing assembly evidence at {address}")
        if not visible:
            continue
        if compact:
            instruction = lines[address].split(": ", 1)[1]
            mnemonic, _, operands = instruction.partition(" ")
            operands = operands.replace("dword ptr ", "").replace("qword ptr ", "")
            print(f"      {address}  {mnemonic:<5} {operands.replace(',', ', ')}")
        else:
            print("      " + lines[address])


def assembly_rows(function):
    return [line.split(": ", 1) for line in (function.assembly or "").splitlines()]


def verify_square(function, floating):
    """Verify the observed ELF argument spill -> reload -> self-multiply idiom.

    These are instruction/data-flow checks, not fixed addresses or names.
    The source return expression corroborates them but never identifies a function.
    """
    rows = assembly_rows(function)
    operation, register, move, width = ("MULSD", "XMM0", "MOVSD", "qword") if floating else (
        "IMUL", "EAX", "MOV", "dword")
    matches = [i for i, (_, instruction) in enumerate(rows)
               if instruction == f"{operation} {register},{register}"]
    require(len(matches) == 1 and matches[0] > 0,
            f"Expected one {operation} self-multiply in {function.address}")
    i = matches[0]
    load = re.fullmatch(rf"{move} {register},({width} ptr \[RBP [^\]]+\])", rows[i - 1][1])
    require(load is not None, f"Cannot trace {operation} operand to a saved argument")
    incoming = "XMM0" if floating else "EDI"
    spill = f"{move} {load.group(1)},{incoming}"
    require(any(instruction == spill for _, instruction in rows[:i - 1]),
            "No matching spill from the ELF parameter register")
    require(re.search(r"return\s+(\w+)\s*\*\s*\1\s*;", function.decompiled_text),
            "Decompiler does not corroborate self-multiplication")
    return [rows[i - 1][0], rows[i][0]]


def verify_call(caller, callee, site):
    instruction = dict(assembly_rows(caller)).get(site, "")
    match = re.fullmatch(r"CALL (0x[0-9a-fA-F]+)", instruction)
    require(match is not None and int(match.group(1), 16) == int(callee.address, 16),
            f"Direct CALL evidence does not match the index at {site}")


def argument_evidence(caller, sites, reads):
    """Only claim values for consecutive, observed SysV register-setup idioms.

    Unsupported/missing bounded evidence remains PENDING. A supported idiom with
    the wrong value fails verification rather than silently accepting the source.
    """
    rows = assembly_rows(caller)
    positions = {address: i for i, (address, _) in enumerate(rows)}
    result = []
    i = positions[sites[0]]
    immediate = re.fullmatch(r"MOV EDI,(0x[0-9a-fA-F]+|[0-9]+)", rows[i - 1][1]) if i else None
    if immediate:
        value = int(immediate.group(1), 0)
        require(value == 7, "Integer call argument differs from 7")
        result.append({"value": value, "sites": [rows[i - 1][0], sites[0]]})
    else:
        result.append(None)
    i = positions[sites[1]]
    if (i >= 2 and rows[i - 1][1] == "MOVQ XMM0,RAX" and
            re.fullmatch(r"MOV RAX,qword ptr \[0x[0-9a-fA-F]+\]", rows[i - 2][1])):
        references = reads.get(rows[i - 2][0], [])
        if len(references) == 1:
            reference = references[0]
            value = struct.unpack("<d", reference['raw'])[0]
            require(value == 7.5, "Double call argument differs from 7.5")
            result.append({"value": value, "sites": [rows[i - 2][0], rows[i - 1][0], sites[1]],
                           "address": reference['address'], "raw": reference['raw']})
        else:
            result.append(None)
    else:
        result.append(None)
    return result


def present(index, strings, thunks, info, overloads, caller, sites, arithmetic, arguments, full):
    """Render verified facts only; never modify the index or Ghidra program."""
    binary = index.binary
    counts = {kind: sum(a.type == kind for a in index.artifacts)
              for kind in ("STRING", "IMPORT", "EXPORT")}
    section(2, "Binary Overview")
    for label, value in [("Format", "ELF"), ("Architecture", "x86-64"),
                         ("Platform / ABI", info.get('ELF Note[required kernel ABI]', 'not recovered')),
                         ("PIE (DF_1_PIE)", info.get('ELF DF_1_PIE', 'not recovered')),
                         ("Image base", binary.image_base),
                         ("Compiler spec", binary.compiler_spec),
                         ("DWARF loaded", info.get('DWARF Loaded', 'not reported'))]:
        field(label, value)
    print()
    for label, value in [("Functions", len(index.functions)),
                         ("Decompiled", sum(bool(f.decompiled_text) for f in index.functions)),
                         ("Strings", counts['STRING']), ("Imports", counts['IMPORT']),
                         ("Direct CALL records", len(index.function_edges))]:
        field(label, value)
    if full:
        print("\n    Technical metadata:")
        field("Ghidra format", binary.format)
        field("Language", binary.architecture)
        field("Compiler ID", info.get('Compiler'))
        field("Compiler comment", info.get('Elf Comment[0]'))
        field("Ghidra version", index.metadata.get('ghidra_version'))
        field("EXPORT artifacts", counts['EXPORT'])
        field("ELF file type", info.get('ELF File Type'))
        field("ELF original base", info.get('ELF Original Image Base'))
        print("      Counts include runtime functions and PLT thunks.")
    print("\n    Addresses use Ghidra's image base; PIE runtime addresses may differ.")

    meanings = ["32-bit integer argument multiplied by itself; result in EAX.",
                "64-bit double multiplied by itself; result returned in XMM0."]
    for i, (function, value, label) in enumerate(zip(overloads, STRINGS,
                                                    ["square(int)", "square(double)"])):
        section(i + 3, f"Overload #{i + 1} - {label}")
        print(f"    Function: {function.current_name} @ {function.address}")
        print("\n    Recovered behavior:")
        for line in function.decompiled_text.splitlines():
            if line.strip().startswith("return "):
                print("      " + line.strip())
        print("\n    Key assembly:")
        show_lines(function, arithmetic[i], compact=True)
        print(f"\n    Meaning: {meanings[i]}")
        string = next(s for s in strings if s['value'] == value)
        print("    String evidence:")
        for ref in string['xrefs']:
            print(f'      "{value}" referenced at {ref["from"]} ({ref["type"]})')
        print("    Status: VERIFIED")
        if full:
            print("\n    Ghidra signature (analysis representation):")
            block(function.signature)
            print("    Exact string xrefs:")
            for ref in string['xrefs']:
                print(f"      {string['address']} <- {ref['from']} ({ref['type']})")
                print(f"      Instruction: {ref['instruction']}")
            print("    Indexed direct CALLs to this body:")
            for source, site in direct_callers(index, function):
                print(f"      {source.current_name} @ {source.address}")
                print(f"        CALL @ {site} -> {function.address}")
            incoming = [t for t in thunks if t['target'] == function.address]
            print("    Incoming jump thunks:", "none" if not incoming else "")
            for thunk in incoming:
                print(f"      {thunk['address']}: {thunk['instruction']}")
            print("\n    Full decompiler body:")
            block(function.decompiled_text)
            print("\n    Complete bounded assembly:")
            block(function.assembly)

    section(5, "Common Caller / main")
    print(f"    Common caller: {caller.current_name} @ {caller.address}")
    print(f"\n      {caller.current_name} @ {caller.address}")
    for i, (label, branch) in enumerate([("square(int)", "|--"), ("square(double)", "`--")]):
        print(f"        {branch} CALL {sites[i]} -> {label} @ {overloads[i].address}")
    print("\n    Argument evidence:")
    for label, argument in zip(["square(int)", "square(double)"], arguments):
        if argument is None:
            print(f"      {label}: PENDING (unsupported or insufficient assembly evidence)")
        else:
            print(f"      {label}: {argument['value']} - VERIFIED")
            show_lines(caller, argument['sites'][:-1], compact=True)
            if 'raw' in argument and full:
                print(f"      {argument['address']}: {argument['raw'].hex(' ')} = double 7.5")
    print("\n    Main identification: VERIFIED symbol + common direct caller")
    print("    Both overloads are called; the body returns zero.")
    print("    Names are recovered by Ghidra; no renaming was performed.")
    if full:
        print("\n    Exact direct callsites:")
        show_lines(caller, sites)
        print("\n    Caller signature (analysis representation):")
        block(caller.signature)
        print("\n    Full caller decompiler body:")
        block(caller.decompiled_text)
        print("\n    Complete bounded caller assembly:")
        block(caller.assembly)
        # A recovered ELF entry body replaces the PE-specific CRT address chain.
        for entry in index.functions:
            if entry.current_name == '_start' and not entry.is_external:
                print(f"\n    Recovered ELF startup: {entry.current_name} @ {entry.address}")
                if entry.decompiled_text:
                    block(entry.decompiled_text)
                if entry.assembly:
                    block(entry.assembly)

    section(6, "Important Constraints")
    print("    Execution constraints:")
    print("      - Static analysis only; runtime behavior has not been tested")
    print("      - ELF x86-64 loader and compatible shared libraries would be required")
    print("      - PIE addresses may be relocated at runtime")
    print("\n    Recovered interpreter:")
    print("      " + info.get('ELF interpreter', 'not recovered'))
    print("    Required libraries (Ghidra ELF metadata):")
    libraries = [v for k, v in sorted(info.items()) if k.startswith('Required Library [')]
    for library in libraries:
        print("      " + library)
    warnings = '\n'.join(index.warnings)
    print("\n    Analysis constraints:")
    if 'not found in project' in warnings:
        print("      - External library implementations are not loaded in the project")
    if 'unresolved symbols' in warnings:
        print("      - External symbols remain unresolved; see --full warnings")
    if 'R_X86_64_COPY' in warnings:
        print("      - Ghidra cannot apply the runtime-copy relocation for std::cout")
    print("      - DWARF/symbols improve names; inferred conventions still need care")
    print("      - Decompiler output is not proof of exact original source or ABI")
    omitted = sum(w.startswith("Indirect call") for w in index.warnings)
    print("\n    A.I.R.E. limitations:")
    print(f"      - {omitted} indirect callsites intentionally omitted")
    print("      - PLT/runtime indirect targets are not added to the direct CALL graph")
    print("      - String xrefs and referenced constant bytes supplemented by this helper")
    print(f"\n    Warnings: {len(index.warnings)} records; details available with --full")
    if full:
        print("\n    Assembly is bounded by M1 limits; the demo bodies are not truncated.")
        print("    Analysis warnings (verbatim; includes omitted indirect callsites):")
        for warning in index.warnings:
            block(warning)
            print()
    print("\n    Target execution: NO")
    print("    No renames, saved Ghidra programs, database access, or LLM calls.")


def demonstrate(full):
    started = time.perf_counter()
    analysis_seconds = None
    checks = {}
    print(RULE)
    print(" A.I.R.E. - Professor Demo")
    print(" C++ Function Overloading Analysis")
    print(RULE, flush=True)
    before = {path: sha256_file(path) for path in (SOURCE, TARGET)}
    section(1, "Integrity Check")
    print("    Original SHA-256:")
    print("    " + before[SOURCE], flush=True)
    success = False
    try:
        require(all(d == EXPECTED for d in before.values()), "Original/copy differs from known hash")
        checksum = (SAMPLE / "original/SHA256SUMS").read_text()
        require(checksum == f"{EXPECTED}  FunctionOverloading\n", "Checksum baseline differs")
        checks['Integrity baseline'] = 'PASS'
        print("\n    Preserved copy: PASS")
        print("    Recorded baseline: PASS")
        print("    Target execution: NO", flush=True)
        print("\n[Analyzing binary...]", flush=True)
        with quiet_java_banner(), redirect_stdout(sys.stderr):
            index = index_binary(TARGET)
        print("[Recovering functions and references...]", flush=True)
        with redirect_stdout(sys.stderr):
            strings, thunks, info, reads = collect_xrefs()
        analysis_seconds = index.metadata['total_seconds']
        print("[Analysis complete]", flush=True)
        binary = index.binary
        require(index.metadata.get("analysis_completed") and
                index.metadata.get("input_sha256_unchanged") and binary.sha256 == EXPECTED,
                "Index did not complete with verified integrity")
        # gcc was observed in the unchanged indexer's initial ELF analysis.
        require(binary.architecture == "x86:LE:64:default" and binary.compiler_spec == "gcc",
                "Unexpected architecture/compiler specification")
        require(binary.format == "Executable and Linking Format (ELF)", "Expected ELF format")
        require(info.get('ELF DF_1_PIE') == 'true', "Expected recovered ELF PIE flag")
        checks['ELF analysis'] = 'PASS'
        by_address = {f.address: f for f in index.functions if not f.is_external}
        overloads = []
        caller_sets = []
        for value in STRINGS:
            matches = [s for s in strings if s['value'] == value]
            require(len(matches) == 1, f"Expected one exact string: {value!r}")
            string = matches[0]
            owners = {ref['function'] for ref in string['xrefs'] if ref['function']}
            require(len(owners) == 1, f"Ambiguous string reference owners for {value!r}")
            function = by_address[owners.pop()]
            require(function.decompiled_text and not function.assembly_truncated,
                    "Missing decompilation or incomplete overload assembly")
            overloads.append(function)
            # ELF calls the bodies directly; jump thunks are not a prerequisite.
            callers = {source.address for source, site in direct_callers(index, function)}
            require(callers, f"No direct caller found for {function.address}")
            caller_sets.append(callers)

        integer, double = overloads
        require(integer.function_id != double.function_id, "Overload xrefs share one body")
        arithmetic = [verify_square(integer, False), verify_square(double, True)]
        checks['square(int)'] = checks['square(double)'] = 'VERIFIED'
        common = caller_sets[0] & caller_sets[1]
        require(len(common) == 1, "No unique common direct caller of the overloads")
        caller = by_address[common.pop()]
        require(caller.decompiled_text and caller.assembly and not caller.assembly_truncated,
                "Missing or truncated common-caller evidence")
        # Resolve by the xrefs/edges first, then corroborate the recovered symbol.
        # No objdump offset or Ghidra image base is assumed for function identity.
        require(caller.current_name == "main", "Common caller does not have the recovered main symbol")
        sites = []
        for function in overloads:
            found = [site for source, site in direct_callers(index, function)
                     if source.function_id == caller.function_id]
            require(len(found) == 1, "Expected one direct callsite per overload in main")
            verify_call(caller, function, found[0])
            sites.append(found[0])
        arguments = argument_evidence(caller, sites, reads)
        # The Linux source has no PAUSE call or MSVC startup/thunk path.
        # Its equivalent evidence is direct calls, argument setup and return zero.
        require('return 0;' in caller.decompiled_text, "Missing main return-zero evidence")
        tail = [instruction for _, instruction in assembly_rows(caller)[-3:]]
        require(tail == ['MOV EAX,0x0', 'POP RBP', 'RET'], "Missing assembly return-zero evidence")
        checks['common caller'] = checks['exact callsites'] = 'VERIFIED'
        checks['input values 7 / 7.5'] = 'VERIFIED' if all(arguments) else 'PENDING'
        present(index, strings, thunks, info, overloads, caller, sites, arithmetic, arguments, full)
        checks['constraints documented'] = 'PASS'
        success = True
    except Exception as exc:
        print(f"DEMO FAILED: {exc}", file=sys.stderr)
    finally:
        section(7, "Integrity Verification")
        try:
            after = {path: sha256_file(path) for path in (SOURCE, TARGET)}
            unchanged = all(before[p] == after[p] == EXPECTED for p in before)
            print("    SHA-256 before (preserved copy):")
            print("    " + before[TARGET])
            print("\n    SHA-256 after (preserved copy):")
            print("    " + after[TARGET])
            print("\n    Original SHA-256 after:")
            print("    " + after[SOURCE])
            print("\n    Original and preserved copy unchanged:", "PASS" if unchanged else "FAIL")
        except OSError as exc:
            unchanged = False
            print(f"Integrity verification FAILED: {exc}", file=sys.stderr)
    print()
    if analysis_seconds is not None:
        print(f"    Analysis time:   {analysis_seconds:.1f} s")
    print(f"    Total demo time: {time.perf_counter() - started:.1f} s")
    print("\n" + RULE)
    for label in ['Integrity baseline', 'ELF analysis', 'square(int)', 'square(double)',
                  'common caller', 'exact callsites', 'input values 7 / 7.5', 'constraints documented']:
        print(f" {label:<26} {checks.get(label, 'PENDING')}")
    print(f" {'binary unchanged':<26} {'PASS' if unchanged else 'FAIL'}")
    print(f" {'Target execution':<26} NO")
    print(f"\n {'DEMO RESULT':<26} {'PASS' if success and unchanged else 'FAIL'}")
    print(RULE)
    return 0 if success and unchanged else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true",
                        help="add exact signatures, full bodies/assembly, xrefs, calls, startup and warnings")
    args = parser.parse_args()
    try:
        sys.exit(demonstrate(args.full))
    except OSError as exc:
        print(f"DEMO FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
