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
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "professor_samples/function_overloading"
SOURCE = ROOT / "FunctionOverloading.exe"
TARGET = SAMPLE / "original/FunctionOverloading.exe"
EXPECTED = "cfc8c5f031587c721d680d3dd9bd94bbc690667acf8651403fb8c7e70f2fab07"
STRINGS = ("square of integer ", "square of double ", "PAUSE")
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
                    # This constant's address is pinned to the verified sample hash.
                    address = program.getAddressFactory().getAddress("00419b70")
                    raw = bytes(int(program.getMemory().getByte(address.add(i))) & 255 for i in range(8))
                    return strings, thunks, metadata, raw
                finally:
                    program.release(consumer)


def direct_callers(index, function):
    by_id = {f.function_id: f for f in index.functions}
    return [(by_id[e.caller_function_id], e.callsite_address)
            for e in index.function_edges
            if e.edge_type == "CALL" and e.callee_function_id == function.function_id]


RULE = "=" * 72
STARTUP = [("004113ca", ["004113ca"]), ("004130d0", ["004130d3"]),
           ("00412d50", ["00412d58"]), ("00412d70", ["00412ec2"]),
           ("00413040", ["00413059"]), ("00411325", ["00411325"])]


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


def present(index, strings, thunks, info, constant, overloads, caller, full):
    """Render verified facts only; never modify the index or Ghidra program."""
    binary = index.binary
    by_address = {f.address: f for f in index.functions if not f.is_external}
    counts = {kind: sum(a.type == kind for a in index.artifacts)
              for kind in ("STRING", "IMPORT", "EXPORT")}
    section(2, "Binary Overview")
    for label, value in [("Format", "PE32"), ("Architecture", "x86 32-bit"),
                         ("Platform", "Windows"), ("Image base", binary.image_base),
                         ("Compiler spec", binary.compiler_spec)]:
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
        field("Ghidra version", index.metadata.get('ghidra_version'))
        field("EXPORT artifacts", counts['EXPORT'])
        print("      The EXPORT artifact is entry; the PE export directory is empty.")
        print("      Counts include runtime functions and thunks.")
    print("\n    Addresses use the preferred image base; Windows ASLR may relocate them.")

    for number, (function, value, label, sites, meaning) in enumerate([
        (overloads[0], STRINGS[0], "square(int)", ["0041267f", "00412682"],
         "32-bit integer argument multiplied by itself; result in EAX."),
        (overloads[1], STRINGS[1], "square(double)", ["00412727", "0041272c"],
         "64-bit double multiplied by itself using SSE2.")], start=3):
        section(number, f"Overload #{number - 2} - {label}")
        print(f"    Function: {function.current_name} @ {function.address}")
        print("\n    Recovered behavior:")
        if number == 3:
            for line in function.decompiled_text.splitlines():
                if line.strip().startswith("return "):
                    print("      " + line.strip())
        else:
            print("      input * input (double precision; plain-English summary)")
        print("\n    Key assembly:")
        show_lines(function, sites, compact=True)
        print(f"\n    Meaning: {meaning}")
        string = next(s for s in strings if s['value'] == value)
        print("    String evidence:")
        for ref in string['xrefs']:
            print(f'      "{value}" referenced at {ref["from"]}')
        print("    Status: VERIFIED")
        if full:
            print("\n    Ghidra signature (inferred, not original source):")
            block(function.signature)
            print("    Exact string xrefs:")
            for ref in string['xrefs']:
                print(f"      {string['address']} <- {ref['from']} ({ref['type']})")
                print(f"      Instruction: {ref['instruction']}")
            print("    Direct CALLs to body: none. Verified incoming thunk JMPs:")
            for thunk in (t for t in thunks if t['target'] == function.address):
                print(f"      {thunk['address']}: {thunk['instruction']}")
                for source, site in direct_callers(index, by_address[thunk['address']]):
                    print(f"      {source.current_name} @ {source.address}")
                    print(f"        CALL @ {site} -> {thunk['address']}")
            print("\n    Full decompiler body:")
            block(function.decompiled_text)
            print("\n    Complete bounded assembly:")
            block(function.assembly)

    section(5, "Common Caller / main Candidate")
    print(f"    Main candidate: {caller.current_name} @ {caller.address}")
    print(f"\n      {caller.current_name}")
    for function, label, branch in [(overloads[0], "square(int)", "|--"),
                                     (overloads[1], "square(double)", "`--")]:
        for thunk in (t for t in thunks if t['target'] == function.address):
            for source, site in direct_callers(index, by_address[thunk['address']]):
                if source.address == caller.address:
                    print(f"        {branch} CALL {site} -> thunk -> {label}")
    print("\n    Evidence:")
    print("      - Passes 7: PUSH 0x7 at 004127b8")
    print(f"      - Passes {struct.unpack('<d', constant)[0]}: double at 00419b70")
    print("      - Calls both recovered overloads through jump thunks")
    print('      - Calls system("PAUSE"); returns zero')
    print("      - Reachable from the CRT invoke_main path")
    print("\n    Main identification: STRONGLY SUPPORTED (inferred)")
    print("    Original main symbol unavailable; Ghidra name unchanged.")
    if full:
        print("\n    Exact caller instructions / argument and return evidence:")
        show_lines(caller, ["004127b8", "004127ba", "004127f5", "00412802", "0041280f",
                            "00412857", "0041285c", "0041286c"])
        print(f"      00419b70: {constant.hex(' ')} = IEEE-754 double 7.5")
        print("\n    Startup chain (library names are Ghidra matches):")
        for address, sites in STARTUP:
            print(f"      {by_address[address].current_name} @ {address}")
            show_lines(by_address[address], sites)
        print("\n    Caller signature (inferred):")
        block(caller.signature)
        print("\n    Full caller decompiler body:")
        block(caller.decompiled_text)
        print("\n    Complete bounded caller assembly:")
        block(caller.assembly)

    section(6, "Important Constraints")
    print("    Execution constraints:")
    print("      - Windows PE32; not native Kali")
    print("      - Windows x86 support and compatible MSVC debug runtimes required")
    print("      - Use an isolated Windows VM and official Visual Studio/SDK libraries")
    print("      - Standard release VC++ Redistributable omits the debug runtime DLLs")
    print("\n    Imported DLLs:")
    dlls = sorted({a.value.split("::", 1)[0] for a in index.artifacts if a.type == "IMPORT"})
    for dll in dlls:
        print(f"      {dll}")
    pdb_missing = any("Could not find an appropriate PDB" in w for w in index.warnings)
    print("\n    Analysis constraints:")
    print("      - Matching PDB unavailable" if pdb_missing else
          "      - PDB status: inspect analysis warnings")
    print("      - All four external DLL implementations unavailable to Ghidra")
    print("      - Some decompiler types and ostream arguments are imperfect")
    omitted = sum(w.startswith("Indirect call") for w in index.warnings)
    print("\n    A.I.R.E. limitations:")
    print(f"      - {omitted} indirect callsites intentionally omitted")
    print("      - Thunk JMP edges not persisted in the direct CALL graph")
    print("      - String xrefs supplemented by this demo helper")
    print(f"\n    Warnings: {len(index.warnings)} records; details available with --full")
    if full:
        print("\n    PDB metadata:")
        for label, key in [("File", 'PDB File'), ("GUID", 'PDB GUID'), ("Age", 'PDB Age')]:
            field(label, info.get(key))
        print("\n    Decompiler caveats:")
        print("      float10 models the x87 return; two undefined4 pieces form one double.")
        print("      CONCAT44 and the inferred signature are not recovered C++ declarations.")
        print("      Core arithmetic uses MULSD; MOVSD/FLD transfer the result to x87.")
        print("      Assembly is bounded by M1 limits; the demo bodies are not truncated.")
        print("\n    Analysis warnings (verbatim; includes omitted indirect callsites):")
        for warning in index.warnings:
            block(warning)
            print()
    print("\n    Target execution: NO | Windows execution: PENDING")
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
        require(checksum == f"{EXPECTED}  FunctionOverloading.exe\n", "Checksum baseline differs")
        checks['Integrity baseline'] = 'PASS'
        print("\n    Preserved copy: PASS")
        print("    Recorded baseline: PASS")
        print("    Target execution: NO", flush=True)
        print("\n[Analyzing binary...]", flush=True)
        with quiet_java_banner(), redirect_stdout(sys.stderr):
            index = index_binary(TARGET)
        print("[Recovering functions and references...]", flush=True)
        with redirect_stdout(sys.stderr):
            strings, thunks, info, constant = collect_xrefs()
        analysis_seconds = index.metadata['total_seconds']
        print("[Analysis complete]", flush=True)
        binary = index.binary
        require(index.metadata.get("analysis_completed") and
                index.metadata.get("input_sha256_unchanged") and binary.sha256 == EXPECTED,
                "Index did not complete with verified integrity")
        require(binary.architecture == "x86:LE:32:default" and binary.compiler_spec == "windows",
                "Unexpected architecture/compiler specification")
        checks['PE analysis'] = 'PASS'
        by_address = {f.address: f for f in index.functions if not f.is_external}
        overloads = []
        caller_sets = []
        for value in STRINGS[:2]:
            matches = [s for s in strings if s['value'] == value]
            require(len(matches) == 1, f"Expected one exact string: {value!r}")
            string = matches[0]
            owners = {ref['function'] for ref in string['xrefs'] if ref['function']}
            require(len(owners) == 1, f"Ambiguous string reference owners for {value!r}")
            function = by_address[owners.pop()]
            require(function.decompiled_text and not function.assembly_truncated,
                    "Missing decompilation or incomplete overload assembly")
            overloads.append(function)
            require(not direct_callers(index, function), "Unexpected direct body caller; inspect full index")
            callers = set()
            for thunk in (t for t in thunks if t['target'] == function.address):
                for caller, site in direct_callers(index, by_address[thunk['address']]):
                    callers.add(caller.address)
            caller_sets.append(callers)

        integer, double = overloads
        require(integer.address == "00412620" and double.address == "004126c0", "Unexpected string owners")
        require("IMUL EAX,dword ptr [EBP + 0x8]" in integer.assembly and
                "return param_1 * param_1;" in integer.decompiled_text, "Integer semantics not verified")
        require("MULSD XMM0,qword ptr [EBP + 0x8]" in double.assembly and
                "FLD double ptr" in double.assembly, "Double semantics not verified")
        # Preserve every existing assembly check, including evidence hidden in
        # the default view. Modes affect presentation, never verification.
        show_lines(integer, ["0041267f", "00412682"], visible=False)
        show_lines(double, ["00412727", "0041272c", "00412731", "00412739"], visible=False)
        checks['square(int)'] = checks['square(double)'] = 'VERIFIED'
        common = caller_sets[0] & caller_sets[1]
        require(len(common) == 1, "No unique common caller of the overload thunks")
        caller = by_address[common.pop()]
        require(caller.address == "00412790", "Unexpected common caller")
        show_lines(caller, ["004127b8", "004127ba", "004127f5", "00412802", "0041280f",
                           "00412857", "0041285c", "0041286c"], visible=False)
        value = struct.unpack("<d", constant)[0]
        require(value == 7.5, "Double call argument differs")
        require('system("PAUSE")' in caller.decompiled_text, "Missing system/PAUSE evidence")
        for address, sites in STARTUP:
            show_lines(by_address[address], sites, visible=False)
        checks['common caller'] = checks['exact callsites'] = 'VERIFIED'
        present(index, strings, thunks, info, constant, overloads, caller, full)
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
    for label in ['Integrity baseline', 'PE analysis', 'square(int)', 'square(double)',
                  'common caller', 'exact callsites', 'constraints documented']:
        print(f" {label:<26} {checks.get(label, 'PENDING')}")
    print(f" {'binary unchanged':<26} {'PASS' if unchanged else 'FAIL'}")
    print(f" {'Windows execution':<26} PENDING (not executed)")
    print(f"\n {'DEMO RESULT':<26} {'PASS' if success and unchanged else 'FAIL'}")
    print(RULE)
    return 0 if success and unchanged else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true",
                        help="add exact signatures, full bodies/assembly, thunks, startup and warnings")
    args = parser.parse_args()
    try:
        sys.exit(demonstrate(args.full))
    except OSError as exc:
        print(f"DEMO FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
