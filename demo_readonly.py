"""Professor demo: M1 whole-binary facts, one known call, and input integrity."""
import hashlib
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
BINARY = ROOT / "/home/kali/aire/FunctionOverloading.exe"
sys.path.insert(0, str(ROOT / "aire-server/src"))
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(Path.home() / "tools/ghidra"))

from aire.pyghidra.indexer import IndexingError, index_binary


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    print("=== A.I.R.E. READ-ONLY WHOLE-BINARY DEMO ===", flush=True)
    before = sha256(BINARY)
    print(f"SHA-256 BEFORE analysis: {before}", flush=True)

    # M1 imports and statically analyzes the whole binary; it never runs it.
    index = None
    try:
        index = index_binary(BINARY)
    except IndexingError as exc:
        print(f"INDEXING FAILED: {exc}", flush=True)

    whole_binary_ok = False
    control_ok = False
    if index is not None:
        binary = index.binary
        print(f"\nBinary: {binary.path}")
        print(f"Format: {binary.format}")
        print(f"Architecture: {binary.architecture}")
        print(f"Compiler: {binary.compiler_spec}")
        print(f"Image base: {binary.image_base}")
        print(f"Total discovered functions: {len(index.functions)}")
        print(f"Decompiled functions: {sum(bool(f.decompiled_text) for f in index.functions)}")
        for label, kind in [("Strings", "STRING"), ("Imports", "IMPORT"), ("Exports", "EXPORT")]:
            print(f"{label}: {sum(a.type == kind for a in index.artifacts)}")
        direct_calls = [edge for edge in index.function_edges if edge.edge_type == "CALL"]
        print(f"Direct call relationships: {len(direct_calls)} (callsite records)")

        # Confirm completed analysis and coverage of Ghidra's discovered functions.
        whole_binary_ok = (
            index.metadata.get("analysis_completed") is True
            and len(index.functions) > 1
            and len(index.functions) == index.metadata.get("ghidra_function_count")
            and binary.sha256 == before
        )
        print(f"Ghidra function count: {index.metadata.get('ghidra_function_count')}")
        print("\nSample of discovered internal functions:")
        preferred = ["main", "initialize_app", "print_banner", "process_input",
                     "validate_input", "calculate_checksum", "transform_input"]
        for name in preferred:
            for function in index.functions:
                if function.current_name == name and not function.is_external:
                    print(f"  {function.current_name} @ {function.address}")

        # GROUND_TRUTH.md: process_input calls validate_input (also in the C source).
        # Resolve edge endpoints by their real FunctionRecord IDs, not guessed addresses.
        print("\n=== CONTROL TEST ===")
        print("Ground truth expected:\nprocess_input -> validate_input")
        functions_by_id = {f.function_id: f for f in index.functions}
        for edge in direct_calls:
            caller = functions_by_id.get(edge.caller_function_id)
            callee = functions_by_id.get(edge.callee_function_id)
            if (caller is not None and callee is not None
                    and not caller.is_external and not callee.is_external
                    and caller.current_name == "process_input"
                    and callee.current_name == "validate_input"
                    and edge.callsite_address):
                print("\nA.I.R.E. recovered:")
                print(f"{caller.current_name} @ {caller.address}")
                print("    calls")
                print(f"{callee.current_name} @ {callee.address}")
                print(f"    at callsite {edge.callsite_address}")
                control_ok = True
                break
        print(f"\nCONTROL RESULT: {'PASS' if control_ok else 'FAIL'}")
        if index.warnings:
            print(f"\nIndexer warnings ({len(index.warnings)}):")
            for warning in index.warnings:
                print(f"  {warning}")

    # Independently compare the on-disk bytes after analysis, including on failure.
    print("\n=== READ-ONLY VERIFICATION ===")
    unchanged = False
    try:
        after = sha256(BINARY)
        unchanged = before == after
        print(f"Before:\n{before}\n\nAfter:\n{after}")
        print("\nBinary modified: NO" if unchanged else "\nFAILURE: Binary modified: YES")
    except OSError as exc:
        print(f"FAILURE: Cannot verify binary integrity: {exc}")
    print("Target executed: NO")

    print("\n=== DEMO RESULT ===")
    print(f"Whole-binary indexing: {'PASS' if whole_binary_ok else 'FAIL'}")
    print(f"Known control recovered: {'PASS' if control_ok else 'FAIL'}")
    print(f"Binary unchanged: {'PASS' if unchanged else 'FAIL'}")
    print("Target execution: NONE")
    return 0 if whole_binary_ok and control_ok and unchanged else 1


if __name__ == "__main__":
    sys.exit(main())
