#!/usr/bin/env bash
set -euo pipefail

cd "$HOME/aire"

export GHIDRA_INSTALL_DIR="$HOME/tools/ghidra"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PYTHONPATH="$PWD/aire-server/src"

PYTHON="$PWD/aire-server/.venv/bin/python"

ELF="tests/fixtures/simple_elf/aire_test_binary"
PROF_ELF="professor_samples/function_overloading_elf/original/FunctionOverloading"
PE="professor_samples/function_overloading/original/FunctionOverloading.exe"

echo
echo "============================================================"
echo "              A.I.R.E. STATIC ANALYSIS DEMO"
echo "       ELF + Windows PE + Disassembly Cross-Check"
echo "============================================================"
echo
echo "IMPORTANT: analyzed binaries are NEVER executed."
echo

echo "------------------------------------------------------------"
echo "[1] TARGET FORMAT CHECK"
echo "------------------------------------------------------------"

echo
echo "[Small ELF]"
file "$ELF"

echo
echo "[Professor ELF]"
file "$PROF_ELF"

echo
echo "[Professor Windows PE]"
file "$PE"

echo
echo "------------------------------------------------------------"
echo "[2] SHA-256 BEFORE ANALYSIS"
echo "------------------------------------------------------------"

ELF_HASH_BEFORE=$(sha256sum "$ELF" | awk '{print $1}')
PROF_ELF_HASH_BEFORE=$(sha256sum "$PROF_ELF" | awk '{print $1}')
PE_HASH_BEFORE=$(sha256sum "$PE" | awk '{print $1}')

echo "Small ELF:     $ELF_HASH_BEFORE"
echo "Professor ELF: $PROF_ELF_HASH_BEFORE"
echo "Professor PE:  $PE_HASH_BEFORE"

echo
echo "------------------------------------------------------------"
echo "[3] A.I.R.E. — SMALL ELF ANALYSIS"
echo "------------------------------------------------------------"

"$PYTHON" -m aire.pyghidra.indexer "$ELF"

echo
echo "------------------------------------------------------------"
echo "[4] A.I.R.E. — PROFESSOR ELF ANALYSIS"
echo "------------------------------------------------------------"

"$PYTHON" -m aire.pyghidra.indexer "$PROF_ELF"

echo
echo "------------------------------------------------------------"
echo "[5] A.I.R.E. — PROFESSOR WINDOWS PE ANALYSIS"
echo "------------------------------------------------------------"

"$PYTHON" -m aire.pyghidra.indexer "$PE"

echo
echo "------------------------------------------------------------"
echo "[6] FUNCTION CROSS-CHECK TESTS"
echo "------------------------------------------------------------"

"$PYTHON" -m unittest discover \
    -s aire-server/tests \
    -p 'test_*crosscheck*.py' \
    -v

echo
echo "------------------------------------------------------------"
echo "[7] APPLICATION RELEVANCE TESTS"
echo "------------------------------------------------------------"

"$PYTHON" -m unittest discover \
    -s aire-server/tests \
    -p 'test_application_relevance.py' \
    -v

echo
echo "------------------------------------------------------------"
echo "[8] SHA-256 AFTER ANALYSIS"
echo "------------------------------------------------------------"

ELF_HASH_AFTER=$(sha256sum "$ELF" | awk '{print $1}')
PROF_ELF_HASH_AFTER=$(sha256sum "$PROF_ELF" | awk '{print $1}')
PE_HASH_AFTER=$(sha256sum "$PE" | awk '{print $1}')

echo "Small ELF:     $ELF_HASH_AFTER"
echo "Professor ELF: $PROF_ELF_HASH_AFTER"
echo "Professor PE:  $PE_HASH_AFTER"

echo
echo "------------------------------------------------------------"
echo "[9] INTEGRITY RESULTS"
echo "------------------------------------------------------------"

if [[ "$ELF_HASH_BEFORE" == "$ELF_HASH_AFTER" ]]; then
    echo "Small ELF unchanged:      PASS"
else
    echo "Small ELF unchanged:      FAIL"
fi

if [[ "$PROF_ELF_HASH_BEFORE" == "$PROF_ELF_HASH_AFTER" ]]; then
    echo "Professor ELF unchanged:  PASS"
else
    echo "Professor ELF unchanged:  FAIL"
fi

if [[ "$PE_HASH_BEFORE" == "$PE_HASH_AFTER" ]]; then
    echo "Professor PE unchanged:   PASS"
else
    echo "Professor PE unchanged:   FAIL"
fi

echo
echo "============================================================"
echo "                  DEMO ANALYSIS COMPLETE"
echo "============================================================"
echo
echo "A.I.R.E. demonstrated:"
echo "  [✓] Linux ELF static analysis"
echo "  [✓] Windows PE static analysis"
echo "  [✓] PyGhidra/Ghidra indexing"
echo "  [✓] Function recovery"
echo "  [✓] Assembly extraction"
echo "  [✓] Decompiler extraction"
echo "  [✓] Direct CALL relationships"
echo "  [✓] Application relevance"
echo "  [✓] Assembly/decompiler cross-check tests"
echo "  [✓] Binary integrity preservation"
echo
echo "No analyzed target was executed."
echo
