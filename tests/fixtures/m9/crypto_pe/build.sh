#!/usr/bin/env bash
# Build the M9 CNG crypto fixtures as x86-64 Windows PE (never executed here).
# Toolchain (documented dependency, no root needed):
#   python3 -m venv ~/tools/zig-venv && ~/tools/zig-venv/bin/pip install ziglang==0.13.0
# zig cc bundles MinGW-w64 headers and import libraries (bcrypt, kernel32).
#
# The .exe files contain no COFF symbol table and no embedded debug sections;
# function names exist only in the linker's PDB. The PDB is moved to
# build/<name>.groundtruth.pdb (a name Ghidra will not auto-discover) and is
# read only by scripts/crypto_ground_truth.py, never by A.I.R.E. analysis.
set -euo pipefail
cd "$(dirname "$0")"
ZIG=${ZIG:-"$HOME/tools/zig-venv/bin/python -m ziglang"}
FLAGS="-target x86_64-windows-gnu -O1 -fno-inline-functions -fno-stack-protector"
mkdir -p build
for program in aes_gcm sha256_hash ecdsa_sign; do
  rm -f "$program.exe" "build/$program.groundtruth.pdb"
  $ZIG cc $FLAGS -o "$program.exe" "src/$program.c" -lbcrypt
  mv "$program.pdb" "build/$program.groundtruth.pdb"
  chmod 0444 "$program.exe" "build/$program.groundtruth.pdb"
done
sha256sum aes_gcm.exe sha256_hash.exe ecdsa_sign.exe > SHA256SUMS
(cd build && sha256sum *.groundtruth.pdb > PDB_SHA256SUMS)
$ZIG version > build/TOOLCHAIN.txt
echo "target: x86_64-windows-gnu; flags: $FLAGS" >> build/TOOLCHAIN.txt
cat SHA256SUMS
