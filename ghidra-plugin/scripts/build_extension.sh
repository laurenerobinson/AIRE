#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${GHIDRA_INSTALL_DIR:?Set GHIDRA_INSTALL_DIR to your Ghidra installation}"
if [[ ! -f "$GHIDRA_INSTALL_DIR/support/buildExtension.gradle" ]]; then
  echo "Missing Ghidra support/buildExtension.gradle in $GHIDRA_INSTALL_DIR" >&2
  exit 1
fi
# Let Ghidra generate help and package the module from a clean checkout.
exec gradle --offline -p "$ROOT_DIR" "-PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" buildExtension "$@"
