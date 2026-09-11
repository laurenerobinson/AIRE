# A.I.R.E. Ghidra extension

Canonical restored v1 Java extension. All original Java source is unchanged.
Build from repository root with `./ghidra-plugin/scripts/build_extension.sh`
after setting GHIDRA_INSTALL_DIR and configuring the matching JDK/Gradle.
The helper performs an offline Gradle build, including generated help.
The bundled Gson jar is retained. buildTemplate.gradle is historical reference.

See [development](../docs/DEVELOPMENT.md), [current state](../docs/CURRENT_STATE.md),
and [test corpus](../tests/README.md). Placeholder language/help assets remain
from the original Ghidra skeleton and do not implement extra analysis features.
