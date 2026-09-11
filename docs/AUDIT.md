# Archive audit and migration report

## Archive location and preservation

The supplied workspace had no original-devx/ directory. Its extracted archive
was `home/kali/devx/` (168 files, about 7.2 MiB). The root README was a separate,
detailed historical setup document. Before any removal, every archive file and
the root README were saved in `recovery/original-devx.tar.gz`. Every archived
file was verified against its SHA-256 before migration and again afterward.
The archive is intentionally retained as an inactive recovery artifact; it is
not a second active Java source tree or a build input.

[Original inventory](recovery/original-devx-manifest.json) lists every original
file, size and SHA-256. [Migration ledger](recovery/migration.json) accounts for
all 168 files and each destination or removal reason. [Recovery checksum](recovery/SHA256SUMS)
authenticates the bundle. Extract to a separate scratch directory if recovery
is needed, not over the canonical source tree. The bundle includes historical
machine-local configuration and generated files for lossless recovery.

## Canonical and stale Java trees

`aire-ghidra-extension/src/main/java/aire/` is the canonical 11-file extension.
It is selected by the module's Gradle/source layout and manual packaging script,
has Module.manifest, extension.properties, help/resources, Gson and compiled
class/package evidence, and contains the richer v1 feature set. The root README
also identifies this module as canonical. This is source/build evidence of the
working implementation; a fresh live build was not possible here.

`devx/src/main/java/aire/` is a separate 11-file stale implementation without its
own build or extension metadata. Ten same-named Java files differ from the
canonical module. It uses the earlier strict JSON Ollama schema and simpler UI
that applies the top suggestion. Its unique SuggestionChoicesTableModel is
unreferenced in that tree; the canonical UI implements candidate selection as
cards. The canonical tree uniquely includes AirePluginPackage. Older code is
preserved in the recovery bundle, not merged into the working module.

## Build and generated files

- Active `build.gradle`: Ghidra extension hook plus Maven Gson dependency in
  the archive; now uses the supplied Ghidra build script and bundled jar offline.
- `buildTemplate.gradle`: Ghidra reference template retained byte-for-byte.
- `build.gradle.bak`: obsolete alternate hook, removed from active files.
- `data/buildLanguage.xml`, `data/sleighArgs.txt`, and six skel language files:
  retained; the language declaration in skel.ldefs is commented out.
- `scripts/build_extension.sh`: replaced fragile manual javac/zip packaging
  with the canonical Gradle build, so help is generated from source.
- `build_aire_test.sh` and `build_raptor7_aire.sh`: retained as fixture rebuild
  scripts, moved to root scripts/ with repository-relative sources and separate
  output paths. No original Gradle wrapper, settings file or Java test tree found.
- Generated `.gradle/` (4.4.1 and 8.5 caches), `build/` (classes, resource copies,
  help indexes, jars, source zip, compiler state), and `dist/` (14 extension zips)
  removed from the active module only after recovery verification.

## Corpus, demos, Ollama and local clutter

Six C sources moved to tests/source; eight intentional ELF binaries moved to
tests/binaries; two function maps moved unchanged to tests/ground_truth.
The expanded RAPTOR pair and aire_test pair share build IDs within each pair.
The historical RAPTOR map does not match the preserved binary; a separately
named map derived from nm records correct symbol values and binary hash.
See [corpus inventory](../tests/README.md) for every fixture and relationship.

AIRE_DEMO_SCRIPT.md moved to docs with a provenance/limitations banner; its
historical presentation remains intact below that banner. The original root
README is inside the recovery bundle; the module's original README was only
`# Skeleton` and is now replaced by accurate module instructions.

All Ollama Java sources are accounted for: canonical AirePlugin config,
OllamaSuggestionProvider HTTP/prompt/filter implementation, SuggestionProvider
interface and AireSuggestionsProvider error/status UI; the earlier equivalents
are in the recovery archive. No separate Python Ollama runtime existed.

Two editor files were found: model/.NameSuggestion.java.swp and
services/.OllamaSuggestionProvider.java.swo in the stale Java tree. Both removed
from active files. `.claude/settings.local.json` contained obsolete absolute
machine-read permissions and was removed from active files.

The module's nested .git contained HEAD, core config, description, exclude file
and sample hooks, with no objects, refs or commits found. It is preserved inside
the recovery archive and absent from the active module. Workspace-owned root
.git/.agents/.codex directories were not modified.

Absolute local paths found: manual packaging default `/opt/ghidra_12.0.1_PUBLIC`,
shared `/tmp/aire-*` staging directories, generated build/helpconfig pointing to
`/home/kali/devx/...`, and obsolete .claude machine paths. Active scripts no longer
use those paths. `/usr/include/openssl/evp.h` remains an intentional system header
probe, not a repository path. Binary interpreter/DWARF paths remain untouched
inside preserved binaries. The historical README's example paths remain in recovery.

## Changes created

The requested aire-server package contains six dataclasses, all planned module
files, validation/rules documentation, pyproject.toml and two stdlib unit tests.
No runtime functions, ORM, services or M1 indexer are implemented. Root README,
.gitignore, LICENSE-TODO.md, current-state/architecture/roadmap/development docs,
test/integration docs, this audit, verification report, final tree, preservation
manifests and corrected RAPTOR map are new. No blanket executable ignore exists.

## Verification and remaining decisions

See [verification](VERIFICATION.md) for exact checks and limits. All 11 canonical
Java files, six C sources, eight binaries, two original maps and bundled assets
are byte-identical. Of 168 original files, 48 remain byte-identical active files,
6 were intentionally updated, and 114 are removed from active use but recoverable.
No packages were installed, target binaries executed, cloud APIs added, M1
implemented, or commits created.

Owner input is needed for the project license and eventual publication rights.
A compatible Ghidra/JDK/Gradle installation and local Ollama model are needed for
live v1 validation. OpenSSL development headers are needed for the crypto-enabled
fixture rebuild. No decision is required to preserve the stale RAPTOR map: it
is retained with a separately named corrected map.

**Next: M1 — Implement the first READ-ONLY PyGhidra whole-binary indexer.**
The precise acceptance recommendation is in [ROADMAP.md](ROADMAP.md).
