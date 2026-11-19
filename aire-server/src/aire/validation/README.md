# Validation

**Implemented (M9): static structural validation.** `pe_structure.validate_pe`
parses DOS/PE signatures, the optional header, section table and import
directory from bytes. It returns a `PeReport` with issues and an analysis level
(`full` / `partial` / `none`). Upload intake (`aire.api.binary_library.inspect_binary`)
and chat structural answers (`aire.analysis.file_structure.assess`) both use it.
Nothing is executed or mapped.

**Not implemented: dynamic validation.** This package was originally reserved
for optional dynamic validation, planned for M10. M10 shipped static assembly
intelligence instead (2026-11-19 audit). No execution, sandbox, emulator,
exploitation or runtime-validation API exists. Any future execution requires
explicit analyst approval, authorization to test the binary, and an isolated
environment.
