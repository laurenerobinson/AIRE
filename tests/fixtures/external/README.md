# External static benchmark fixtures

11 original binaries with 11 original C/C++ translation units from angr/binaries.
Nothing was rebuilt, stripped locally, or executed. All original upstream bytes
are pinned and protected by SHA-256 and Git blob identities in manifest.json.
Imported files are ordinary non-executable data files; supplied build recipes are
inert provenance only. See docs/EXTERNAL_BINARY_BENCHMARKS.md at the repository
root for audit, exclusions, compatibility results, and reproduction instructions.

Run `python3 scripts/validate_external_fixtures.py` from the repository root for
offline checks. Perform binary inspection through your restricted environment.
The negative DLL deliberately carries a non-UTF-8 forwarded-export string; its
accuracy scope is the local C function and raw export metadata. No ordinary DLL
behavior is asserted. No exact source/build reproducibility claim is made for
any sample. Source and instruction evidence corroborate application behavior.

The eight ELF files include seven with symbols and one stripped C PIE. They are
not paired stripped/unstripped outputs of one build. Existing AIRE paired ELF
fixtures remain available and unchanged. Upstream licenses and directory-specific
exceptions are retained under angr/; these fixtures do not relicense AIRE.
