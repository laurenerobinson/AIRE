# M7 rules

Exactly two registered built-ins, both version 1.0.0:

- AIRE-CWE-120-UNBOUNDED-COPY: strcpy only → CWE-120.
- AIRE-CWE-242-DANGEROUS-API: gets only → CWE-242.

These emit static SIGNAL findings, never confirmed vulnerabilities or automatic
CANDIDATE escalation. memcpy is deliberately not classified as unsafe.
See docs/M7_SECURITY_RULES.md at the repository root for exact prerequisites,
import-named-thunk limitations, failure handling and evidence contracts.
