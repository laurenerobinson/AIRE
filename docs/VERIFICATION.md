# Verification report

Reconstruction checks were performed without installing packages or executing
test binaries. No Ghidra UI or model session was started.

| Check | Result |
| --- | --- |
| Recovery archive | All 168 original file hashes verified before migration and after it; original root README also preserved |
| Migration ledger | Every original file accounted for |
| Canonical Java | Exactly 11 active .java files, all under ghidra-plugin/src/main/java/aire; all original hashes match |
| Corpus preservation | All 6 C sources, 8 binaries and 2 original maps retain original SHA-256 |
| Python | Every .py file passes ast.parse; every package/module imports without services or third-party dependencies |
| Dataclass tests | 2 unittest cases pass, checking evidence-list isolation |
| Shell scripts | bash -n checks all three scripts |
| C syntax | gcc -fsyntax-only -Wall -Wextra passes for all 6 sources without HAVE_OPENSSL |
| OpenSSL syntax | Unavailable: openssl/evp.h missing for both crypto fixtures; no packages installed |
| Fixture rebuilds | Both scripts compile, generate maps and strip successfully without OpenSSL; binaries never executed |
| Preserved maps | All 12 aire_test entries match nm; all 12 historical RAPTOR entries differ, retained with explicit warning |
| Corrected RAPTOR map | Generated from preserved debug binary global T symbols with input SHA-256 |
| Active paths | No old /home/kali/devx, /opt Ghidra default or fixed /tmp staging paths remain in active build scripts |
| Ghidra build | Not run: Java 17 only; javac, Gradle and Ghidra unavailable |
| Ollama integration | Source preserved; Ollama unavailable for live validation |

Warnings from original C code: aire_test syntax check reports depth_stack set but
unused and handle_nack's unused parameter. Fallback builds additionally report
unused RAPTOR crypto data/helper definitions when OpenSSL is absent. These do
not prevent compilation and source was left unchanged.

Fixture rebuild outputs went to ignored build/test-corpus, separate from the
preserved assets, and were removed after verification to leave a clean foundation.
This proves local path/build usability for fallback variants, not byte-for-byte
reproduction of the original binaries or successful crypto-path builds.
The Gradle helper/build configuration still requires validation in a compatible
Ghidra installation. There are no automated claims about v1 naming quality,
whole-binary coverage, vulnerability detection or runtime safety.
