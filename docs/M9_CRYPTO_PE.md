# M9 Phase 3 — security-related Windows PE fixtures

Three small x86-64 Windows programs using **Windows CNG (`bcrypt.dll`)**, the standard OS
cryptographic API. No cryptographic algorithm is implemented in the sources. Keys/nonces
are fixed public test values (fixture only). The executables were **never run** (no
Windows/Wine here; target execution is out of policy); behaviour is documented from source.

| Program | Source | Binary SHA-256 | Algorithm | Key functions (ground-truth VA) |
|---|---|---|---|---|
| AES-256-GCM | `tests/fixtures/m9/crypto_pe/src/aes_gcm.c` | `90e403baf7bc7e0faef7258b140a28742436a63ee73bb468b8ed60131b6a0db5` | AES-256-GCM | key setup `0041d080`, encrypt `0041d160`, decrypt `0041d1e0`, cleanup `0041d270`, main `0041d2a0` |
| SHA-256 | `src/sha256_hash.c` | `9c5ac9cd5a76d14515f2558a82c2b103c581ed483e38bc6a96f4742257f438a6` | SHA-256 | input processing `0041d020`, digest `0041d0a0`, output `0041d1a0`, main `0041d350` |
| ECDSA | `src/ecdsa_sign.c` | `d52ad9d02868e6dd532dcb5feb35a855659c9a3044bc86ed9d32ccd47f649c36` | ECDSA P-256 + SHA-256 | keygen `0041d020`, export pub `0041d080`, import pub `0041d0b0`, hash `0041d0e0`, sign `0041d1b0`, verify `0041d1f0`, main `0041d230` |

## Toolchain (documented dependency)

No MinGW cross-compiler or root access was available. `zig cc` from PyPI bundles MinGW-w64
headers and import libraries:

```bash
python3 -m venv ~/tools/zig-venv && ~/tools/zig-venv/bin/pip install ziglang==0.13.0
tests/fixtures/m9/crypto_pe/build.sh     # x86_64-windows-gnu, -O1 -fno-inline-functions
aire-server/.venv/bin/python scripts/crypto_ground_truth.py
```

Notes: zig 0.13's MinGW headers lack the Windows 10 one-shot `BCryptHash` and pseudo-handles,
so `hash_message` uses the classic open/create/hash/finish sequence. The executables contain
no COFF symbols or debug sections; names exist only in the linker PDB, kept as
`build/<name>.groundtruth.pdb` (renamed so Ghidra cannot auto-load it). `zig cc -s` was not
used because it produced a differently linked binary.

## Ground truth

`scripts/crypto_ground_truth.py` parses the PDB (MSF 7.0) procedure records, verifies the
PDB GUID matches each PE's CodeView record, maps every source function to its virtual
address, and records the expected CNG APIs, roles, identifier strings and `main` call
relationships written from the sources → `crypto_pe/GROUND_TRUTH.json`.

## A.I.R.E. evidence mechanism

`aire/security/crypto_evidence.py` (agent tool `crypto_evidence`, GUI card *Crypto
evidence*) uses only stored static facts, no names or model output:
call references from function-owned instructions to crypto IMPORT artifacts (and direct
CALLs into import thunk chains), operation classification per exact API (CNG, NCrypt,
CryptoAPI, OpenSSL), exact CNG/OpenSSL algorithm-identifier strings referenced by the same
function, and direct CALL callers. Each item carries `source_table`/`source_id`.
The GUI's "crypto or hashing" question now seeds retrieval from this evidence.

## Verified results (real pipeline, `docs/m9/pipeline_verification.json`)

- Every ground-truth crypto function found at its exact address with all documented APIs;
  no crypto evidence at any other address (no false positives).
- Operations: AES — key_handling/encryption/decryption/cleanup; SHA-256 — hashing; ECDSA —
  key_handling ×3, hashing, signing, verification, and main's own key/provider cleanup.
- All `main` → crypto-function CALL relationships recovered.
- Identifier strings recovered: `ChainingMode`, `ChainingModeGCM`, `SHA256`, `ECDSA_P256`,
  `ECCPUBLICBLOB`. **Not recovered:** `L"AES"` (3 chars, below Ghidra's default minimum
  string length).
- Fresh analysis 17.8–55.0 s per program (host-freeze affected); cached 0.0014–0.0016 s.
- Opt-in integration test `tests/test_m9_integration.py` re-checks this with real PyGhidra.

## Limitations

Static API-callsite evidence only; no runtime reachability, parameter, key-secrecy or
strength assessment. Statically linked or hand-written crypto without imports/identifier
strings is not detected. Calls via computed pointers without a stored import binding are not
attributed.
