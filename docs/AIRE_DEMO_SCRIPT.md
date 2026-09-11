> Historical demo preserved from v1. Claimed results are presentation examples,
> not measured guarantees. The addresses below belong to an older RAPTOR build.
> Use `tests/binaries/raptor7_aire` and the matching
> `tests/ground_truth/RAPTOR7_PRESERVED_BINARY_FUNCTION_MAP.txt`; account for
> Ghidra image-base relocation. The original map remains in ground_truth.
> Commands below use the historical layout; any optional execution requires
> authorization and isolation. No demo binary was executed during cleanup.
> Confidence is heuristic, not a calibrated probability. Local-only operation
> assumes the configured Ollama endpoint stays on localhost.

# AIRE Demo Script — RAPTOR-7 Presentation
### Audience: Technical / Security Research
### Binary: `raptor7_aire` (stripped) loaded in Ghidra

---

## BEFORE YOU START — Setup Checklist

- [ ] Ghidra open, `raptor7_aire` fully analyzed
- [ ] AIRE plugin loaded and docked (visible panel)
- [ ] Ollama running locally (`ollama serve`)
- [ ] `AIRE_OLLAMA_MODEL` set to your working model (e.g. `gemma3:12b`)
- [ ] `RAPTOR7_FUNCTION_MAP.txt` open in a second window — your cheat sheet
- [ ] Terminal ready to run `./raptor7_aire_debug` for the live crackme demo

---

## OPENING  (~2 minutes)

> "What I'm about to show you is a tool called AIRE — it stands for AI Reverse Engineering.
> The core problem it solves is this: when you strip a binary, every function name disappears.
> Ghidra gives them labels like FUN_0000155c, FUN_00002169 — completely meaningless.
> A human analyst has to read the decompiled code, understand what it does, and rename it.
> On a real binary that could be thousands of functions. That work takes days, sometimes weeks.
>
> AIRE automates the first pass. It looks at the same evidence a human analyst would —
> the decompiled code, the assembly, what functions it calls, what strings it references,
> the shape of the control flow — and it asks a local LLM to suggest a name.
>
> Critically, it runs entirely on your machine. Nothing leaves the box.
> No API keys, no cloud, no data exfiltration risk. That matters in this field."

**[Open Ghidra, show the Symbol Tree — point to the wall of FUN_ labels]**

> "This is raptor7 — a simulated drone tactical control interface.
> I've stripped the binary the way an adversary would before distributing malware,
> or the way firmware ships without debug symbols.
> Every function you see here is anonymous. Let's change that."

---

## SECTION 1 — Test 1: The Crypto Function  (~3 minutes)

**[Navigate to address `0x155c` in Ghidra]**

> "Let's start with something concrete. I'm navigating to a function at address 0x155c.
> Ghidra has labeled it FUN_0000155c. The decompiler output is dense —
> you can see EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal_ex.
> A trained analyst would recognise these as OpenSSL AES calls immediately.
> But imagine you're triaging 800 functions. You don't have time to read every one."

**[Click the function, open AIRE panel, click Suggest]**

> "I'm going to let AIRE read this function. Watch what it does."

**[Wait for result]**

> "AIRE came back with something like `encrypt_mission_payload` or `aes256_cbc_encrypt`
> with a confidence score in the 0.75 to 0.90 range.
>
> Here's what happened under the hood: AIRE extracted the named callees —
> EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal_ex.
> It found string references — 'AES-256-CBC', 'encryption complete'.
> It flagged the usesCrypto signal.
> The confidence score is multiplicative — named callees boost it by 1.25,
> strings boost it by another 1.20. So the model's raw score gets amplified
> because the evidence is genuinely strong.
>
> That's a confident, grounded suggestion — not a guess."

---

## SECTION 2 — Test 2: The Stub  (~2 minutes)

**[Navigate to `0x16c0`]**

> "Now the other extreme. This function at 0x16c0. Three instructions.
> No callees, no strings, one basic block. Returns 1. That's it."

**[Click Suggest]**

> "AIRE says: INSUFFICIENT EVIDENCE.
>
> This is intentional design. The model was explicitly told: if you don't have enough
> to make a grounded suggestion, say so. Don't guess. Don't fabricate.
> A hallucinated name is worse than no name — it misleads the analyst.
>
> In a real workflow, AIRE surfaces the functions it's confident about
> so you can focus human time on the ones it can't name."

---

## SECTION 3 — Test 3: The Large Parser  (~2 minutes)

**[Navigate to `0x1723`]**

> "This one is interesting for a different reason. Navigate to 0x1723.
> This is a GPS telemetry TLV packet parser. Large function —
> nested loops, deep branches, a dozen field-type cases.
> The decompiled output is several thousand characters."

**[Click Suggest]**

> "AIRE has a feature called smart-trim. If the decompiled output is longer
> than 3200 characters, rather than blindly truncating it — which would lose
> the end of the function where returns and cleanup often live —
> it keeps the first two-thirds and the last third, and bridges them.
> The model sees the entry logic and the exit logic, which together usually
> contain the strongest naming signals.
>
> The result: something like `parse_telemetry_packet` or `decode_gps_record`.
> The function was too big to fit in the prompt window, but AIRE still named it correctly."

---

## SECTION 4 — Test 4: The Dispatcher  (~2 minutes)

**[Navigate to `0x2169`]**

> "0x2169 is my favourite for demonstrations because the decompiler output looks
> intimidating — a massive switch statement, fourteen cases.
> ARM, DISARM, TAKEOFF, LAND, RTH, WAYPOINT, EMERGENCY_STOP...
>
> AIRE has a metric called branch ratio — branches divided by basic blocks.
> High branch ratio is a structural signature for dispatchers, parsers, and validators.
> It tells the model: this function routes execution, it doesn't compute."

**[Click Suggest]**

> "AIRE comes back with `dispatch_drone_command` or `handle_c2_command`.
> It didn't just see the switch — it saw the named handler callees,
> the command-type string references, and the structural shape all pointing
> to the same conclusion. High confidence."

---

## SECTION 5 — Test 5: Ambiguous Evidence  (~2 minutes)

**[Navigate to `0x22fc`]**

> "Not every function is straightforward. 0x22fc calls socket(), connect(),
> setsockopt() with SO_REUSEADDR and TCP_NODELAY. Network IO, clearly.
> But the model doesn't know from `socket()` alone whether this is
> a web server, a C2 channel, a DNS client, or something else."

**[Click Suggest]**

> "Watch the suggestion and the confidence score.
> The score should be moderate — the evidence is real but not specific enough
> for maximum confidence. AIRE might suggest `init_c2_uplink` or
> `connect_ground_station` because of the surrounding string references.
>
> This is exactly the calibration we want — AIRE is not overconfident
> when the evidence is ambiguous. The score signals to the analyst:
> this one is worth a second look."

---

## SECTION 6 — Test 6: The Duplicate Pair  (~2 minutes)

**[Navigate to `0x2501`, run AIRE. Then navigate to `0x2784`, run AIRE.]**

> "These two functions are structurally almost identical — both validate
> a drone frame header, check content type, version, length, checksum.
> One is for video frames, one is for telemetry frames.
>
> Run AIRE on each one. The raw model output often comes back
> with very similar candidate names — `validate_frame_header`,
> `check_frame_header`, `verify_frame_header`.
>
> AIRE has a post-processing step that catches this: Levenshtein distance
> deduplication and semantic root comparison. If two candidates are within
> two edits of each other, or share the same root after stripping common
> verb and noun suffixes, it keeps only the highest-confidence one.
>
> The result is a clean list — no redundant near-copies filling the panel."

---

## SECTION 7 — Test 7: The Failure Path  (~1 minute)

> "Test 7 doesn't need a function. It tests what happens when things go wrong
> at the model level — set the `AIRE_OLLAMA_MODEL` environment variable
> to a model name that doesn't exist and run a suggestion.
>
> AIRE will fail to get a response, return an empty list,
> and display a stable user message recommending a better model.
>
> No fabricated names. No crash. No silent failure.
> The analyst sees exactly why nothing came back."

---

## SECTION 8 — Test 8: Full Evidence Showcase  (~3 minutes)

**[Navigate to `0x2a07`]**

> "Last one — and this is the showcase. 0x2a07 is the session establishment
> function for the encrypted C2 uplink.
>
> Look at what AIRE has to work with:
> Named callees — encrypt_mission_payload, dispatch_drone_command,
> parse_telemetry_packet, crc32_compute.
> String references — 'C2 session', 'session key derivation', 'handshake', 'uplink'.
> Both crypto and network IO flags set.
> Multiple basic blocks, branches, a loop."

**[Click Suggest]**

> "AIRE returns `establish_c2_session` — high confidence, 0.85 or better.
> The confidence breakdown in the detail panel shows exactly why:
> model score multiplied by the evidence multiplier — named callees, strings,
> callers, structural complexity — all stacking.
>
> This is the function that ties the entire system together,
> and AIRE names it correctly on the first pass without any human guidance."

---

## CLOSING  (~1 minute)

> "What you've seen today is AIRE working across the full spectrum of what
> a real binary contains — obvious functions, trivial stubs, ambiguous wrappers,
> near-duplicates, large parsers, and high-complexity orchestration functions.
>
> It's not magic. It's structured evidence collection feeding a local LLM
> with a calibrated confidence model that knows when to commit and when to say
> it doesn't know.
>
> The goal isn't to replace the analyst. The goal is to make the analyst
> ten times faster on the first pass — so they spend their time on the
> functions that actually need human attention.
>
> Questions?"

---

## BACKUP TALKING POINTS

**If asked about false positives:**
> "AIRE has an acceptance threshold of 0.55 — anything below that is dropped
> rather than shown. We'd rather show fewer, better names than fill the panel
> with low-confidence guesses. The analyst can always ask again."

**If asked about the LLM choice:**
> "We use a local Ollama model — nothing leaves the machine.
> The best results in testing came from gemma3:12b and mistral:7b.
> Smaller models like 3b parameter models tend to produce more generic names.
> The architecture is model-agnostic — swap the model name and it just works."

**If asked about the confidence score:**
> "It's multiplicative — the model's raw score gets multiplied by an evidence
> multiplier based on what signals were present. Named callees add 25%,
> string references add 20%, callers add 10%. A thin function with no evidence
> gets a 0.75 penalty. The final score is clamped to [0, 1].
> The threshold is 0.55 — below that, we don't show the candidate."

**If the model gives a wrong name:**
> "That's expected and valuable. When AIRE gets it wrong,
> look at the confidence score — it's usually lower on wrong answers.
> The calibration is the point: a 0.90 score should be right 90% of the time.
> If it's wrong at 0.90, that's a signal to improve the evidence extraction,
> not to distrust the whole system."
