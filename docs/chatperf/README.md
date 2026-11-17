# GUI chat performance

> Historical VM-hosted inference measurements and subsequent deterministic
> fast-path results. Current inference and isolated Chrome run on Windows 11;
> the API and static analysis remain in Ubuntu. No controlled split-host speedup
> has been measured. Follow [current setup](../../README.md#running-aire-with-windows-host-inference)
> and retain the measured conditions/skips below when citing these numbers.

## Baseline (2026-11-11, before Step 1) — `baseline_2026-11-11/`

Profiled `GuiApplication.run_chat` (the `/api/chat` code path) on `demo_artifacts/m9/m9.sqlite` with
`qwen2.5-coder:1.5b` Q4, `num_ctx=4096`, CPU-only on a 4-vCPU VirtualBox guest
(`profile_chat.py`, `cases.json` → `run1.jsonl`, `run1.log`; `vmstat.log`; `stall_test.py` → `stall.jsonl`).
The run was stopped after 7 of 16 cases because of VM freezes.

| Question (binary) | Status | Total | Model calls | VM stall in run |
|---|---|---|---|---|
| encrypt/decrypt + APIs (AES), cold model | partial (timeout) | 539.8 s | 6 | 523 s |
| same, warm | completed, **wrong** function roles | 124.4 s (first text 110 s) | 7 | 97 s |
| Which function hashes the input? (SHA-256) | error (timeout) | 391.7 s | 1 | 388 s |
| Which function signs or verifies…? (ECDSA) | partial (timeout) | 663.6 s | 3 | 640 s |
| Which function encrypts data? (AES) | error (timeout) | 412.2 s | 1 | 403 s |
| What API calls does this function make? (ECDSA) | error (timeout) | 722.2 s | 1 | 721 s |
| What calls this function? (AES) | completed | 0.17 s | 0 | 0 |

Findings:
- Stored-evidence tools take 1–75 ms (`crypto_evidence`) and already hold the correct answers.
- The planner loop re-requested `crypto_evidence` 5–6 times: the 12 KB result never fit `max_planning_chars`, so
  the model never saw it.
- Warm synthesis took 43 s (2,386 prompt tokens at ~85 tok/s prefill + 214 output tokens at ~15 tok/s).
- Guest freezes happen during inference: idle has 0 s of stalls (max tick gap 3 ms); one 4-thread inference
  had 34.7 s of stalls in 40 s.
- The completed model answer named `FUN_00401160`/`FUN_0041d2a0`. The ground truth is `FUN_0041d160`
  (`BCryptEncrypt`) and `FUN_0041d1e0` (`BCryptDecrypt`).

## Step 1 — deterministic intent routing (2026-11-12) — `step1_2026-11-12/`

`aire/agent/fact_answers.py` answers supported factual questions from `crypto_evidence`, `get_callers`/
`get_callees` and the M10 function evidence, rendered with `render_tool_facts`, with no model call.
Benchmark: `scripts/benchmark_chat_fastpath.py` over the real HTTP `/api/chat` NDJSON stream. It used 15
questions × 3 rounds × 2 fresh server processes on `m9.sqlite`, with a model client that fails if called.

| Metric (90 requests) | Result |
|---|---|
| Correct vs `tests/fixtures/m9/crypto_pe/GROUND_TRUTH.json` | 90 / 90 |
| Model calls | 0 |
| First activity event | median 14 ms, p95 28 ms, max 156 ms |
| Complete answer (result packet) | median 26 ms, p95 70 ms, max 256 ms (cold workspace) |
| VM max tick gap during the run | 11 ms |

Regression fixture: `tests/fixtures/chatperf/crypto_pe_index.sqlite` holds real index facts trimmed by
`scripts/export_chat_crypto_fixture.py`; its `crypto_evidence` output and call edges are identical to the full store.
