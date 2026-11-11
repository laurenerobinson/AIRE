# M9 — VirtualBox stability investigation

Read-only investigation from inside the guest (2026-11-11). **No host or guest setting was
changed** (the only service action was the user-approved, since-resumed tracker pause).
Host-side items below are recommendations for the user.

## Evidence

| Observation | Source |
|---|---|
| Guest repeatedly frozen as a whole: `rcu_preempt kthread starved for 95403 jiffies` (~95 s); clocksource gaps of 1.2, 3.6, 25.3, 64.5 and **392.7 s** in the current boot; 21 RCU stall/starvation messages | `journalctl -k -b 0` |
| Same signature in every recorded boot: max clocksource gaps 12,810 s (boot −3), 29,291 s (boot −2), 124 s (boot −1). Multi-hour gaps mean the host slept/suspended with the VM running | `journalctl -k -b -N` |
| The 2026-11-10 "unexpected shutdown": boot −1 ends at 16:07:21 mid-activity with **no shutdown sequence, panic, OOM or I/O error** logged → the VM was stopped from outside (host power-off/crash/kill), not a guest failure | `journalctl -b -1` |
| Benchmark freeze detector: up to 1,373 s frozen within a single 1,627 s analysis; 8 of the first 30 instrumented requests affected | `docs/m9/benchmarks/progress.jsonl` |
| Effect on analysis: frozen decompiler processes exceed the 30 s per-function timeout; before the M9 retry this silently dropped 1–8 functions' decompiled text (see `M9_PERFORMANCE.md`). Fixed by retry; reproduced and verified by freeze injection (`docs/m9/retry_real_verification.json`) | |
| Emulated Intel e1000 NIC repeatedly logs `e1000_watchdog hogged CPU for >10000us` | kernel log, all boots |
| Guest: 4 vCPU (1 thread/core), 22.9 GiB RAM, 25 GB SATA/AHCI virtual disk reported rotational (94 % full), paravirtualization = KVM interface, Guest Additions 7.2.14 (matches VirtualBox 7.2.14) | `lscpu`, `/proc/meminfo`, `lsblk`, `modinfo` |
| Host CPU: Intel Core Ultra 7 155H (laptop hybrid CPU: performance, efficient and low-power-efficient cores) | `lscpu` model name |

A.I.R.E.'s measured needs: peak ~3.2 GB RSS for the full Ghidra test suite; ~1.1 GB worker
peak for the professor PE; ~2.4 GB for sleigh.exe/decompile.exe (+ native decompilers,
~25–40 MB each).

## Recommendations (host side — require the user; none applied)

1. **Power (most likely cause).** Run on AC power; set the host power mode to best
   performance; disable sleep, hibernate and lid-close sleep while the VM is running
   benchmarks or the demo. The multi-hour gaps and the abrupt end of boot −1 match host
   sleep/power events.
2. **Guest RAM.** 22.9 GiB is far above A.I.R.E.'s ~3–4 GB need. If the host has 32 GB or
   less, reduce the guest to **8–12 GiB** so the host never pages guest memory (host paging
   produces exactly these whole-guest stalls). Keep ≥ 8 GB free for the host OS.
3. **vCPUs.** 4 is appropriate (A.I.R.E. uses up to 4 decompiler processes). On a hybrid
   laptop CPU, keep 4–6 and avoid allocating more than the performance-core count. If the
   host is Windows, exclude VirtualBox from power throttling / efficiency mode so its
   threads are not parked on efficiency cores when the window is unfocused.
4. **Hypervisor backend (Windows hosts).** If the VirtualBox VM log reports the Windows
   Hypervisor Platform / NEM backend (green-turtle icon), VirtualBox runs on top of
   Hyper-V, which is markedly slower and stall-prone. Removing it requires disabling
   Hyper-V/VBS features (a security trade-off for the user to decide).
5. **Storage.** Grow the virtual disk to ≥ 60 GB (currently 94 % full); keep the VDI on the
   internal SSD; tick *Solid-state drive* and enable *Use Host I/O Cache* on the SATA
   controller.
6. **Network (minor).** Switch the adapter type from Intel e1000 to *Paravirtualized
   Network (virtio-net)* to remove the e1000 watchdog CPU hogging.
7. **Keep** the KVM paravirtualization interface and the matching Guest Additions.

## Guest-side mitigations already in A.I.R.E.

- Timed-out decompilations are retried once serially; unrecovered ones are explicitly
  listed as incomplete (never silently dropped).
- The benchmark harness records detected freeze time per request; raw and freeze-adjusted
  results are reported separately (`progress.jsonl` keeps raw wall times; summaries label
  adjusted values).
- The analysis watchdog (`AIRE_ANALYSIS_TIMEOUT`, default 3600 s) bounds a hung job.
