# VirtualBox stability diagnostics

Investigation: 2026-11-17, America/Chicago (CST, UTC−06:00). Guest: `aire-VirtualBox`.

## Deployment update after the investigation

The current November 17 demonstration uses Windows 11 for isolated Chrome and
Ollama (`qwen2.5-coder:1.5b`), with the Python API, Ghidra/PyGhidra, SQLite and
deterministic assembly/flow/security analysis in Ubuntu. See the
[architecture](ARCHITECTURE.md) and [launch workflow](../README.md#running-aire-with-windows-host-inference).
GUI responsiveness reportedly improved after moving Chrome and inference off
the guest. This is an operator observation, **not a benchmark or measured speedup**.
The split reduces resource contention inside the VM; it does not automatically
resolve VM scheduling, timer, kernel or host power-management problems.

The original VM resource allocation was excessive relative to recorded needs:
the M9/hardening configuration exposed about 23 GiB RAM and four vCPUs, and
this diagnostic boot exposed 15 vCPUs and 25.82 GiB usable RAM. Earlier measured
analysis peaks were about 3–4 GB. These are separate historical observations;
the final Windows allocation and host headroom have not been independently
verified. Nearly full guest storage (97–99% in the recorded runs) remains a
capacity risk; moving inference does not prove disk space was reclaimed.

The historical Windows VirtualBox **NEM / Windows Hypervisor Platform performance
limitation** is recorded as a possible backend issue in
[M9 stability notes](M9_VIRTUALBOX_STABILITY.md). No corresponding host VBox.log
was supplied here to establish the backend or its contribution to these stalls.
Do not present NEM as the proven cause of every observed pause or infer that
moving Chrome/Ollama disabled it. The original diagnostic evidence below is
preserved with its original host-visibility limits.

## Assessment

**The freezes affect guest kernel scheduling, beyond A.I.R.E. application threads. The specific underlying cause remains unconfirmed without host telemetry and VBox.log.** The strongest candidates are VirtualBox/host vCPU scheduling or virtual interrupt/timer delivery, including a guest-kernel/VirtualBox interaction. Guest RAM exhaustion and ordinary guest CPU saturation have little supporting evidence. The nearly full root filesystem is a separate, confirmed capacity problem that needs remediation, but its causal connection to the long freezes is unproven.

This qualifies the definitive “host-level VM descheduling” attribution in [M10_SECURITY_HARDENING.md](M10_SECURITY_HARDENING.md). Missing guest CPU accounting and idle percentages alone cannot establish a host cause or rule out a kernel/virtual-device problem. No host operating system is assumed.

Only this report was added to the repository. No application code, databases, models, persistent VM/service configuration, or existing project files were changed. No cleanup, stress test, crash reproduction, inference, commit, or push was performed. Diagnostic output was written under `/tmp`.

**Diagnostic side effect and correction:** the first `timedatectl timesync-status` query appears to have D-Bus-activated systemd-timesyncd at 14:24:04. The installed `vboxadd-service.service` explicitly declares `Conflicts=systemd-timesyncd.service`, so VBoxService stopped. This was initially misidentified as unrelated activity; the unit files and matching timestamps identify a likely query side effect. After discovering it, the original runtime service combination was restored at **14:35:55** with `systemctl --no-ask-password start vboxadd-service.service`; readback confirmed VBoxService active/running and timesyncd inactive/dead. No enablement or configuration files changed. The temporary NTP synchronization already affected clock discipline and cannot be retroactively undone. The main passive run occurred while VBoxService was stopped, a material confounder. For future read-only inspection, prefer `systemctl show`, unit files, and existing journal messages over activating D-Bus time-service queries.

## Evidence scope and changes between observations

The current boot is `ac57731a6a524a32851b131c1bfc4418`, beginning at 14:19 CST. The hardening boot was `1b802554c5ba4d6cb19eabbb8d8a9ab8`, 11:59–14:01 CST. These are different operating conditions:

| Measurement | Earlier hardening evidence | Current investigation |
| --- | --- | --- |
| Guest CPUs | 4 vCPUs; raw monitor headers confirm 4 | 15 online vCPUs, IDs 0–14; monitor affinity permits all 15 |
| Guest RAM | Prior report: approximately 23 GB | `MemTotal=27,724,406,784` bytes, 25.82 GiB usable; configured host-side allocation still needs confirmation |
| Kernel | Crash header and prior-boot traces: `7.0.0-42-generic` | `7.0.0-43-generic`, PREEMPT_DYNAMIC |
| Root free space | Reported approximately 255 MB, 99% used | Initially 715 MiB, 97%; final sample about 705 MiB, 98% (background activity and rounding) |
| Crash artifact | Reported approximately 396 MB unittest crash | That path is absent; a separate 133,194,744-byte Python crash remains |
| Time services | Exact previous-boot configuration not established | Initial current boot: VBoxService active, NTP inactive. Query-associated switch at 14:24; original service combination restored at 14:35:55 |

These changes prevent a controlled before/after claim. More CPUs/RAM, a kernel update, a reboot, and temporary time-service changes must not collectively be credited as a proven fix. The cause of the space increase was not audited; the missing crash report is consistent with part of it, but no deletion actor or complete byte reconciliation is known.

Read-only collection used `df`, `findmnt`, `lsblk`, bounded `nice` directory scans, `/proc`, `/sys`, `vmstat`, `iostat`, module/service metadata, Apport headers, and journals. Some root/service-private directories denied access; sizes below are lower bounds where applicable. No privileged filesystem repair or full filesystem integrity scan ran.

## A. Filesystem and storage capacity

### Capacity, inodes, mounts

| Filesystem | Capacity / available | Findings |
| --- | --- | --- |
| `/dev/sda` | 26,843,545,600 bytes (25 GiB) virtual disk | `VBOX HARDDISK`; `/dev/sda1` is 1 MiB, `/dev/sda2` occupies essentially the rest |
| `/dev/sda2`, mounted `/` | ext4 capacity 26,238,750,720 bytes (24.44 GiB); used 24,137,494,528 bytes at one sample; available 742,461,440 bytes (708.1 MiB) | `rw,relatime`; no separate `/home`, `/var`, `/tmp`, or project filesystem |
| Root inodes | 1,638,400 total; 333,263 used; 1,305,137 free (21% used) | Block capacity, not inode exhaustion |
| Root reserved/unavailable-to-user free space | `statvfs`: 2,099,974,144 bytes free including reserved; 741,179,392 user-available; difference 1,358,794,752 bytes (1.27 GiB) | Explains much of the apparent difference between “free” and usable space; do not count this as recovered capacity |
| `/media/sf_a_ubuntu` | `vboxsf`, approximately 930 GiB total, 711 GiB used, 219 GiB available (77%) | Separate host-backed shared folder; this does **not** establish free space on the VM image/snapshot volume |
| `/run`, `/dev/shm`, `/run/user/1000` | tmpfs; approximately 2.6 GiB / 13 GiB / 2.6 GiB limits | RAM-backed limits, not additional root-disk capacity |
| `/media/laurene/VBox_GAs_7.2.141` | 52 MiB ISO, read-only | 100% usage is normal for an ISO |
| `/snap/*` | Read-only squashfs loop mounts | Do not add their mounted contents to their backing-file usage |

The shared folder reports synthetic/unusable inode figures (including negative used values); use the root ext4 figures for the guest capacity assessment. The project is on root ext4, not on the shared-folder mount.

### Disk usage breakdown

Allocated sizes from `du -x -B1`, rounded to MiB/GiB; child rows overlap their parent rows. Root scan counted 23,945,756,672 bytes (22.30 GiB), versus a somewhat larger `df` used value due to metadata, permissions, and scan timing. Directories inaccessible to the current user include `/root`, portions of `/var/lib`, private logs, and private temporary directories. Visible `lsof +L1` output contained RAM-backed `memfd` objects, with no visible large deleted root-disk file; other users' descriptors were not fully inspectable.

| Location | Allocated size | Interpretation |
| --- | ---: | --- |
| `/usr` | 9.01 GiB | Installed system/software footprint |
| `/usr/lib` | 3.41 GiB | Includes system libraries, firmware (663 MiB), modules (359 MiB), JVM (286 MiB) |
| `/usr/local/lib` | 2.47 GiB | Mostly Ollama libraries and globally installed Node packages |
| `/usr/local/lib/ollama` | 2.06 GiB | CUDA v12 1.20 GiB, CUDA v13 811 MiB, plus Vulkan/other libraries; installed runtime libraries, not model files |
| `/usr/share` | 2.19 GiB | Includes Ollama model storage below |
| `/home` / `/home/laurene` | 6.29 GiB | Includes source, analysis data, tools, backups, and installed assistants |
| `/home/laurene/aire` | 1.35 GiB | `demo_artifacts` 1.06 GiB; preserve analysis/project data |
| `aire/demo_artifacts/oct22` | 701 MiB | Multiple analysis SQLite files; not cleanup targets |
| `/home/laurene/aire_backups` | 1.00 GiB | Recovery/checkpoint data; preserve |
| `/home/laurene/.codex` | 1.27 GiB | Installed packages/state; not assumed disposable |
| `/home/laurene/.local/share/claude` | 996 MiB | Several installed executable versions |
| `/home/laurene/tools` | 1.21 GiB | Ghidra installation 881 MiB; Zig environment 356 MiB |
| `/home/laurene/snap` | 343 MiB | Application user data; not classified as cache automatically |
| `/var` | 2.76 GiB | Includes snap data, logs, caches, crash reports |
| `/var/lib/snapd` | At least 1.55 GiB | Seed 1.48 GiB; no manual deletion of seed or snap backing files recommended |
| `/var/log` | At least 589 MiB | Journal directory 576.5 MiB; `journalctl --disk-usage` also reports 576.5 MiB |
| `/var/cache` | At least 166 MiB | APT metadata caches are most of this |
| `/var/lib/apt/lists` | At least 219 MiB | Package index metadata; would need downloading again after removal |
| `/var/crash` | 136.3 MiB | Python report 127.0 MiB, GNOME report 6.8 MiB, smaller system-service reports |
| `/home/laurene/.cache` | 100.1 MiB | Zig cache 79.9 MiB; no user pip cache found |
| `/tmp` | Approximately 2.7 MiB before monitor output | No large temporary-directory recovery opportunity in this boot |
| `/opt` | 14.8 MiB | Guest Additions installation |
| `/swap.img` | 4 GiB | Root-level swap file; unused but intentional allocation, not a cleanup target |

No `.gradle` cache or persistent `.gpr`/`.rep` Ghidra project was found in the scanned project, backup, and tools trees. This does not cover inaccessible or shared-folder locations. A.I.R.E.'s `.venv` is about 29 MiB. Python bytecode totals were 16.4 MiB in `aire`, 0.14 MiB in its backup tree, and 7.6 MiB under tools. Deleting environments or installed Ghidra would remove required tools for little diagnostic benefit.

Largest observed regular files include:

| File / group | Logical size |
| --- | ---: |
| `/swap.img` | 4 GiB |
| Ollama model blob `sha256-29d8c98fa6b098e200069bfb88b9508dc3e85586d20cba59f8dda9a808165104` | 986,048,576 bytes (940.4 MiB) |
| Ollama CUDA v12 `libcublasLt.so.12.8.5.5` | 716.9 MiB |
| Ollama CUDA v13 `libcublasLt.so.13.1.1.3` | 516.5 MiB |
| Ollama CUDA v12 `libggml-cuda.so` | 396.9 MiB |
| Claude executable versions 2.1.326 / 2.1.322 / 2.1.317 | 354.2 / 326.1 / 316.0 MiB |
| Codex daemon executable versions 0.167.0 / 0.169.0 | 305.7 / 280.6 MiB |
| `demo_artifacts/oct22/final.sqlite`, `demo.sqlite` and corresponding backup copies | 211.3 MiB each |
| `analysis.sqlite` and corresponding backup copy | 204.4 MiB each |
| Remaining Python crash report | 127.0 MiB |
| `demo_artifacts/m10/m10.sqlite` | 123.2 MiB |

These are observed large files, not an exhaustive privileged ranking of every guest file. Shared storage was intentionally not recursively scanned. `ollama list` reports `qwen2.5-coder:1.5b` (986 MB); `ollama ps` showed no loaded model. Its storage is `/usr/share/ollama/.ollama/models` (940.4 MiB allocated), not the nearly empty user `~/.ollama`.

### Python crash investigation

The previously reported approximately 396 MB file was `/var/crash/_usr_lib_python3.12_unittest___init__.py.1000.crash`. It is **absent now**, so its contents and exact original size could not be independently verified. `/var/log/apport.log` confirms PID 25662 received SIGSEGV at 13:20:54, running `aire-server/.venv/bin/python -m unittest discover -s aire-server/tests -t aire-server/tests -v`; Apport wrote that exact report path at 13:21:24. This supports the hardening report's account of the S3 test crash. It does not establish a VM crash.

The remaining `/var/crash/_usr_bin_python3.12.1000.crash` is 133,194,744 bytes. Its header records SIGSEGV, Python 3.12.3, kernel `7.0.0-42-generic`, 20 threads, approximately 177 MiB captured RSS, and `/home/laurene/aire` as working directory. Its command starts the JVM through `_start_runtime()` and calls IR `decode()` on nested JSON at depths 1,000, 2,000, 5,000, and 100,000. Apport records this separate reproduction at 13:22:44–13:22:56. The saved command and prior S3 analysis support stack/decoder failure with the JVM in-process, not system-wide memory exhaustion. No core was extracted or reproduction run here.

Apport logs say `core limit 0` for both events, yet produced reports through the piped `/proc/sys/kernel/core_pattern`. Consequently, `ulimit -c 0` alone did not prevent Apport report creation in these runs. Any future crash-report policy needs validation against the actual handler rather than assuming that limit suffices. The defect/fix history remains in the earlier security report; it was not re-tested here.

### Safe recovery estimates — recommendations only

Preserve needed diagnostic evidence externally before removing crash reports or old journal history. No listed action was performed.

| Candidate | Estimated recovery | Conditions |
| --- | ---: | --- |
| Existing Python crash report | 127 MiB | Archive if needed, then deliberate user/admin removal; the old 396 MB file cannot be reclaimed a second time |
| Other existing crash reports | About 9 MiB | Retain GNOME/system crash evidence until investigated |
| `/var/cache/apt/pkgcache.bin` and `srcpkgcache.bin` | About 112 MiB | Regenerable APT binary metadata caches; use an appropriate maintenance procedure when APT is idle |
| Zig user cache | Up to 80 MiB | Regenerable build cache; later builds will take longer |
| Journal history | Potentially about 475 MiB if retaining roughly 100 MiB | Export the relevant boots first; active files/rotation mean this is not a guaranteed immediate vacuum yield |
| Python bytecode across scanned trees | About 24 MiB | Low benefit; avoid indiscriminate project-tree deletion and expect regeneration |
| Superseded assistant executable versions | Potentially hundreds of MiB | Verify active executables and rollback needs; use supported package/version management; not included in the safe immediate estimate |

The first five categories offer roughly **0.8 GiB**, subject to retention decisions and journal behavior. That would still leave root with only about 1.5 GiB available, below a useful 10–20% working margin. APT archives contain essentially no downloaded `.deb` packages (approximately 40 KiB directory allocation); **`apt clean` is not a 112 MiB recovery estimate**. Do not delete SQLite databases, backups, model blobs, snap seeds, installed CUDA libraries by hand, or the swap file. Root reserved blocks are not a durable substitute for disk expansion.

### Filesystem/storage errors

Current and previous boot kernel journals contain no matched ext4 errors, block I/O errors, OOM messages, or “blocked for more than” hung-task reports. Root is writable; `/sys/fs/ext4/sda2/errors_count` and `warning_count` both read zero. Warning-level journal search from November 10 through collection found no matched ENOSPC/“No space”, failed-write, block I/O error, OOM-kill, or read-only-filesystem messages. This is bounded negative evidence, not a full historical integrity guarantee.

There were **24 journal “corrupted or uncleanly shut down” notices** in that interval, frequently following watchdog failures. They identify journal recovery after an unclean stop, not proof of ext4 corruption. Older logs include systemd-journald watchdog timeouts and replacement journals. Keep this evidence; an offline filesystem check is justified if fresh ext4 errors or persistent corruption appear, rather than running repair on mounted `/` now.

## B. Guest health, scheduling, and clocks

| Area | Observed evidence |
| --- | --- |
| OS | Ubuntu 24.04.5 LTS, x86_64; current kernel `7.0.0-43-generic` |
| CPU presentation | 15 vCPUs; presented Intel Core Ultra 7 155H; `lscpu` reports hypervisor vendor KVM while DMI/devices and modules identify VirtualBox |
| Current memory | Initial sample: 1.64 GiB used, 21.43 GiB free, 24.18 GiB available; 4 GiB swap, zero used |
| Load/scheduling | Early post-boot load 4.19/3.54/1.66 on 15 vCPUs; subsequent `vmstat` intervals 93–100% idle, 0–2 runnable, zero blocked, zero swap traffic, 0–2% I/O wait, zero reported steal |
| Process limits | Current terminal/monitor cgroup ancestors show no finite CPU quota or memory limit; memory event counters show no OOM/OOM-kill; affinity includes all 15 vCPUs |
| PSI | Early post-boot CPU `some avg10=2.68%`, I/O `some avg10=0.06%`, memory `some/full avg10=0`; cumulative totals include boot activity and must be differenced |
| Storage | SATA/AHCI virtual disk; `[mq-deadline]` scheduler; rotational flag 1, write-back guest queue. Virtual flags do not reveal host SSD/HDD media or host cache policy |
| Short passive I/O sample | Mostly no operations; one active second: 2 writes/s, 60 KiB/s, write await 14 ms, flush await 13.5 ms, queue depth 0.06, utilization 2.8%. No sustained saturation in that window |
| Guest Additions | `VBoxControl` / `VBoxService` and `vboxguest` / `vboxsf` version `7.2.14 r174565`; module vermagic matches current kernel; host version unknown |
| Guest Additions warnings | Both boots show an RCU warning during `vboxguest` initialization, with `VbglR0GRPerform` / HGCM / `VGDrvCommonProcessOptionsFromHost` in the stack. Out-of-tree/unsigned-module taints are recorded; taints alone do not prove causation |
| Service state | VBoxService started at 14:19:50, stopped at 14:24:13 during the D-Bus query side effect; restarted at 14:35:55 with timesyncd stopped. Module presence alone does not establish service state |
| Clocksource | Current `tsc`; available `tsc kvm-clock acpi_pm`. Both boots initially selected kvm-clock then switched to TSC; no inspected TSC-unstable/backward-clock message |
| Time synchronization | Initially NTP inactive, synchronized=no (not a direct assessment of VBox host sync). Query-activated timesyncd synchronized at 14:24:13; later offset −1.216 ms, jitter 8.227 ms, frequency −9.984 ppm. Initial runtime service combination subsequently restored; no persistent settings edited |
| Watchdogs | Software watchdog enabled; NMI watchdog disabled; hung-task timeout 120 s. Absence of an NMI event cannot exonerate a stalled VM |
| GUI/graphics | Both boots record vmwgfx unsupported-hypervisor errors and six GNOME Shell SIGSEGVs during login. Current graphics reports 32 MiB VRAM. These are separate reproducible desktop-health concerns, not sufficient explanation for independent process stalls |

The KVM vendor string is compatible with VirtualBox's Linux paravirtualization interface. **It does not prove a Linux/KVM host, nested virtualization, or a Windows Hyper-V backend.** Oracle recommends its KVM interface for Linux guests. [Oracle paravirtualization documentation](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/working-with-vms.html) (see Paravirtualization Providers).

`VBoxControl guestproperty get /VirtualBox/HostInfo/VBoxVer` and `/VBoxRev` could not contact the host under the current permissions. `/dev/vboxguest` is restricted to `vboxadd:root`, while `/dev/vboxuser` is world-accessible. The failure is not by itself evidence that the VM host or kernel driver is down.

### Kernel evidence during the hardening freezes

Prior boot `journalctl -k -b -1` contains **20 soft-lockup reports**, 21–40 s long, between 13:35:14 and 13:57:00 CST. Multiple vCPUs report together; many stacks are idle tasks in `pv_native_safe_halt`, rather than application execution. Examples:

| CST time | Kernel observation | Interpretation |
| --- | --- | --- |
| 13:26:44 | Clocksource watchdog skipped after a 42.388704436 s TSC interval versus 42.388691131 s watchdog interval | Both clock readings advanced almost equally while the check was delayed; consistent with a delayed VM/kernel, not evidence of an isolated wall-clock step |
| 13:35:14 | CPUs 0 and 2 idle in halt; Python on CPU 3 in `default_send_IPI_mask_sequence_phys` → `smp_call_function_many_cond` → TLB flush → `munmap` | Investigate vCPU wakeup, virtual APIC/IPI delivery, and kernel/hypervisor interaction; this is kernel work, not simply a Python thread holding a lock |
| 13:41:20 | Idle CPUs plus Python in block dispatch/`ata_scsi_queuecmd` near interrupt-state restoration | Storage/device-emulation path is present in one trace; low PSI alone cannot categorically exclude all host/device stalls |
| 13:45:05 | Idle CPUs plus Python in `filemap_get_read_batch`, and journald near interrupt-state restoration | Different active paths stall alongside idle CPUs; no single application stack explains all events |
| 13:57:00 | Bash and idle CPUs report 40 s lockups | Effect extends beyond A.I.R.E. |

Across warning logs since November 10 there are 129 soft-lockup messages (messages, not unique episodes), including November 12 reports as long as **526 s** affecting systemd, idle tasks, and llama-server. OOM daemon watchdog failure is not an OOM kill. Current-boot kernel capture had zero soft-lockup messages. A later current-boot log at 14:33:30 recorded a 1.006 s long clocksource readout interval; this is much shorter than the old freezes. A short light-work boot cannot establish a resolution.

## C. Saved stall data and bounded monitoring

### Re-audit of prior measurements

Raw source directory: `demo_artifacts/m10/security_phase2/` (git-ignored). Reviewed both monitoring scripts without running the GUI workload. Several files lack an `end` record; do not treat their intended runtime as a measured completed duration. Overlapping monitors observe the same event, so counts must not be added as independent episodes.

| File | Recorded stalls >0.5 s late | Stalls with sample gaps >5 s | Maximum lateness | Caveat |
| --- | ---: | ---: | ---: | --- |
| `idle_baseline.jsonl` | 0 | 0 | 0.114 s (end summary) | Complete 180.05 s run, 1,741 samples |
| `full_suite2_monitor.jsonl` | 9 | 2 | 42.342 s | No end marker; long-gap accounted/wall ratio 0.746–0.748 |
| `full_suite_monitor.jsonl` | 85 | 36 | 72.045 s | Complete monitor lifetime 1,888.28 s, but spans later work; older inline process scanning can block, so not a clean workload attribution |
| `gui_monitor2.jsonl` | 39 | 17 | 73.911 s | No end marker |
| `gui_monitor3.jsonl` | 34 | 18 | **75.271 s** | No end marker; later event omitted from previous report's stated maximum |
| `gui_monitor.jsonl` | 0 recorded | 0 recorded | Unknown | Start-only file; not evidence of a stall-free completed run |

Thus the longest saved lateness is **75.271 s**, a 75.371 s interval ending at **19:53:06.942 UTC / 13:53:06.942 CST**, exceeding the previously cited 73.9 s. At 19:39:59.63 UTC, two independent monitor files end long gaps within approximately 20 ms of each other. This is strong evidence against a single monitor process or application lock explaining that event.

In `gui_monitor2` long gaps, idle is 99.351–100% **of accounted ticks**, and normalized accounted time is 74.75–75.03% of elapsed monotonic time. For the 74.011 s gap, four vCPUs recorded 221.82 aggregate idle CPU-seconds, 0.14 aggregate busy CPU-seconds, and 55.49 normalized accounted seconds. Wall-minus-monotonic and boottime-minus-monotonic differences were effectively zero. I/O PSI some/full increased only 5.1/1.2 ms; no swap/major-fault increments were recorded for that event.

**Accounting limitation:** roughly one vCPU's worth of time is consistently missing on a four-vCPU guest. That can reflect delayed accounting, interrupt/tick delivery, or vCPU execution/scheduling anomalies. It does not measure “25% of real time spent paused” directly. One older monitor's process scan attributes about 72 CPU-seconds to Python across a 72 s gap while aggregate busy ticks barely move. Its different sampling windows and possible blocking make that unsuitable for precise attribution, but the contradiction further prevents treating tick-derived idle as definitive proof that all CPUs were inactive. Zero steal does not prove absence of host contention. The helper-thread monitor's empty/stale top-process windows also do not prove that no process ran.

Wall, monotonic, and boottime tracking together through the long gaps argues against a simple realtime-only correction. They are all guest clocks and may share virtual time infrastructure, so only host correlation can independently validate elapsed physical time. One later record has approximately 72 ms clock-difference deltas, far too small to explain the minute-scale gaps.

Prior separate HTTP responsiveness evidence (`gui_validation_concurrency.txt`) records 83 probes during an 11.27 s validation request: median 18.3 ms, p95 113.9 ms, max 281.1 ms. Expensive validation answers can delay their own completion while the service remains responsive. This distinguishes application latency from the kernel/VM stalls; it does not rule out every application bottleneck.

### Current passive run

At collection time approximately 707 MiB was available, enough for a strictly bounded sub-megabyte diagnostic capture, but not for heavy testing. A standard-library Python sampler ran at normal priority from **14:27:19.417 to 14:29:19.474 CST** (20:27:19.417–20:29:19.474 UTC), with an outer 150 s termination timeout and 5 s kill grace. No workload generator, application server, browser, Ghidra, or model was launched. A separate child echoed one byte over a local socket approximately once per second, measuring basic cross-process responsiveness rather than GUI rendering. No A.I.R.E. HTTP listener was present, so application HTTP responsiveness was not re-tested.

The query-triggered time-service transition described above had already happened: this run sampled **timesyncd active, VBoxService stopped**, with the guest modules still loaded. It therefore cannot establish behavior with the original Guest Additions services active.

The timing loop used 100 ms sleeps and recorded realtime, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW and CLOCK_BOOTTIME on each wake. About once per second it collected aggregate/per-vCPU ticks, PSI, major faults/swap counters, diskstats, available memory, load, and its own scheduling runtime/wait counters. No full-process scan ran in the timing loop. Sampling and JSON output add overhead to the next interval; maxima are observed lateness, not a calibrated timer benchmark. Metric/heartbeat collection took at most 28.6 ms in a sampled iteration.

| Measurement | Result |
| --- | --- |
| Completed interval | 120.057748 s; 1,131 wake samples |
| Wake lateness | Median 3.14 ms; p95 19.62 ms; maximum **131.87 ms** |
| Stalls >0.5 s / >5 s late | **0 / 0** |
| Independent process heartbeat | 113 exchanges; median 0.0616 ms; p95 1.091 ms; max 9.214 ms; zero timeouts |
| Clock increments versus monotonic | Maximum per-interval absolute difference: realtime 0.656 ms, raw 1.292 ms, boottime 2.930 ms; sequential clock reads are not atomic |
| Total clock increment differences | Realtime +3.1 microseconds, raw +1.938 ms, boottime −11.1 microseconds over the run; no seconds-scale discontinuity |
| Guest CPU accounting | 96.62% idle **among accounted ticks**; normalized accounted/elapsed ratio **0.93398** across 15 vCPUs |
| Per-vCPU accounting ratios | Approximately 0.929–0.940 of elapsed time per CPU |
| Sampler scheduling counters | 1.173 s additional runtime, 0.269 s additional runqueue wait across the interval |
| CPU PSI some | +2.711 s cumulative pressure (about 2.26% of this interval); full +0 |
| I/O PSI some/full | +42.911 / +23.244 ms across the entire run |
| Memory PSI some/full | +0 / +0 |
| Memory/swap | Minimum MemAvailable 24.09 GiB; no swap-in/out, swap remained unused |
| Major faults | +8 over the full interval; no pressure-associated burst demonstrated |
| Diskstats | 17 reads / 358 writes / 50 flushes; total I/O-busy time 459 ms; derived mean read/write/flush await approximately 4.76 / 2.25 / 3.22 ms |
| Load averages | 2.00/2.62/1.64 at start; 1.05/2.12/1.58 at end |
| Output | `/tmp/aire-vm-passive-monitor.jsonl`, 365,591 bytes; SHA-256 `ac2c5e6667896662bf3671aaa105a88b4ec68e276e59d33314500df1658f9522` |

**Crucial control observation:** 0.93398 × 15 is approximately 14 CPU-seconds accounted per elapsed second. Thus approximately one vCPU's worth of aggregate accounting is also missing during a responsive, no-stall run, distributed across CPUs. This closely resembles the old three-of-four accounting ratio and substantially weakens its use as a signature of hypervisor suspension. The accounting discrepancy itself needs investigation; this capture does not identify its implementation-level cause. An off-CPU host trace and reliable per-vCPU timing are needed before equating unaccounted ticks to a real pause.

Compared with the saved 180 s idle baseline (worst lateness 114 ms, zero stalls), this light run is similarly free of severe stalls. It is **not** comparable to the old loaded runs and does not prove the kernel/configuration changes resolved the freezes. No cleanup was performed, so there is no cleanup before/after result.

After restoring VBoxService active/timesyncd inactive, the existing unmodified `scripts/stall_monitor.py` ran for **60.098 s**, 14:36:45.625–14:37:45.724 CST, with an outer 90 s timeout. It completed 548 samples, **zero stalls >0.5 s**, and worst lateness **263 ms**. Load changed from 1.07/1.29/1.39 to 0.85/1.20/1.35. The script captures wall/monotonic/boottime deltas for threshold-crossing events; no such events occurred, and this follow-up does not supply another continuous raw-clock comparison or IPC latency series. Service readback confirmed the original active/inactive combination. Both service combinations passed only a short idle check; this is not evidence that either caused or cured the loaded freezes. Raw follow-up: `/tmp/aire-vm-restored-monitor.jsonl`.

### Discriminating the failure modes

| Hypothesis | Evidence that would support it | Present conclusion |
| --- | --- | --- |
| Guest CPU starvation | Runnable queue/CPU PSI grows while busy time accounts for elapsed time; individual tasks miss deadlines | Some CPU pressure exists, but sustained saturation does not explain the prior idle-task lockups; not established |
| Guest memory exhaustion | Falling MemAvailable, reclaim/major faults, memory PSI, swap traffic or OOM kills | Strong evidence against this in observed long gaps; current guest also has ample RAM |
| Guest disk I/O stalls | Sustained await/queue depth/I/O PSI, D-state tasks, write/transport errors | No sustained pressure in sampled windows; capacity risk is real; host image I/O or virtual controller stalls remain possible |
| Application thread blocking | Slow application probes while independent scheduling/heartbeat stays healthy | Explains some slow validation requests; insufficient for correlated external monitor and kernel-watchdog events |
| Hypervisor pause or host descheduling | Simultaneous guest deadlines missed; host heartbeat continues or host scheduler records vCPU off-CPU intervals; VBox state changes | Leading cause family, but host evidence is missing |
| Guest kernel/virtual timer or interrupt issue | Soft lockups, idle vCPUs not waking, IPI/TLB-related stacks, clock/accounting discrepancies with host otherwise healthy | Material competing explanation requiring controlled kernel/VirtualBox/SMP comparison |
| Clock synchronization anomaly | Realtime diverges from monotonic/raw without independent responsiveness loss | No minute-scale realtime-only jump in saved evidence; common virtual-clock error still needs host comparison |

## Ranked possible causes

1. **Virtualization-boundary vCPU scheduling / wakeup / timer-interrupt problem — strongest evidence.** Independent guest monitors pause together and idle-task watchdogs fire across CPUs. The guest accounting anomaly also occurs without severe stalls and is not sufficient causal evidence. This identifies the affected layer, not a particular host fault. Host overload, host sleep, a CPU execution cap, VirtualBox backend behavior, and virtual APIC/timer delivery remain distinguishable alternatives.
2. **Guest kernel and VirtualBox/Guest Additions interaction — substantial evidence, mechanism unproven.** RCU warnings occur in VBox HGCM initialization on both kernels; later hardening traces include IPIs/TLB flushes and multiple unrelated kernel paths. The kernel and vCPU count changed before this collection. A supported-version comparison with the same workload and fixed settings is needed. The startup RCU warning is not yet temporally linked to every freeze.
3. **Host RAM/CPU pressure, power management, or a competing hypervisor backend — plausible but unmeasured.** The current 15-vCPU/25.8-GiB guest can leave inadequate host headroom on some machines, but host capacity is unknown and old freezes occurred with four vCPUs. Nothing inside this guest proves Windows, Hyper-V, host paging, thermal throttling, or exhausted host storage.
4. **Nearly full guest root / host backing-storage problem — confirmed guest capacity risk, weak direct freeze attribution.** The 25 GiB disk is undersized for this installed footprint. No inspected ENOSPC or ext4 error, swap traffic, or sustained I/O pressure explains the recorded long gaps. Host disk/image/snapshot latency remains unmeasured and could stall device emulation without ordinary guest pressure signatures.
5. **Desktop graphics instability — confirmed separate fault, limited freeze attribution.** Repeated GNOME crashes and vmwgfx warnings can impair desktop responsiveness; they do not alone explain independent scheduler gaps. Investigate separately with a console/SSH heartbeat and the same clock monitor.
6. **Application locks, guest memory exhaustion, or pure realtime synchronization steps — least supported as the general cause.** Application computation explains individual slow answers; sampled resources and clock differences do not explain broad kernel stalls through these mechanisms.

## D. Exact host-side checks still required

Perform these **on the machine running VirtualBox**, not in Ubuntu. Capture host and guest UTC timestamps during the same bounded ordinary-work interval. Keep the prior boot's VBox logs before further VM starts rotate them. No host checks below were executed during this investigation.

### VirtualBox configuration, logs, disk and snapshots — all host platforms

Use the VM's name or UUID from `list vms`; replace `VM_NAME` and `DISK_UUID_OR_PATH`. In Windows PowerShell, use `& 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'` if it is not on PATH.

```text
VBoxManage --version
VBoxManage list hostinfo
VBoxManage list runningvms
VBoxManage list vms
VBoxManage showvminfo "VM_NAME" --details
VBoxManage showvminfo "VM_NAME" --machinereadable
VBoxManage getextradata "VM_NAME" enumerate
VBoxManage snapshot "VM_NAME" list --details
VBoxManage list hdds --long
VBoxManage showmediuminfo disk "DISK_UUID_OR_PATH"
VBoxManage showvminfo "VM_NAME" --log=0
```

Save the complete output and copy the VM log directory, including `VBox.log`, rotated `VBox.log.*`, and `VBoxHardening.log` where present. `showvminfo --log=0` is the current release log; index 1 is the hardening log in the current reference, not necessarily the previous run. Use actual log filenames for historical boots. [Oracle command reference](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/vboxmanage.html).

Inspect CPU count, CPU execution/processing cap, RAM, nested virtualization/paging, paravirtualization provider, graphics controller/VRAM/3D, storage controller, host I/O cache, medium attachments, saved state, shared-folder mappings, snapshot folder, and extension pack/Guest Additions versions. Confirm the actual backend from `HM`, `NEM`, and hypervisor initialization messages. A Linux guest's KVM CPUID string does not answer that question.

Find the actual `.vbox`, base virtual disk, **every differencing disk/parent**, and snapshot location from these outputs. Follow parent UUIDs with `showmediuminfo`. Check free space, filesystem health, latency, and physical location for **every containing host volume**, including any cloud-synced, network, external USB, or encrypted storage. Guest free space, dynamic-image logical capacity, host image allocation, and snapshot growth are separate quantities. Do not manually delete snapshot files.

In `VBox.log`, correlate the UTC startup header and elapsed log timestamps with **2026-11-17 19:26:44Z**, **19:35:14Z**, **19:39:59.63Z**, and **19:53:06.94Z**. Search for `TM`, `TSC`, `GIM`, `VMMDev`, `HM`, `NEM`, `SUP`, `Changing the VM state`, `SUSPEND`, `RESUM`, `PAUS`, `VERR`, `DISK_FULL`, `AHCI`, and I/O errors. Preserve surrounding lines and long gaps, not just matches. Lack of a logged pause does not rule out OS descheduling. Oracle documents these logs as containing host/version, virtualization setup, configuration, and runtime state transitions. [Oracle diagnostic logging](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/Troubleshooting.html).

### If the host is Windows

Run in PowerShell; some information needs an elevated read-only shell. Counter names below are English Windows names; use Resource Monitor/Performance Monitor equivalents on localized installations.

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,LastBootUpTime,TotalVisibleMemorySize,FreePhysicalMemory
Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,LoadPercentage
Get-Volume | Select-Object DriveLetter,FileSystemLabel,Size,SizeRemaining,HealthStatus
Get-Process VirtualBoxVM,VBoxHeadless,VBoxSVC -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,CPU,WorkingSet64,PrivateMemorySize64,PriorityClass
Get-Counter -Counter '\Processor(_Total)\% Processor Time','\System\Processor Queue Length','\Memory\Available MBytes','\Memory\Pages Input/sec','\PhysicalDisk(_Total)\Avg. Disk sec/Transfer','\PhysicalDisk(_Total)\Current Disk Queue Length' -SampleInterval 1 -MaxSamples 120
powercfg /getactivescheme
powercfg /lastwake
systeminfo
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
Get-WindowsOptionalFeature -Online | Where-Object FeatureName -match 'Hyper-V|HypervisorPlatform|VirtualMachinePlatform|Containers-DisposableClientVM' | Select-Object FeatureName,State
bcdedit /enum '{current}'
$vmDiagStart = [datetime]'2026-11-17T19:15:00Z'
$vmDiagEnd = [datetime]'2026-11-17T20:05:00Z'
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$vmDiagStart; EndTime=$vmDiagEnd} | Where-Object ProviderName -match 'Kernel-Power|Power-Troubleshooter|Kernel-Processor-Power|WHEA|disk|storahci|stornvme|volmgr|Ntfs' | Select-Object TimeCreated,ProviderName,Id,Message
```

Also inspect Task Manager and `resmon.exe` during the interval for VM/other-process CPU, committed memory, paging/hard faults, and latency on the actual image volume. Process `CPU` above is cumulative time, not instantaneous utilization. Event IDs 42/107 often indicate sleep/resume, Kernel-Power 41 and EventLog 6008 unexpected shutdowns; inspect messages and chronology rather than treating an ID alone as a cause.

Check whether `systeminfo` reports a detected hypervisor, whether Device Guard/VBS is running, and whether Hyper-V, Virtual Machine Platform, Windows Hypervisor Platform, Sandbox, WSL2, Docker, Credential Guard, or Memory Integrity is active. Confirm actual use in `VBox.log` (`NEM` versus native hardware acceleration). These are conditional checks, not evidence of a conflict on this unknown host. Oracle documents potential Hyper-V coexistence performance problems. Do not disable host security/virtualization features merely to satisfy a guess; first record the backend and plan a deliberate comparison if it is implicated. [Oracle troubleshooting](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/Troubleshooting.html).

### If the host is Linux

Run the following bounded samplers in separate terminals during the same two-minute window. `pidstat` and `iostat` require sysstat if already installed; no installation is required for the baseline checks.

```bash
date -u --iso-8601=ns
uname -a
lscpu
free -h
swapon --show
df -hT
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL
vmstat -w 1 120
iostat -xz -y 1 120
pidstat -u -r -w -t -C 'VirtualBoxVM|VBoxHeadless|VBoxSVC' 1 120
journalctl --since '2026-11-17 19:15:00 UTC' --until '2026-11-17 20:05:00 UTC' -k --no-pager
journalctl --since '2026-11-17 19:15:00 UTC' --until '2026-11-17 20:05:00 UTC' -u systemd-suspend -u systemd-hibernate --no-pager
lsmod | rg 'kvm|vbox'
ps -eo pid,comm,pcpu,pmem,args | rg 'VirtualBoxVM|VBoxHeadless|qemu|vmware'
```

Check host CPU/I/O/memory PSI deltas in `/proc/pressure/*`, available memory and swap activity, VM per-thread CPU/wait patterns, host cgroup quotas/affinity, OOM records, storage resets, suspend/resume and thermal/power warnings. Inspect CPU frequency/thermal telemetry with existing host tools during the interval. Presence of a KVM module alone does not demonstrate an active conflict; check running VMs and actual hardware-virtualization errors. Run `df -hT` on each discovered image/snapshot path explicitly if it is not obvious which mount contains it.

### If the host is macOS

```bash
date -u '+%Y-%m-%dT%H:%M:%SZ'
sw_vers
sysctl hw.memsize hw.physicalcpu hw.logicalcpu
vm_stat 1 120
iostat -w 1 -c 120
top -l 120 -s 1 -o cpu -n 15
df -h
sysctl vm.swapusage
pmset -g custom
pmset -g log | tail -n 200
log show --start '2026-11-17 13:15:00' --end '2026-11-17 14:05:00' --style compact --predicate 'process == "powerd" OR process == "kernel"'
```

The final command uses host local time; translate the UTC incident window to the host's actual zone. Use Activity Monitor's CPU, Memory Pressure, Swap Used, and Disk panels, and inspect the discovered image/snapshot volumes. Record other hypervisors/VMs, power/sleep/lid events and thermal state. Run long samplers in parallel terminals; they are each bounded to approximately two minutes. `pmset` history and kernel logs help distinguish actual host sleep from a guest-only freeze.

### What the guest cannot establish

Host physical RAM/cores and remaining headroom; real host run queues and VM-thread off-CPU time; physical disk latency/health and where images actually reside; snapshot chain depth and host free space; CPU cap/backend configuration; host suspension/lid/AC/power/thermal transitions; and Windows Hyper-V/VBS state require host evidence. A guest heartbeat that freezes alongside every guest clock is not an independent host time reference.

## Safe remediation and recommended settings

Recommendations are proposed baselines for measured comparisons, **not changes applied or proven fixes**. Preserve the current configuration/logs and change one factor at a time.

| Setting / action | Recommended baseline | Justification / limits |
| --- | --- | --- |
| Root disk | Plan 60–80 GiB virtual capacity for this development VM; maintain at least 10 GiB or 15–20% available, whichever suits observed growth | Current 25 GiB disk holds about 23 GiB of data/software. After backup and snapshot review, expansion requires both virtual medium and guest partition/filesystem growth; host free space must support actual growth. The size/margin is an investigation recommendation, not a vendor minimum |
| CPU count | Start a controlled comparison at **4 vCPUs**, then 2 if needed; increase only with measured benefit and verified host headroom | The old failure already occurred at 4, so returning to 4 is a diagnostic baseline, not a claimed fix. Current 15 vCPUs increase SMP/interrupt scheduling demands. Leave physical cores for the host; do not confuse guest topology or host logical threads with physical cores |
| CPU execution/processing cap | **100%**, verify on host | A restrictive cap can cause guest timing problems; the actual current cap is unknown |
| RAM | For deterministic GUI/Ghidra work, test **8–12 GiB** initially, then size from measured peak working sets; preserve at least several GiB plus normal workload headroom on host | Current guest has about 24 GiB available at initial light load; allocating more guest RAM does not address observed guest exhaustion. Live models need a separately measured budget. Do not reduce memory during a workload or assume host RAM size |
| Virtualization | Hardware acceleration and nested paging enabled where supported; Linux paravirtualization Default/KVM; nested virtualization off unless needed | Appropriate general Linux baseline. Verify backend and retain current settings until a controlled test; KVM interface is already presented |
| Guest Additions / kernel | Match Guest Additions to the supported host VirtualBox release and verify kernel compatibility | Current module build matches `7.0.0-43`, but RCU warnings remain. Record exact versions first; use a supported kernel/VirtualBox comparison if host remains healthy through a freeze. Do not unload active modules or update multiple layers together during diagnosis |
| Clocksource / synchronization | Keep the recorded TSC baseline initially; use one deliberately configured clock-discipline policy | No evidence justifies changing clocksource now. A later TSC versus kvm-clock test must hold other settings fixed. If investigating VBox time sync, disable only that function in a planned comparison rather than treating all Guest Additions services as disposable. The query-induced service switch is a confounder |
| Graphics | Inspect current controller/3D configuration; Linux VMSVGA is the vendor default. Compare 3D off with adequate VRAM (e.g. 128 MiB for a single desktop) only if graphics remains implicated | Current guest sees 32 MiB VRAM and startup GNOME crashes. Preserve crash evidence; changing graphics cannot by itself explain or repair kernel-wide scheduling stalls |
| Storage | Keep SATA/AHCI and current guest scheduler as baseline; use a reliable local host volume with headroom, after verifying where disks/snapshots live | No sustained guest saturation justifies changing controller or cache policy. Do not enable unsafe caching, compact disks, merge snapshots, or move active databases as an exploratory fix |
| Power/backend | Measure host on AC with recorded power mode and no sleep during verification; inspect competing hypervisors | Host sleep, thermal/power limits, or backend conflict must be evidenced. Avoid speculative BIOS/security-feature changes |
| Cleanup | Archive crash/journal evidence, then explicitly approved maintenance of selected regenerable caches/history | Roughly 0.8 GiB possible; insufficient as a long-term disk-capacity solution. Preserve projects/models/backups |

Oracle advises keeping vCPU count within physical cores and notes that reduced processing caps can cause timing problems; it also documents RAM being taken from host availability, Linux VMSVGA, nested paging, and KVM paravirtualization. The numerical baseline/margins above are engineering recommendations for this workload. [Oracle VM settings](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/working-with-vms.html).

## Verification plan

1. Preserve the current/previous guest journals, relevant crash metadata, VBox logs/configuration, and snapshot/medium inventory. Establish host UTC clock and continuous host sampling before another normal-work trial. Do not infer resolution from the new boot alone.
2. Restore adequate disk headroom through deliberate cleanup/expansion after evidence retention. Record `df -B1 /`, `df -i /`, memory/swap, VM settings, time-service state, kernel/module versions, and host headroom before and after. Separate capacity maintenance from a freeze-cause experiment.
3. Run a 2–3 minute idle scheduling baseline, then a bounded 3–5 minute rehearsal of an already indexed small-fixture GUI workflow. Use the existing `scripts/stall_monitor.py` with a unique `/tmp` output and an external timeout; independently sample realtime/monotonic/raw/boottime and host timing. Avoid the full heavy validation workload, model inference, indexing, or the crash input during initial verification. Stop escalation of workload if >5 s stalls or renewed lockups appear.
4. Record application request latency separately from process heartbeat/scheduling lateness. A single slow answer with healthy independent probes points to application latency; simultaneous probes/guest deadlines lost with a healthy host suggests VM/backend/kernel behavior; host-wide heartbeat loss plus sleep/paging/disk evidence points to the host mechanism.
5. Change only one implicated factor (CPU count, cap, supported kernel/VirtualBox combination, time discipline, or graphics) and repeat the same bounded workload with host telemetry. Record stall count above 0.5 s and 5 s, worst/p95 lateness, application and independent-probe latency, per-vCPU accounting, PSI, swap, I/O await, clock deltas, and fresh watchdog/RCU/error events.
6. Provisional acceptance: three repeated rehearsals without >0.5 s scheduling lateness, no new soft lockups/watchdog failures, stable host memory/storage headroom, and no unexplained clock discontinuities. These criteria are practical rehearsal targets, not proof against every future freeze. Confirm the proposed cause by reproducible correlation and a single-factor improvement, or by direct host/backend evidence; otherwise retain “cause unresolved.”

## Evidence locations and limitations

- Historical project evidence: `docs/M10_SECURITY_HARDENING.md`, `scripts/stall_monitor.py`, `scripts/measure_gui_responsiveness.py`, `demo_artifacts/m10/security_phase2/*monitor*.jsonl`, `idle_baseline.jsonl`, and `gui_validation_concurrency.txt`.
- Current raw captures: `/tmp/aire-vm-kernel-current.txt`, `/tmp/aire-vm-kernel-previous.txt`, `/tmp/aire-vm-warnings.txt`, `/tmp/aire-vm-root-du.txt`, `/tmp/aire-vm-du-details.txt`, `/tmp/aire-vm-large-files.txt`, `/tmp/aire-vm-passive-monitor.jsonl`, and `/tmp/aire-vm-restored-monitor.jsonl`. Permission diagnostics are in matching `/tmp/aire-vm-*-errors.txt` files. These temporary files may be lost on reboot; key measurements are retained in this report.
- Current system sources: `/var/log/apport.log`, the remaining Python report header, `/proc/{stat,vmstat,meminfo,pressure,diskstats}`, clocksource and ext4 sysfs counters, `journalctl -k -b` / `-b -1`, and warning journal entries since November 10.
- No complete host evidence, privileged root-directory inventory, SMART data, offline ext4 check, GUI rendering trial, or model inference was collected. Saved monitoring windows overlap and several lack clean completion markers. Different CPU/RAM allocations and kernels, plus the temporary query-induced service change, prevent attributing apparent improvement to one change.
