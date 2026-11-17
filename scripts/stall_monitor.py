#!/usr/bin/env python3
"""Separate-process scheduling-stall monitor with attribution evidence.

Wakes every --interval seconds. A wakeup later than --threshold is a stall. For
each stall it records what the guest kernel accounted during the gap: CPU time
by state (user/system/iowait/steal/idle), pressure-stall (PSI) totals, major
faults/swap and the processes that consumed CPU. A gap during which the kernel
accounted almost no time of any kind (including idle) points to the whole VM
being descheduled by the host; a gap filled by iowait/PSI-io points to storage;
a gap filled by user/system time in one process points to that process.

Standard library only. Read-only: /proc and /sys are sampled, nothing is changed.
Usage: stall_monitor.py OUTPUT.jsonl --seconds N [--label PHASE]
"""
import argparse
import json
import os
import threading
import time

HZ = os.sysconf('SC_CLK_TCK')
NCPU = os.cpu_count() or 1


def cpu_ticks():
    with open('/proc/stat') as handle:
        values = [int(v) for v in handle.readline().split()[1:]]
    names = ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal')
    return dict(zip(names, values))


def psi():
    result = {}
    for resource in ('cpu', 'io', 'memory'):
        try:
            with open(f'/proc/pressure/{resource}') as handle:
                for line in handle:
                    kind, *fields = line.split()
                    result[f'{resource}_{kind}_us'] = int(fields[-1].split('=')[1])
        except OSError:
            pass
    return result


def vmstat():
    keep = {'pgmajfault', 'pswpin', 'pswpout', 'pgpgin', 'pgpgout'}
    with open('/proc/vmstat') as handle:
        return {k: int(v) for k, v in (line.split() for line in handle) if k in keep}


def processes():
    result = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open(f'/proc/{pid}/stat') as handle:
                raw = handle.read()
            name = raw[raw.index('(') + 1:raw.rindex(')')]
            fields = raw[raw.rindex(')') + 2:].split()
            result[int(pid)] = (name, int(fields[11]) + int(fields[12]))
        except (OSError, ValueError):
            continue
    return result


class ProcessSampler(threading.Thread):
    """Per-process CPU scans run off the timing loop: a read of /proc/PID that
    blocks (e.g. a process being core-dumped) must not appear as a stall."""

    def __init__(self):
        super().__init__(daemon=True)
        self.lock = threading.Lock()
        self.history = []  # (monotonic, {pid: (name, ticks)}), last ~30 s

    def run(self):
        while True:
            sample = (time.monotonic(), processes())
            with self.lock:
                self.history = [h for h in self.history if sample[0] - h[0] < 30] + [sample]
            time.sleep(1.0)

    def busiest(self, since):
        with self.lock:
            history = list(self.history)
        before = next((h for h in reversed(history) if h[0] <= since), history[0] if history else None)
        after = history[-1] if history else None
        if not before or before is after:
            return [], 0.0
        rows = sorted(((ticks - before[1].get(pid, (None, ticks))[1], name, pid)
                       for pid, (name, ticks) in after[1].items()), reverse=True)[:6]
        return [[n, p, round(t / HZ, 2)] for t, n, p in rows if t > 0], round(after[0] - before[0], 2)


def delta(after, before):
    return {k: after[k] - before.get(k, 0) for k in after}


def snapshot():
    return {'mono': time.monotonic(), 'boot': time.clock_gettime(time.CLOCK_BOOTTIME), 'wall': time.time(),
            'cpu': cpu_ticks(), 'psi': psi(), 'vm': vmstat()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output')
    parser.add_argument('--seconds', type=float, required=True)
    parser.add_argument('--interval', type=float, default=0.1)
    parser.add_argument('--threshold', type=float, default=0.5)
    parser.add_argument('--label', default='')
    args = parser.parse_args()
    end = time.monotonic() + args.seconds
    sampler = ProcessSampler()
    sampler.start()
    previous = snapshot()
    count = stalls = 0
    worst = 0.0
    with open(args.output, 'a', buffering=1) as out:
        out.write(json.dumps({'type': 'start', 'label': args.label, 'wall': previous['wall'],
                              'interval': args.interval, 'threshold': args.threshold, 'ncpu': NCPU,
                              'loadavg': open('/proc/loadavg').read().split()[:3]}) + '\n')
        while time.monotonic() < end:
            time.sleep(args.interval)
            now = snapshot()
            count += 1
            gap = now['mono'] - previous['mono']
            late = gap - args.interval
            worst = max(worst, late)
            if late > args.threshold:
                stalls += 1
                cpu = delta(now['cpu'], previous['cpu'])
                accounted = sum(cpu.values()) / HZ / NCPU  # seconds of wall time the kernel accounted
                busy, window = sampler.busiest(previous['mono'])
                out.write(json.dumps({
                    'type': 'stall', 'label': args.label, 'wall': now['wall'], 'late_s': round(late, 3),
                    'gap_s': round(gap, 3), 'boot_minus_mono_s': round((now['boot'] - previous['boot']) - gap, 3),
                    'wall_minus_mono_s': round((now['wall'] - previous['wall']) - gap, 3),
                    'kernel_accounted_s': round(accounted, 3),
                    'cpu_s': {k: round(v / HZ, 2) for k, v in cpu.items() if v},
                    'psi_ms': {k: round(v / 1000, 1) for k, v in delta(now['psi'], previous['psi']).items() if v},
                    'vm': {k: v for k, v in delta(now['vm'], previous['vm']).items() if v},
                    'top_cpu_s': busy, 'proc_window_s': window}) + '\n')
            previous = now
        out.write(json.dumps({'type': 'end', 'label': args.label, 'wall': time.time(), 'samples': count,
                              'stalls': stalls, 'worst_late_s': round(worst, 3),
                              'loadavg': open('/proc/loadavg').read().split()[:3]}) + '\n')


if __name__ == '__main__':
    main()
