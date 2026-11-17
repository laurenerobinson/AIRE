#!/usr/bin/env bash
# M10 Phase 6: run the evaluation one unit (binary) per process, sequentially, at low priority, with a
# per-unit timeout. Completed steps are skipped, so re-running after a crash resumes where it stopped.
# Logs resources before each unit; refuses to start a unit when memory or disk is low.
set -u
cd "$(dirname "$0")/.."
export PYTHONPATH=aire-server/src AIRE_M10_NARRATION=0
LOG=docs/m10/eval_full_run3.log
UNIT_TIMEOUT=${UNIT_TIMEOUT:-2400}
for unit in O0 O0-stripped O2 aes_gcm sha256_hash ecdsa_sign negatives latency_large_pe phase2_mutation_O2; do
  avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
  disk=$(df -Pm . | awk 'NR==2 {print $4}')
  echo "$(date +%T) unit=$unit mem_available_mb=$avail disk_free_mb=$disk load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$LOG"
  if [ "$avail" -lt 2048 ] || [ "$disk" -lt 300 ]; then echo "$(date +%T) STOP: low resources" >> "$LOG"; exit 3; fi
  timeout "$UNIT_TIMEOUT" nice -n 10 aire-server/.venv/bin/python scripts/evaluate_m10_full.py --only "$unit" >> "$LOG" 2>&1
  echo "$(date +%T) unit=$unit exit=$?" >> "$LOG"
done
aire-server/.venv/bin/python scripts/evaluate_m10_full.py --merge >> "$LOG" 2>&1
echo "$(date +%T) merge exit=$?" >> "$LOG"
