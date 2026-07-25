#!/usr/bin/env bash
set -euo pipefail

# Keep the debug queue full without exceeding the per-user array-task limit.
# This monitor is intentionally append-only: it submits only missing offsets
# and never cancels or rewrites a previously submitted run.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROZEN_ROOT="${AGENTDOJO_TRANSFER_FROZEN_ROOT:-${ROOT}/configs/frozen/agentdojo_public_transfer_slice_v1}"
ARTIFACT_ROOT="${AGENTDOJO_TRANSFER_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-public-transfer-debug-v2}"
MAX_ACTIVE_TASKS="${AGENTDOJO_DEBUG_MAX_ACTIVE_TASKS:-8}"
ROWS_PER_TASK="${AGENTDOJO_TRANSFER_ROWS_PER_TASK:-40}"
SLEEP_SECONDS="${AGENTDOJO_DEBUG_MONITOR_SLEEP:-30}"
PARTITION="${AGENTDOJO_TRANSFER_PARTITION:-debug}"
LOG="${ARTIFACT_ROOT}/slurm/debug-monitor.log"

mkdir -p "${ARTIFACT_ROOT}/slurm"
exec >>"${LOG}" 2>&1
echo "monitor_start $(date -Is) max_active=${MAX_ACTIVE_TASKS} rows_per_task=${ROWS_PER_TASK}"

suite_offsets() {
  local suite="$1"
  case "${suite}" in
    # workspace rows 800:1057 are already covered by job 10064479;
    # travel rows 0:40 are already covered by job 10064482.
    workspace) printf '%s\n' $(seq 0 40 760) ;;
    travel) printf '%s\n' $(seq 40 40 960) ;;
    banking) printf '%s\n' $(seq 0 40 920) ;;
    slack) printf '%s\n' $(seq 0 40 960) ;;
    *) return 2 ;;
  esac
}

suite_port() {
  case "$1" in
    workspace) echo 38000 ;;
    travel) echo 38600 ;;
    banking) echo 39200 ;;
    slack) echo 39800 ;;
  esac
}

declare -a SUITES=()
declare -a OFFSETS=()
for suite in workspace travel banking slack; do
  while read -r offset; do
    SUITES+=("${suite}")
    OFFSETS+=("${offset}")
  done < <(suite_offsets "${suite}")
done

next=0
total="${#SUITES[@]}"
while (( next < total )); do
  active="$(squeue -r -h -u "${USER}" -p "${PARTITION}" | wc -l)"
  if (( active >= MAX_ACTIVE_TASKS )); then
    sleep "${SLEEP_SECONDS}"
    continue
  fi
  suite="${SUITES[next]}"
  offset="${OFFSETS[next]}"
  art="${ARTIFACT_ROOT}/${suite}"
  mkdir -p "${art}/slurm"
  job_id="$(sbatch --parsable --partition="${PARTITION}" --time=00:30:00 \
    --job-name="ad-transfer-d-${suite}" \
    --output="${art}/slurm/%x_%A_%a.out" \
    --error="${art}/slurm/%x_%A_%a.err" \
    --array=0-0%1 \
    --export=ALL,AGENTDOJO_FROZEN_ROOT="${FROZEN_ROOT}",AGENTDOJO_ARTIFACT_ROOT="${art}",AGENTDOJO_SUITE="${suite}",AGENTDOJO_ARRAY_OFFSET="${offset}",VLLM_BASE_PORT="$(suite_port "${suite}")" \
    "${ROOT}/scripts/run_agentdojo_external.slurm" formal 0 "${ROWS_PER_TASK}" attempt-0001 "${suite}")"
  echo "submitted $(date -Is) suite=${suite} offset=${offset} job=${job_id%%;*} active_before=${active}"
  next=$((next + 1))
done
echo "monitor_submitted_all $(date -Is) total=${total}"
