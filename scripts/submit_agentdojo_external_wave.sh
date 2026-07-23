#!/usr/bin/env bash
set -euo pipefail
PHASE="${1:?phase development or formal}"
PLAN="${2:?frozen plan JSONL path}"
LIMIT="${3:-8}"
MAX_WAVE_TASKS=10
FORMAL_PLAN_NAME=formal_plan.jsonl  # formal shards default to 8 victim runs
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "${PLAN}" ]] || { echo "missing frozen plan: ${PLAN}" >&2; exit 2; }
[[ "${LIMIT}" -ge 1 ]] || { echo "limit must be positive" >&2; exit 2; }
COUNT="$(awk 'NF{n++} END{print n+0}' "${PLAN}")"
if [[ "${PHASE}" == development ]]; then
  [[ "${COUNT}" -gt 0 ]] || { echo "development plan is empty" >&2; exit 2; }
  sbatch "${ROOT}/scripts/run_agentdojo_external.slurm" development 0 "${COUNT}" attempt-0001
  exit 0
fi
[[ "${PHASE}" == formal ]] || { echo "phase must be development or formal" >&2; exit 2; }
SHARDS=$(( (COUNT + LIMIT - 1) / LIMIT ))
[[ "${SHARDS}" -gt 0 ]] || { echo "formal plan is empty" >&2; exit 2; }
[[ "${SHARDS}" -le "${MAX_WAVE_TASKS}" ]] || { echo "wave exceeds ${MAX_WAVE_TASKS} debug tasks; lower shard limit" >&2; exit 2; }
ARRAY_MAX=$((SHARDS - 1))
sbatch --array="0-${ARRAY_MAX}%2" "${ROOT}/scripts/run_agentdojo_external.slurm" formal 0 "${LIMIT}" attempt-0001
