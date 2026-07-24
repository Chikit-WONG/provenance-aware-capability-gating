#!/usr/bin/env bash
# Submit one bounded debug wave for the frozen native AgentDojo plan.
#
# Usage:
#   submit_agentdojo_external_wave.sh development PLAN [ignored-limit]
#   submit_agentdojo_external_wave.sh formal PLAN [rows-per-shard] [shard-start] [wave-shards]
#
# ``shard-start`` and ``wave-shards`` make plans larger than ten shards
# schedulable in sequential waves.  For example, a plan with twelve shards
# at eight rows per shard is submitted as starts 0 and 10 (the second wave has
# two tasks).
set -euo pipefail

PHASE="${1:?phase development or formal}"
PLAN="${2:?frozen plan JSONL path}"
LIMIT="${3:-8}"
SHARD_START="${4:-0}"
MAX_WAVE_TASKS=10
WAVE_SHARDS="${5:-${MAX_WAVE_TASKS}}"
MAX_FORMAL_SHARD_ROWS=8
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SLURM_LOG_DIR="${AGENTDOJO_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-external-v1}/slurm"
mkdir -p "${SLURM_LOG_DIR}"
case "${PHASE}" in
  development) EXPECTED_PLAN_NAME="development_plan.jsonl" ;;
  formal) EXPECTED_PLAN_NAME="formal_plan.jsonl" ;;
  *) echo "phase must be development or formal" >&2; exit 2 ;;
esac

[[ -f "${PLAN}" ]] || { echo "missing frozen plan: ${PLAN}" >&2; exit 2; }
[[ "${LIMIT}" =~ ^[0-9]+$ && "${LIMIT}" -ge 1 ]] || {
  echo "limit must be a positive integer" >&2
  exit 2
}
[[ "${SHARD_START}" =~ ^[0-9]+$ ]] || {
  echo "shard start must be a non-negative integer" >&2
  exit 2
}
[[ "${WAVE_SHARDS}" =~ ^[0-9]+$ && "${WAVE_SHARDS}" -ge 1 ]] || {
  echo "wave shard count must be a positive integer" >&2
  exit 2
}

PLAN_DIR="$(cd "$(dirname "${PLAN}")" && pwd)"
PLAN_NAME="$(basename "${PLAN}")"
[[ "${PLAN_NAME}" == "${EXPECTED_PLAN_NAME}" ]] || {
  echo "${PHASE} plan must be named ${EXPECTED_PLAN_NAME}: ${PLAN}" >&2
  exit 2
}
COUNT="$(awk 'NF{n++} END{print n+0}' "${PLAN}")"
[[ "${COUNT}" -gt 0 ]] || { echo "${PHASE} plan is empty" >&2; exit 2; }

if [[ "${PHASE}" == development ]]; then
  [[ "${SHARD_START}" -eq 0 ]] || { echo "development has one task; shard start must be 0" >&2; exit 2; }
  [[ "${WAVE_SHARDS}" -eq "${MAX_WAVE_TASKS}" ]] || {
    echo "development has one task; omit wave range arguments" >&2
    exit 2
  }
  # A development submission is exactly one task covering the complete plan.
  AGENTDOJO_FROZEN_ROOT="${AGENTDOJO_FROZEN_ROOT:-${PLAN_DIR}}" \
    AGENTDOJO_ARTIFACT_ROOT="${AGENTDOJO_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-external-v1}" \
    sbatch "${ROOT}/scripts/run_agentdojo_external.slurm" development 0 "${COUNT}" attempt-0001
  exit 0
fi

[[ "${LIMIT}" -le "${MAX_FORMAL_SHARD_ROWS}" ]] || {
  echo "formal shard limit must be <= ${MAX_FORMAL_SHARD_ROWS} victim runs" >&2
  exit 2
}
TOTAL_SHARDS=$(( (COUNT + LIMIT - 1) / LIMIT ))
[[ "${SHARD_START}" -lt "${TOTAL_SHARDS}" ]] || {
  echo "shard start ${SHARD_START} is outside ${TOTAL_SHARDS}-shard formal plan" >&2
  exit 2
}
[[ "${WAVE_SHARDS}" -le "${MAX_WAVE_TASKS}" ]] || {
  echo "wave shard count must be <= ${MAX_WAVE_TASKS}" >&2
  exit 2
}
REMAINING_SHARDS=$((TOTAL_SHARDS - SHARD_START))
TASKS_IN_WAVE="${WAVE_SHARDS}"
if [[ "${TASKS_IN_WAVE}" -gt "${REMAINING_SHARDS}" ]]; then
  TASKS_IN_WAVE="${REMAINING_SHARDS}"
fi
ARRAY_END=$((SHARD_START + TASKS_IN_WAVE - 1))
# SLURM array IDs carry the absolute shard offset; the launcher maps each ID
# to LIMIT consecutive rows, so later waves never repeat an earlier shard.
AGENTDOJO_FROZEN_ROOT="${AGENTDOJO_FROZEN_ROOT:-${PLAN_DIR}}" \
  AGENTDOJO_ARTIFACT_ROOT="${AGENTDOJO_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-external-v1}" \
  sbatch --array="${SHARD_START}-${ARRAY_END}%2"     "${ROOT}/scripts/run_agentdojo_external.slurm" formal 0 "${LIMIT}" attempt-0001
