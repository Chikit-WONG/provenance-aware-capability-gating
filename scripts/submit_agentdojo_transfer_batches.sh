#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROZEN_ROOT="${AGENTDOJO_TRANSFER_FROZEN_ROOT:-${ROOT}/configs/frozen/agentdojo_public_transfer_slice_v1}"
ARTIFACT_ROOT="${AGENTDOJO_TRANSFER_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-public-transfer-slice-v1}"
PARTITION="${AGENTDOJO_TRANSFER_PARTITION:-i64m1tga40u}"
ROWS_PER_TASK="${AGENTDOJO_TRANSFER_ROWS_PER_TASK:-80}"
TASKS_PER_ARRAY="${AGENTDOJO_TRANSFER_TASKS_PER_ARRAY:-10}"
WALLTIME="${AGENTDOJO_TRANSFER_WALLTIME:-02:00:00}"
# The first workspace array (job 10064412) already covers rows 0:80.
WORKSPACE_OFFSET="${AGENTDOJO_TRANSFER_WORKSPACE_OFFSET:-0}"

[[ "${ROWS_PER_TASK}" -ge 1 ]] || exit 2
[[ "${TASKS_PER_ARRAY}" -ge 1 && "${TASKS_PER_ARRAY}" -le 10 ]] || exit 2
mkdir -p "${ARTIFACT_ROOT}/slurm"

for suite in workspace travel banking slack; do
  plan="${FROZEN_ROOT}/${suite}/formal_plan.jsonl"
  [[ -f "${plan}" ]] || { echo "missing plan: ${plan}" >&2; exit 2; }
  count="$(awk 'NF{n++} END{print n+0}' "${plan}")"
  offset=0
  if [[ "${suite}" == workspace ]]; then offset="${WORKSPACE_OFFSET}"; fi
  (( offset < count )) || continue
  suite_root="${ARTIFACT_ROOT}/${suite}"
  mkdir -p "${suite_root}/slurm"
  case "${suite}" in
    workspace) suite_base_port=18000 ;;
    travel) suite_base_port=22000 ;;
    banking) suite_base_port=26000 ;;
    slack) suite_base_port=30000 ;;
  esac
  remaining=$((count - offset))
  while (( remaining > 0 )); do
    tasks=$(( (remaining + ROWS_PER_TASK - 1) / ROWS_PER_TASK ))
    if (( tasks > TASKS_PER_ARRAY )); then tasks="${TASKS_PER_ARRAY}"; fi
    last_task=$((tasks - 1))
    job_id="$(AGENTDOJO_FROZEN_ROOT="${FROZEN_ROOT}" \
      AGENTDOJO_ARTIFACT_ROOT="${suite_root}" \
      AGENTDOJO_SUITE="${suite}" \
      AGENTDOJO_ARRAY_OFFSET="${offset}" \
      VLLM_BASE_PORT="${suite_base_port}" \
      sbatch --parsable --partition="${PARTITION}" --time="${WALLTIME}" \
        --job-name="ad-transfer-${suite}" \
        --output="${suite_root}/slurm/%x_%A_%a.out" \
        --error="${suite_root}/slurm/%x_%A_%a.err" \
        --array="0-${last_task}%2" \
        "${ROOT}/scripts/run_agentdojo_external.slurm" formal 0 "${ROWS_PER_TASK}" attempt-0001 "${suite}")"
    echo "${suite} offset=${offset} tasks=0-${last_task} job=${job_id%%;*}"
    offset=$((offset + tasks * ROWS_PER_TASK))
    remaining=$((count - offset))
  done
done
