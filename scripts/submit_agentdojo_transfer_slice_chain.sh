#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROZEN_ROOT="${AGENTDOJO_TRANSFER_FROZEN_ROOT:-${ROOT}/configs/frozen/agentdojo_public_transfer_slice_v1}"
ARTIFACT_ROOT="${AGENTDOJO_TRANSFER_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-public-transfer-slice-v1}"
ROWS_PER_SHARD="${AGENTDOJO_TRANSFER_ROWS_PER_SHARD:-8}"
WAVE_SHARDS="${AGENTDOJO_TRANSFER_WAVE_SHARDS:-8}"

[[ "${ROWS_PER_SHARD}" -ge 1 && "${ROWS_PER_SHARD}" -le 8 ]] || exit 2
[[ "${WAVE_SHARDS}" -ge 1 && "${WAVE_SHARDS}" -le 8 ]] || exit 2

mkdir -p "${ARTIFACT_ROOT}/slurm"
declare -a JOB_SUMMARY=()
suite_index=0
for suite in workspace travel banking slack; do
  plan="${FROZEN_ROOT}/${suite}/formal_plan.jsonl"
  [[ -f "${plan}" ]] || { echo "missing plan: ${plan}" >&2; exit 2; }
  count="$(awk 'NF{n++} END{print n+0}' "${plan}")"
  total_shards=$(( (count + ROWS_PER_SHARD - 1) / ROWS_PER_SHARD ))
  previous=""
  suite_root="${ARTIFACT_ROOT}/${suite}"
  suite_base_port=$((18000 + suite_index * 4000))
  for ((start=0; start<total_shards; start+=WAVE_SHARDS)); do
    end=$((start + WAVE_SHARDS - 1))
    if (( end >= total_shards )); then end=$((total_shards - 1)); fi
    dependency=()
    if [[ -n "${previous}" ]]; then dependency=("--dependency=afterany:${previous}"); fi
    job_id="$(AGENTDOJO_FROZEN_ROOT="${FROZEN_ROOT}" \
      AGENTDOJO_ARTIFACT_ROOT="${suite_root}" \
      AGENTDOJO_SUITE="${suite}" \
      VLLM_BASE_PORT="${suite_base_port}" \
      sbatch --parsable "${dependency[@]}" \
        --job-name="ad-transfer-${suite}" \
        --output="${suite_root}/slurm/%x-%A_%a.out" \
        --error="${suite_root}/slurm/%x-%A_%a.err" \
        --array="${start}-${end}%2" \
        "${ROOT}/scripts/run_agentdojo_external.slurm" formal 0 "${ROWS_PER_SHARD}" attempt-0001 "${suite}")"
    previous="${job_id%%;*}"
    JOB_SUMMARY+=("${suite} wave_start=${start} wave_end=${end} job=${previous}")
  done
  suite_index=$((suite_index + 1))
done

for summary in "${JOB_SUMMARY[@]}"; do echo "${summary}"; done
