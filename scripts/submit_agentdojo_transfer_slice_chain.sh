#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FROZEN_ROOT="${AGENTDOJO_TRANSFER_FROZEN_ROOT:-${ROOT}/configs/frozen/agentdojo_public_transfer_slice_v1}"
ARTIFACT_ROOT="${AGENTDOJO_TRANSFER_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-public-transfer-slice-v1}"
ROWS_PER_SHARD="${AGENTDOJO_TRANSFER_ROWS_PER_SHARD:-8}"

[[ "${ROWS_PER_SHARD}" -ge 1 && "${ROWS_PER_SHARD}" -le 8 ]] || exit 2

mkdir -p "${ARTIFACT_ROOT}/slurm"
declare -a JOB_SUMMARY=()
suite_index=0
for suite in workspace travel banking slack; do
  plan="${FROZEN_ROOT}/${suite}/formal_plan.jsonl"
  [[ -f "${plan}" ]] || { echo "missing plan: ${plan}" >&2; exit 2; }
  count="$(awk 'NF{n++} END{print n+0}' "${plan}")"
  total_shards=$(( (count + ROWS_PER_SHARD - 1) / ROWS_PER_SHARD ))
  suite_root="${ARTIFACT_ROOT}/${suite}"
  suite_base_port=$((18000 + suite_index * 4000))
  end=$((total_shards - 1))
  job_id="$(AGENTDOJO_FROZEN_ROOT="${FROZEN_ROOT}" \
    AGENTDOJO_ARTIFACT_ROOT="${suite_root}" \
    AGENTDOJO_SUITE="${suite}" \
    VLLM_BASE_PORT="${suite_base_port}" \
    sbatch --parsable \
      --job-name="ad-transfer-${suite}" \
      --output="${suite_root}/slurm/%x_%A_%a.out" \
      --error="${suite_root}/slurm/%x_%A_%a.err" \
      --array="0-${end}%2" \
      "${ROOT}/scripts/run_agentdojo_external.slurm" formal 0 "${ROWS_PER_SHARD}" attempt-0001 "${suite}")"
  JOB_SUMMARY+=("${suite} shards=0-${end} job=${job_id%%;*}")
  suite_index=$((suite_index + 1))
done

for summary in "${JOB_SUMMARY[@]}"; do echo "${summary}"; done
