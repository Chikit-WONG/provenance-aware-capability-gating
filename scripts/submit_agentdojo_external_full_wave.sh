#!/usr/bin/env bash
set -euo pipefail
PHASE="${1:?phase development or formal}"
FROZEN_ROOT="${2:?full frozen root}"
LIMIT="${3:-8}"
SHARD_START="${4:-0}"
WAVE_SHARDS="${5:-10}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="${AGENTDOJO_ARTIFACT_ROOT:-${ROOT}/artifacts/agentdojo-external-full-v1}"
for suite in workspace travel banking slack; do
  plan="${FROZEN_ROOT}/${suite}/${PHASE}_plan.jsonl"
  [[ -f "${plan}" ]] || { echo "missing ${suite} ${PHASE} plan: ${plan}" >&2; exit 2; }
  suite_artifacts="${ARTIFACT_ROOT}/${suite}"
  mkdir -p "${suite_artifacts}/slurm"
  if [[ "${PHASE}" == development ]]; then
    AGENTDOJO_FROZEN_ROOT="${FROZEN_ROOT}" AGENTDOJO_ARTIFACT_ROOT="${suite_artifacts}" AGENTDOJO_SUITE="${suite}" \
      sbatch "${ROOT}/scripts/run_agentdojo_external.slurm" development 0 "$(awk 'NF{n++} END{print n+0}' "${plan}")" attempt-0001 "${suite}"
  else
    AGENTDOJO_FROZEN_ROOT="${FROZEN_ROOT}/${suite}" AGENTDOJO_ARTIFACT_ROOT="${suite_artifacts}" \
      bash "${ROOT}/scripts/submit_agentdojo_external_wave.sh" formal "${plan}" "${LIMIT}" "${SHARD_START}" "${WAVE_SHARDS}"
  fi
done
