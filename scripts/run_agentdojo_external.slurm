#!/usr/bin/env bash
#SBATCH --job-name=agentdojo-ext
#SBATCH --partition=debug
#SBATCH --gres=gpu:a40:1
#SBATCH --cpus-per-task=8
#SBATCH --time=00:30:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/agentdojo-external-v1/slurm/%x-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/agentdojo-external-v1/slurm/%x-%j.err
set -euo pipefail

PHASE="${1:?phase development or formal}"
START_INDEX="${2:-0}"
LIMIT="${3:-12}"
ATTEMPT_ID="${4:-attempt-0001}"
if [[ "${PHASE}" == formal && -n "${SLURM_ARRAY_TASK_ID:-}" ]]; then
  START_INDEX=$((SLURM_ARRAY_TASK_ID * LIMIT))
fi
MODEL_PATH="/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
PROJECT_ROOT="${AGENTDOJO_PROJECT_ROOT:-/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating}"
ARTIFACT_ROOT="${AGENTDOJO_ARTIFACT_ROOT:-${PROJECT_ROOT}/artifacts/agentdojo-external-v1}"
FROZEN_ROOT="${AGENTDOJO_FROZEN_ROOT:-${PROJECT_ROOT}/configs/frozen/agentdojo_external_v1}"
mkdir -p "${ARTIFACT_ROOT}/slurm"

case "${PHASE}" in
  development) PLAN="${FROZEN_ROOT}/development_plan.jsonl" ;;
  formal) PLAN="${FROZEN_ROOT}/formal_plan.jsonl" ;;
  *) echo "phase must be development or formal" >&2; exit 2 ;;
esac
[[ -f "${PLAN}" ]] || { echo "missing frozen plan: ${PLAN}" >&2; exit 2; }

BASE_PORT="${VLLM_BASE_PORT:-18000}"
PORT="$("${PROJECT_ROOT}/scripts/select_vllm_port.sh" "${BASE_PORT}")"
export VLLM_PORT="${PORT}"
VLLM_LOG="${ARTIFACT_ROOT}/slurm/vllm-${SLURM_JOB_ID:-local}.log"
CONTROLLER_LOG="${ARTIFACT_ROOT}/slurm/controller-${SLURM_JOB_ID:-local}.log"
"${PROJECT_ROOT}/scripts/launch_vllm.sh" >"${VLLM_LOG}" 2>&1 &
VLLM_PID=$!
cleanup() { kill "${VLLM_PID}" 2>/dev/null || true; wait "${VLLM_PID}" 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:${PORT}/v1/models" >/dev/null; then break; fi
  sleep 1
done
curl --fail --silent "http://127.0.0.1:${PORT}/v1/models" >/dev/null
source "/hpc2hdd/home/ckwong627/miniconda3/etc/profile.d/conda.sh"
conda run -n agentdojo-external python "${PROJECT_ROOT}/scripts/run_agentdojo_external.py"   --plan "${PLAN}" --artifact-root "${ARTIFACT_ROOT}" --phase "${PHASE}"   --start-index "${START_INDEX}" --limit "${LIMIT}" --attempt-id "${ATTEMPT_ID}" --port "${PORT}"   2>&1 | tee "${CONTROLLER_LOG}"
