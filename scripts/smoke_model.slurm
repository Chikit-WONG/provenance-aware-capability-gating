#!/usr/bin/env bash
#SBATCH --job-name=agentsec-vllm-smoke
#SBATCH --partition=debug
#SBATCH --gres=gpu:a40:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=00:30:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-smoke-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-smoke-%j.err

set -euo pipefail

PROJECT_ROOT="${SLURM_SUBMIT_DIR:-/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2}"
CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
# Debug/shared nodes are shared; choose and verify an actually free local port.
REQUESTED_VLLM_PORT="${VLLM_PORT:-$((18000 + ${SLURM_JOB_ID:-0} % 1000))}"
VLLM_PORT="$(${PROJECT_ROOT}/scripts/select_vllm_port.sh "${REQUESTED_VLLM_PORT}" "${CONDA_ROOT}/envs/test/bin/python")"
echo "selected vLLM port ${VLLM_PORT}" >&2
SERVER_LOG="${PROJECT_ROOT}/artifacts/vllm-smoke-${SLURM_JOB_ID}.log"

mkdir -p "${PROJECT_ROOT}/artifacts"

VLLM_HOST=127.0.0.1 VLLM_PORT="${VLLM_PORT}" \
  "${PROJECT_ROOT}/scripts/launch_vllm.sh" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null || true; wait "${SERVER_PID}" 2>/dev/null || true' EXIT

READY=0
for _ in $(seq 1 300); do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "vLLM exited during startup; see ${SERVER_LOG}" >&2
    exit 1
  fi
  if curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/health" >/dev/null \
    && curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/v1/models" \
      | grep -q 'qwen3-vl-8b'; then
    READY=1
    break
  fi
  sleep 2
done
if [[ "${READY}" -ne 1 ]]; then
  echo "vLLM was not ready within 600 seconds; see ${SERVER_LOG}" >&2
  exit 1
fi

PYTHON="${CONDA_ROOT}/envs/test/bin/python"
PYTHONPATH="${PROJECT_ROOT}/src" "${PYTHON}" "${PROJECT_ROOT}/scripts/smoke_model.py" \
  --base-url "http://127.0.0.1:${VLLM_PORT}/v1"
