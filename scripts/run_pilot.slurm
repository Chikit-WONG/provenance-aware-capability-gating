#!/usr/bin/env bash
#SBATCH --job-name=agentsec-pilot
#SBATCH --partition=i64m1tga40u
#SBATCH --gres=gpu:a40:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=07-00:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-pilot-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-pilot-%j.err

set -euo pipefail
PROJECT_ROOT="${SLURM_SUBMIT_DIR:-/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2}"
CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
CORPUS_DIR="${PROJECT_ROOT}/data/frozen/red_corpus_qwen3_v1"
PILOT_CANDIDATE="${PILOT_CANDIDATE:-1}"
if [[ ! "${PILOT_CANDIDATE}" =~ ^[123]$ ]]; then
  echo "PILOT_CANDIDATE must be 1, 2, or 3" >&2
  exit 2
fi
PILOT_ROOT="${PROJECT_ROOT}/artifacts/pilot-candidate${PILOT_CANDIDATE}"
PILOT_REPORT="${PROJECT_ROOT}/artifacts/pilot-gates-candidate${PILOT_CANDIDATE}.json"
# Debug/shared nodes are shared; choose and verify an actually free local port.
REQUESTED_VLLM_PORT="${VLLM_PORT:-$((18000 + ${SLURM_JOB_ID:-0} % 1000))}"
VLLM_PORT="$(${PROJECT_ROOT}/scripts/select_vllm_port.sh "${REQUESTED_VLLM_PORT}" "${CONDA_ROOT}/envs/test/bin/python")"
echo "selected vLLM port ${VLLM_PORT}" >&2
SERVER_LOG="${PROJECT_ROOT}/artifacts/vllm-pilot-${SLURM_JOB_ID}.log"
cd "${PROJECT_ROOT}"
mkdir -p artifacts

VLLM_HOST=127.0.0.1 VLLM_PORT="${VLLM_PORT}" scripts/launch_vllm.sh >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null || true; wait "${SERVER_PID}" 2>/dev/null || true' EXIT
READY=0
for _ in $(seq 1 360); do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then exit 1; fi
  if curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/health" >/dev/null \
    && curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/v1/models" \
      | grep -q 'qwen3-vl-8b'; then READY=1; break; fi
  sleep 2
done
[[ "${READY}" -eq 1 ]]
export PYTHONPATH="${PROJECT_ROOT}/src"
PYTHON="${CONDA_ROOT}/envs/test/bin/python"
"${PYTHON}" scripts/run_pilot.py --corpus-dir "${CORPUS_DIR}" --output-root "${PILOT_ROOT}" \
  --pilot-report "${PILOT_REPORT}" --candidate-index "${PILOT_CANDIDATE}" \
  --base-url "http://127.0.0.1:${VLLM_PORT}/v1"
