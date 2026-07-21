#!/usr/bin/env bash
#SBATCH --job-name=agentsec-red-hard
#SBATCH --partition=debug
#SBATCH --gres=gpu:a40:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=00:30:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/slurm-red-hard-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/slurm-red-hard-%j.err

set -euo pipefail

PROJECT_ROOT="/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating"
CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
CORPUS_DIR="${PROJECT_ROOT}/data/frozen/red_corpus_qwen3_hardened_v1"
PROMPT="${PROJECT_ROOT}/configs/prompts/red_agent_hardened_system.txt"
PYTHON="${CONDA_ROOT}/envs/test/bin/python"

cd "${PROJECT_ROOT}"
mkdir -p artifacts
if [[ -e "${CORPUS_DIR}" ]]; then
  echo "hardened Red corpus refused: destination already exists: ${CORPUS_DIR}" >&2
  exit 2
fi

REQUESTED_VLLM_PORT="${VLLM_PORT:-$((18000 + ${SLURM_JOB_ID:-0} % 1000))}"
VLLM_PORT="$("${PROJECT_ROOT}/scripts/select_vllm_port.sh" "${REQUESTED_VLLM_PORT}" "${PYTHON}")"
SERVER_LOG="${PROJECT_ROOT}/artifacts/vllm-red-hard-${SLURM_JOB_ID}.log"
export PYTHONPATH="${PROJECT_ROOT}/src"
VLLM_HOST=127.0.0.1 VLLM_PORT="${VLLM_PORT}" \
  scripts/launch_vllm.sh >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null || true; wait "${SERVER_PID}" 2>/dev/null || true' EXIT

READY=0
for _ in $(seq 1 300); do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then exit 1; fi
  if curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/health" >/dev/null \
    && curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/v1/models" | grep -q 'qwen3-vl-8b'; then
    READY=1
    break
  fi
  sleep 2
done
[[ "${READY}" -eq 1 ]]

"${PYTHON}" scripts/generate_red_corpus.py \
  --backend vllm \
  --base-url "http://127.0.0.1:${VLLM_PORT}/v1" \
  --model qwen3-vl-8b \
  --system-prompt "${PROMPT}" \
  --validation-profile hardened \
  --output "${CORPUS_DIR}"

"${PYTHON}" - <<'PY'
from pathlib import Path
from agentsec.redteam import verify_frozen_corpus

root = Path("data/frozen/red_corpus_qwen3_hardened_v1")
manifest = verify_frozen_corpus(root)
assert manifest.formal_eligible
assert len(manifest.scenarios) == 6
assert all(len(item.candidates) == 5 for item in manifest.scenarios)
print("verified hardened formal Red corpus", root)
PY
