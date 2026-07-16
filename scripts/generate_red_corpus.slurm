#!/usr/bin/env bash
#SBATCH --job-name=agentsec-red-freeze
#SBATCH --partition=debug
#SBATCH --gres=gpu:a40:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=00:30:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-red-freeze-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-red-freeze-%j.err

set -euo pipefail

PROJECT_ROOT="${SLURM_SUBMIT_DIR:-/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2}"
CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
# Debug nodes are shared; choose and verify an actually free local API port.
REQUESTED_VLLM_PORT="${VLLM_PORT:-$((18000 + ${SLURM_JOB_ID:-0} % 1000))}"
VLLM_PORT="$(${PROJECT_ROOT}/scripts/select_vllm_port.sh "${REQUESTED_VLLM_PORT}" "${CONDA_ROOT}/envs/test/bin/python")"
echo "selected vLLM port ${VLLM_PORT}" >&2
SERVER_LOG="${PROJECT_ROOT}/artifacts/vllm-red-freeze-${SLURM_JOB_ID}.log"
CORPUS_DIR="${PROJECT_ROOT}/data/frozen/red_corpus_qwen3_v1"

cd "${PROJECT_ROOT}"
mkdir -p "${PROJECT_ROOT}/artifacts" "${PROJECT_ROOT}/data/frozen"

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

export PYTHONPATH="${PROJECT_ROOT}/src"
PYTHON="${CONDA_ROOT}/envs/test/bin/python"
"${PYTHON}" "${PROJECT_ROOT}/scripts/generate_red_corpus.py" \
  --backend vllm \
  --base-url "http://127.0.0.1:${VLLM_PORT}/v1" \
  --model qwen3-vl-8b \
  --output "${CORPUS_DIR}"

"${PYTHON}" - <<'PY'
from agentsec.redteam import verify_frozen_corpus
from pathlib import Path
root = Path("data/frozen/red_corpus_qwen3_v1")
manifest = verify_frozen_corpus(root)
assert manifest.formal_eligible
assert len(manifest.scenarios) == 6
assert all(len(item.candidates) == 5 for item in manifest.scenarios)
print(f"verified formal Red corpus: {root}")
PY

# Submit the remaining stages only after this job has successfully frozen and
# verified the corpus.  Delaying submission avoids consuming the user's job
# slots while Red is waiting for a GPU, and using --parsable prevents manual ID
# mix-ups in the dependency chain.
FREEZE_JOB="$(sbatch --parsable --dependency=afterok:${SLURM_JOB_ID} scripts/freeze_plan.slurm)"
PILOT_JOB="$(sbatch --parsable --dependency=afterok:${FREEZE_JOB} scripts/run_pilot.slurm)"
FORMAL_JOB="$(sbatch --parsable --dependency=afterok:${PILOT_JOB} scripts/run_formal.slurm)"
echo "submitted dependency chain: freeze=${FREEZE_JOB} pilot=${PILOT_JOB} formal=${FORMAL_JOB}"
