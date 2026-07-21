#!/usr/bin/env bash
# Run one paired 108-cell group from the hardened completion factorial.
#SBATCH --job-name=agentsec-hard-missing
#SBATCH --partition=debug
#SBATCH --gres=gpu:a40:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=00:30:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/slurm-hard-missing-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/slurm-hard-missing-%j.err

set -euo pipefail

PROJECT_ROOT="/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating"
CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
CORPUS_DIR="${PROJECT_ROOT}/data/frozen/red_corpus_qwen3_hardened_v1"
PILOT_REPORT="${PROJECT_ROOT}/artifacts/pilot-gates-candidate3.json"
PYTHON="${CONDA_ROOT}/envs/test/bin/python"
HARDENED_GROUP="${HARDENED_GROUP:-}"

case "${HARDENED_GROUP}" in
  baseline)
    PLAN_DIR="${PROJECT_ROOT}/configs/frozen/hardened_missing_baseline_v1"
    ARTIFACT_ROOT="${PROJECT_ROOT}/artifacts/hardened-missing-baseline-v1"
    ;;
  capability)
    PLAN_DIR="${PROJECT_ROOT}/configs/frozen/hardened_missing_capability_v1"
    ARTIFACT_ROOT="${PROJECT_ROOT}/artifacts/hardened-missing-capability-v1"
    ;;
  provenance_prompt)
    PLAN_DIR="${PROJECT_ROOT}/configs/frozen/hardened_missing_provenance_prompt_v1"
    ARTIFACT_ROOT="${PROJECT_ROOT}/artifacts/hardened-missing-provenance-prompt-v1"
    ;;
  *)
    echo "HARDENED_GROUP must be baseline, capability, or provenance_prompt" >&2
    exit 2
    ;;
esac

cd "${PROJECT_ROOT}"
mkdir -p artifacts
if [[ -e "${ARTIFACT_ROOT}" ]]; then
  echo "hardened completion refused: append-only output exists: ${ARTIFACT_ROOT}" >&2
  exit 2
fi

"${PYTHON}" - "${PILOT_REPORT}" "${PLAN_DIR}" "${CORPUS_DIR}" <<'PY'
import json
import sys
from pathlib import Path

pilot, plan, corpus = map(Path, sys.argv[1:])
if not pilot.is_file() or not json.loads(pilot.read_text(encoding="utf-8"))["passed"]:
    raise SystemExit("hardened completion refused: pilot gates did not pass")
if not plan.is_dir() or not corpus.is_dir():
    raise SystemExit("hardened completion refused: frozen input is missing")
PY

REQUESTED_VLLM_PORT="${VLLM_PORT:-$((18000 + ${SLURM_JOB_ID:-0} % 1000))}"
VLLM_PORT="$("${PROJECT_ROOT}/scripts/select_vllm_port.sh" "${REQUESTED_VLLM_PORT}" "${PYTHON}")"
SERVER_LOG="${PROJECT_ROOT}/artifacts/vllm-hard-missing-${HARDENED_GROUP}-${SLURM_JOB_ID}.log"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 TOKENIZERS_PARALLELISM=false
export PYTHONPATH="${PROJECT_ROOT}/src"
VLLM_HOST=127.0.0.1 VLLM_PORT="${VLLM_PORT}" \
  scripts/launch_vllm.sh >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null || true; wait "${SERVER_PID}" 2>/dev/null || true' EXIT

READY=0
for _ in $(seq 1 360); do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then exit 1; fi
  if curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/health" >/dev/null \
    && curl --silent --fail "http://127.0.0.1:${VLLM_PORT}/v1/models" \
      | grep -q 'qwen3-vl-8b'; then
    READY=1
    break
  fi
  sleep 2
done
[[ "${READY}" -eq 1 ]]

set +e
"${PYTHON}" scripts/run_experiment.py \
  --plan-dir "${PLAN_DIR}" \
  --corpus-dir "${CORPUS_DIR}" \
  --output-root "${ARTIFACT_ROOT}" \
  --base-url "http://127.0.0.1:${VLLM_PORT}/v1"
RUN_STATUS=$?
set -e
if [[ "${RUN_STATUS}" -ne 0 && "${RUN_STATUS}" -ne 2 ]]; then
  exit "${RUN_STATUS}"
fi
exit "${RUN_STATUS}"
