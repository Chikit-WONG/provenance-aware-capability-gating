#!/usr/bin/env bash
#SBATCH --job-name=agentsec-ablation
#SBATCH --partition=i64m1tga40u
#SBATCH --gres=gpu:a40:1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH --time=07-00:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/slurm-ablation-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating/artifacts/slurm-ablation-%j.err

set -euo pipefail

PROJECT_ROOT="/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/provenance-aware-capability-gating"
CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
CORPUS_DIR="${PROJECT_ROOT}/data/frozen/red_corpus_qwen3_v1"
FORMAL_PLAN_DIR="${PROJECT_ROOT}/configs/frozen/formal_plan_v1"
ABLATION_PLAN_DIR="${PROJECT_ROOT}/configs/frozen/ablation_plan_v1"
FORMAL_ARTIFACT_ROOT="${PROJECT_ROOT}/artifacts/formal-v1"
ABLATION_ARTIFACT_ROOT="${PROJECT_ROOT}/artifacts/ablation-v1"
ANALYSIS_DIR="${PROJECT_ROOT}/artifacts/ablation-analysis-v1"
PILOT_REPORT="${PROJECT_ROOT}/artifacts/pilot-gates-candidate3.json"
PYTHON="${CONDA_ROOT}/envs/test/bin/python"

cd "${PROJECT_ROOT}"
mkdir -p artifacts

for output_path in "${ABLATION_ARTIFACT_ROOT}" "${ANALYSIS_DIR}"; do
  if [[ -e "${output_path}" ]]; then
    echo "ablation run refused: append-only output already exists: ${output_path}" >&2
    exit 2
  fi
done

"${PYTHON}" - "${PILOT_REPORT}" "${ABLATION_PLAN_DIR}" "${FORMAL_ARTIFACT_ROOT}" <<'PY'
import json
import sys
from pathlib import Path

pilot_report, ablation_plan, formal_artifacts = map(Path, sys.argv[1:])
if not pilot_report.is_file() or not json.loads(pilot_report.read_text())["passed"]:
    raise SystemExit("ablation run refused: candidate-3 development pilot gates did not pass")
if not ablation_plan.is_dir():
    raise SystemExit("ablation run refused: frozen ablation plan is missing")
if not formal_artifacts.is_dir():
    raise SystemExit("ablation run refused: formal-v1 artifacts are missing")
PY

# Shared GPU nodes need a verified free loopback port for the single vLLM server.
REQUESTED_VLLM_PORT="${VLLM_PORT:-$((18000 + ${SLURM_JOB_ID:-0} % 1000))}"
VLLM_PORT="$("${PROJECT_ROOT}/scripts/select_vllm_port.sh" \
  "${REQUESTED_VLLM_PORT}" "${PYTHON}")"
echo "selected vLLM port ${VLLM_PORT}" >&2
SERVER_LOG="${PROJECT_ROOT}/artifacts/vllm-ablation-${SLURM_JOB_ID}.log"

export PYTHONPATH="${PROJECT_ROOT}/src"
VLLM_HOST=127.0.0.1 VLLM_PORT="${VLLM_PORT}" \
  scripts/launch_vllm.sh >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
trap 'kill "${SERVER_PID}" 2>/dev/null || true; wait "${SERVER_PID}" 2>/dev/null || true' EXIT

READY=0
for _ in $(seq 1 360); do
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
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
[[ "${READY}" -eq 1 ]]

# The runner completes all frozen cells and returns 2 if any record is invalid.
# Preserve that status, but aggregate the complete ITT artifact set first.
set +e
"${PYTHON}" scripts/run_experiment.py \
  --plan-dir "${ABLATION_PLAN_DIR}" \
  --corpus-dir "${CORPUS_DIR}" \
  --output-root "${ABLATION_ARTIFACT_ROOT}" \
  --base-url "http://127.0.0.1:${VLLM_PORT}/v1"
RUN_STATUS=$?
set -e
if [[ "${RUN_STATUS}" -ne 0 && "${RUN_STATUS}" -ne 2 ]]; then
  exit "${RUN_STATUS}"
fi

"${PYTHON}" scripts/analyze_results.py \
  --artifact-root "${FORMAL_ARTIFACT_ROOT}" \
  --artifact-root "${ABLATION_ARTIFACT_ROOT}" \
  --plan-dir "${FORMAL_PLAN_DIR}" \
  --plan-dir "${ABLATION_PLAN_DIR}" \
  --output-dir "${ANALYSIS_DIR}"

exit "${RUN_STATUS}"
