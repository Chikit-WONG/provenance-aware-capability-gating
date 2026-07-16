#!/usr/bin/env bash
# Freeze the formal 216-cell plan only after a verified Red corpus exists.
# This is CPU-only and intentionally refuses to overwrite an existing plan.
#SBATCH --job-name=agentsec-freeze-plan
#SBATCH --partition=i64m512u
#SBATCH --cpus-per-task=4
#SBATCH --mem=16G
#SBATCH --time=00:30:00
#SBATCH --output=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-freeze-plan-%j.out
#SBATCH --error=/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2/artifacts/slurm-freeze-plan-%j.err

set -euo pipefail
PROJECT_ROOT="${SLURM_SUBMIT_DIR:-/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/Class/AIAA4313_L01-Frontier_Topics_in_AI_Security_and_Privacy/Group_Project/test/ckw-test2}"
PYTHON="/hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python"
cd "${PROJECT_ROOT}"
mkdir -p artifacts
export PYTHONPATH="${PROJECT_ROOT}/src"
"${PYTHON}" scripts/freeze_run_plan.py \
  --corpus-dir data/frozen/red_corpus_qwen3_v1 \
  --output-dir configs/frozen/formal_plan_v1 \
  --model-config configs/model.json \
  --project-root "${PROJECT_ROOT}"
