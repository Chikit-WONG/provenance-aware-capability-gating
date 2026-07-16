#!/usr/bin/env bash
set -euo pipefail

MODEL_PATH="/hpc2hdd/home/ckwong627/workdir/new_sub_workdir/EEG_Project/models/Qwen3-VL-8B-Instruct"
CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
HOST="${VLLM_HOST:-127.0.0.1}"
PORT="${VLLM_PORT:-8000}"

if [[ ! -f "${MODEL_PATH}/model.safetensors.index.json" ]]; then
  echo "Local model is incomplete or missing: ${MODEL_PATH}" >&2
  exit 2
fi

# Formal runs are offline: a missing local asset must fail, never download.
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
export TOKENIZERS_PARALLELISM=false

source "${CONDA_ROOT}/etc/profile.d/conda.sh"
conda activate vllm

exec vllm serve "${MODEL_PATH}" \
  --host "${HOST}" \
  --port "${PORT}" \
  --dtype bfloat16 \
  --max-model-len 8192 \
  --tensor-parallel-size 1 \
  --max-num-seqs 4 \
  --gpu-memory-utilization "${VLLM_GPU_MEMORY_UTILIZATION:-0.90}" \
  --served-model-name qwen3-vl-8b \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --limit-mm-per-prompt '{"image":0,"video":0}'
