#!/usr/bin/env bash
set -euo pipefail

CONDA_ROOT="/hpc2hdd/home/ckwong627/miniconda3"
ENV_NAME="agentdojo-external"
ENV_PREFIX="${CONDA_ROOT}/envs/${ENV_NAME}"
CONDA="${CONDA_ROOT}/bin/conda"
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -x "${ENV_PREFIX}/bin/python" ]]; then
  "${CONDA}" create --yes --name "${ENV_NAME}" python=3.11
fi

"${CONDA}" run --no-capture-output --name "${ENV_NAME}" \
  python -m pip install --requirement "${PROJECT_DIR}/requirements-agentdojo-external.txt"
"${CONDA}" run --no-capture-output --name "${ENV_NAME}" \
  python -m pip install --editable "${PROJECT_DIR}[analysis]"

"${CONDA}" run --no-capture-output --name "${ENV_NAME}" python - <<'PY'
from importlib.metadata import version

assert version("agentdojo") == "0.1.35", version("agentdojo")
print("agentdojo", version("agentdojo"))
PY
