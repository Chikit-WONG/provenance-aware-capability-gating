#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

exec /hpc2hdd/home/ckwong627/miniconda3/envs/test/bin/python \
  -m unittest discover -s "$PROJECT_ROOT/tests" -p 'test_*.py' -v

