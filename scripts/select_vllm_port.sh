#!/usr/bin/env bash
# Print the first localhost TCP port that can be bound right now.
# vLLM otherwise silently increments a busy --port, which can make a caller's
# health check and requests reach a different service on a shared node.
set -euo pipefail

BASE_PORT="${1:?base port is required}"
PYTHON="${2:-python3}"

for offset in $(seq 0 100); do
  port=$((BASE_PORT + offset))
  if "${PYTHON}" - "${port}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
  then
    printf '%s\n' "${port}"
    exit 0
  fi
done

echo "no free localhost port in ${BASE_PORT}..$((BASE_PORT + 100))" >&2
exit 1
