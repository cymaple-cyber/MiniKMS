#!/usr/bin/env bash
# Trusted KMS one-click startup — run from repository root: ./start-trusted-kms.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PY="${ROOT}/.venv/bin/python"
PORT="${ENCLAVE_PORT:-9787}"
API_PORT="${API_PORT:-8000}"
ENV_FILE="${ROOT}/.env"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

read_env() {
  local key="$1"
  if [[ -f "$ENV_FILE" ]]; then
    local line
    line="$(grep -E "^${key}=" "$ENV_FILE" | tail -1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s' "${line#*=}"
      return 0
    fi
  fi
  return 1
}

cleanup() {
  [[ -n "${ENCLAVE_PID:-}" ]] && kill "$ENCLAVE_PID" 2>/dev/null || true
  [[ -n "${API_PID:-}" ]] && kill "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

[[ -x "$PY" ]] || {
  red "Missing virtualenv. Run:"
  echo "  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
}

MASTER_KEY="${MASTER_KEY:-$(read_env MASTER_KEY || true)}"
JWT_SECRET_KEY="${JWT_SECRET_KEY:-$(read_env JWT_SECRET_KEY || true)}"
DATABASE_URL="${DATABASE_URL:-$(read_env DATABASE_URL || echo 'sqlite:///./data/minikms.db')}"
ACCESS_TOKEN_EXPIRE_MINUTES="${ACCESS_TOKEN_EXPIRE_MINUTES:-$(read_env ACCESS_TOKEN_EXPIRE_MINUTES || echo '60')}"

if [[ -z "$MASTER_KEY" ]]; then
  red "MASTER_KEY not found. Add it to .env or run:"
  echo '  MASTER_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())") ./start-trusted-kms.sh'
  exit 1
fi

if [[ -z "$JWT_SECRET_KEY" || "$JWT_SECRET_KEY" == replace-with* ]]; then
  JWT_SECRET_KEY="$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")"
  green "Generated ephemeral JWT_SECRET_KEY for this run"
fi

mkdir -p "${ROOT}/data"

while nc -z 127.0.0.1 "$API_PORT" 2>/dev/null; do
  API_PORT=$((API_PORT + 1))
done

green "▶ Starting Enclave (Master Key stays in enclave process)..."
(
  cd "$ROOT"
  export MASTER_KEY
  export ENCLAVE_PORT="$PORT"
  exec "$PY" -m enclave.kms_enclave
) &
ENCLAVE_PID=$!

for _ in $(seq 1 50); do
  nc -z 127.0.0.1 "$PORT" 2>/dev/null && break
  kill -0 "$ENCLAVE_PID" 2>/dev/null || { red "Enclave failed to start"; exit 1; }
  sleep 0.1
done
nc -z 127.0.0.1 "$PORT" 2>/dev/null || { red "Enclave not ready on port $PORT"; exit 1; }
green "✓ Enclave ready (127.0.0.1:$PORT)"

green "▶ Starting Trusted KMS API..."
(
  cd "$ROOT"
  export USE_ENCLAVE=true
  export ENCLAVE_PORT="$PORT"
  export JWT_SECRET_KEY
  export DATABASE_URL
  export ACCESS_TOKEN_EXPIRE_MINUTES
  unset MASTER_KEY
  exec "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$API_PORT"
) &
API_PID=$!

for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:${API_PORT}/" >/dev/null 2>&1 && break
  sleep 0.1
done

echo ""
green "════════════════════════════════════════════"
green "  Trusted KMS is running"
green "════════════════════════════════════════════"
echo "  Swagger:  http://127.0.0.1:${API_PORT}/docs"
echo "  Health:   http://127.0.0.1:${API_PORT}/"
echo ""
echo "  Press Ctrl+C to stop"
echo ""

wait "$API_PID"
