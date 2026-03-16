#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

if [ ! -d .venv ] || [ ! -d frontend/node_modules ]; then
    echo "Local dependencies are missing. Running setup first..."
    ./scripts/setup.sh
fi

source .venv/bin/activate
export PYTHONPATH="$ROOT_DIR"

require_port_free() {
    local port="$1"
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "Port $port is already in use."
        echo "Stop the existing process or free the port, then rerun make run-local."
        exit 1
    fi
}

cleanup() {
    if [ -n "${BACKEND_PID:-}" ] && kill -0 "$BACKEND_PID" >/dev/null 2>&1; then
        kill "$BACKEND_PID"
    fi
    if [ -n "${FRONTEND_PID:-}" ] && kill -0 "$FRONTEND_PID" >/dev/null 2>&1; then
        kill "$FRONTEND_PID"
    fi
}

trap cleanup EXIT INT TERM

require_port_free 5000
require_port_free 5173

python3 -m backend.app &
BACKEND_PID=$!

(
    cd frontend
    npm run dev -- --host 0.0.0.0 --port 5173 --strictPort
) &
FRONTEND_PID=$!

echo "Backend: http://127.0.0.1:5000"
echo "Frontend: http://127.0.0.1:5173"

while true; do
    if ! kill -0 "$BACKEND_PID" >/dev/null 2>&1; then
        wait "$BACKEND_PID"
        exit $?
    fi

    if ! kill -0 "$FRONTEND_PID" >/dev/null 2>&1; then
        wait "$FRONTEND_PID"
        exit $?
    fi

    sleep 1
done
