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

port_is_listening() {
    local port="$1"
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
}

resolve_ganache_cmd() {
    if command -v ganache >/dev/null 2>&1; then
        echo "ganache"
        return 0
    fi

    if command -v ganache-cli >/dev/null 2>&1; then
        echo "ganache-cli"
        return 0
    fi

    return 1
}

wait_for_port() {
    local port="$1"
    local label="$2"
    local attempts="${3:-20}"
    local delay="${4:-1}"

    for ((i = 1; i <= attempts; i++)); do
        if port_is_listening "$port"; then
            return 0
        fi
        sleep "$delay"
    done

    echo "$label did not start on port $port."
    exit 1
}

cleanup() {
    if [ -n "${GANACHE_PID:-}" ] && kill -0 "$GANACHE_PID" >/dev/null 2>&1; then
        kill "$GANACHE_PID"
    fi
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

GANACHE_STARTED_LOCALLY=0
if port_is_listening 7545; then
    echo "Ganache already running on http://127.0.0.1:7545"
else
    GANACHE_CMD="$(resolve_ganache_cmd || true)"
    if [ -z "${GANACHE_CMD:-}" ]; then
        echo "Ganache is not installed."
        echo "Install it with 'npm install -g ganache' or start Ganache manually, then rerun make run-local."
        exit 1
    fi

    "$GANACHE_CMD" --deterministic --accounts 10 --defaultBalanceEther 1000 --host 0.0.0.0 --port 7545 >/tmp/security-framework-ganache.log 2>&1 &
    GANACHE_PID=$!
    GANACHE_STARTED_LOCALLY=1
    wait_for_port 7545 "Ganache"
fi

python3 -m backend.app &
BACKEND_PID=$!

(
    cd frontend
    npm run dev -- --host 0.0.0.0 --port 5173 --strictPort
) &
FRONTEND_PID=$!

echo "Backend: http://127.0.0.1:5000"
echo "Frontend: http://127.0.0.1:5173"
echo "Blockchain RPC: http://127.0.0.1:7545"
if [ "$GANACHE_STARTED_LOCALLY" -eq 1 ]; then
    echo "Ganache started by run-local"
fi

while true; do
    if [ -n "${GANACHE_PID:-}" ] && ! kill -0 "$GANACHE_PID" >/dev/null 2>&1; then
        wait "$GANACHE_PID"
        exit $?
    fi

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
