#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to run the integrated stack."
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
else
    echo "Docker Compose is required to run the integrated stack."
    exit 1
fi

cd "$ROOT_DIR"

echo "Starting the integrated framework with Docker..."
"${COMPOSE_CMD[@]}" up --build -d

echo
echo "Framework is starting."
echo "Frontend: http://localhost:8080"
echo "Backend API: http://localhost:5000/api/health"
echo "MQTT Broker: localhost:1883"
echo
echo "Follow logs with: ${COMPOSE_CMD[*]} logs -f"
echo "Stop everything with: ${COMPOSE_CMD[*]} down"
