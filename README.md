# IoT & Web Security Testing Framework

This repository contains a merged Flask backend, modular security scanners, and a React dashboard. The runtime has been integrated so the project can be started with a single command in either Docker or local development mode.

## Run the project

Docker:

```bash
make run
```

Local development:

```bash
make run-local
```

## Access points

- Docker frontend: `http://localhost:8080`
- Local frontend: `http://127.0.0.1:5173`
- Backend API: `http://127.0.0.1:5000`
- MQTT broker: `localhost:1883`

## Architecture

- `backend/app.py` exposes the scan and dashboard APIs.
- `backend/core/` contains the generic scan engine, module loader, and safety checker.
- `backend/modules/web_security/`, `backend/modules/iam_security/`, and `backend/modules/iot_security/` provide the merged scanners.
- `frontend/` is a Vite React app that polls scan status and renders normalized findings.
- `docker-compose.yml` runs the backend, frontend, and MQTT broker as one integrated stack.

## Useful commands

```bash
make run
make run-local
make down
python3 -m compileall backend frontend
```

## Integration notes

- The frontend now calls `/api/*` by relative path and uses a Vite proxy in local development.
- Docker serves the React build through nginx and proxies `/api` to the Flask backend.
- The backend scan engine normalizes findings from all merged modules into one response shape for the dashboard.
