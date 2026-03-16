# Quick Start

## One-command Docker run

```bash
make run
```

This starts the integrated stack with Docker:
- React dashboard: `http://localhost:8080`
- Flask API: `http://localhost:5000`
- MQTT broker: `localhost:1883`

Stop it with:

```bash
make down
```

## One-command local development run

```bash
make run-local
```

This bootstraps local dependencies if needed, then starts:
- Flask backend on `http://127.0.0.1:5000`
- Vite frontend on `http://127.0.0.1:5173`

## Notes

- The frontend now uses same-origin `/api` calls in Docker and a Vite proxy in local development.
- The Docker setup is aligned with the merged application actually present in this repository.
