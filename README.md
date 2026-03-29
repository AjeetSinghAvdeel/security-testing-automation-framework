# Security Testing Automation Framework

This project is a local-lab security testing platform with:

- a Flask backend for scan orchestration
- a React dashboard with Firebase authentication
- modular Web, IAM, IoT, SIEM, compliance, and blockchain support
- user-scoped persisted scan history in Firebase
- local-lab attack flows for OWASP Juice Shop and similar safe test targets

It is built for authorized local security labs only.

## What It Does

The platform can:

- authenticate users with Google or email/password via Firebase
- run user-selected local-lab attack flows against safe targets
- normalize findings from multiple security modules into one dashboard
- persist scan history per signed-in user
- attach SIEM alerts, compliance mappings, and report summaries to completed scans
- hash scan evidence and store blockchain records through Ganache when available

The dashboard currently supports real local-lab actions for attack types such as:

- credential stuffing
- password strength / weak credential login
- brute-force control checks
- SQL injection login probes
- union-based search injection
- reflected XSS probes
- admin section exposure checks
- basket access / authorization checks
- empty user registration checks
- exposed metrics checks
- application configuration exposure checks

## Project Structure

- `backend/app.py`
  Flask API, auth-protected endpoints, attack-profile routing
- `backend/core/`
  Scan engine, module loading, safety validation
- `backend/modules/`
  Web, IAM, IoT, SIEM/compliance-related security modules
- `backend/modules/local_lab.py`
  Local-lab helpers for Juice Shop-specific live interactions
- `backend/firebase_store.py`
  Firebase token verification, persisted scan history, dashboard stats
- `backend/blockchain/`
  Evidence hashing and blockchain storage
- `frontend/src/components/`
  Dashboard, scan form, results, history, UI layout
- `frontend/src/auth/`
  Firebase auth provider and protected-session handling
- `scripts/run_local.sh`
  Local launcher for Ganache, backend, and frontend

## Runtime Modes

### Docker

```bash
make run
```

This starts the integrated Docker stack.

### Local Development

```bash
make run-local
```

This now starts:

- Ganache automatically if needed
- Flask backend on `http://127.0.0.1:5000`
- Vite frontend on `http://127.0.0.1:5173`

If Ganache is missing, the script reports that clearly instead of silently falling back.

## Access Points

- Local frontend: `http://127.0.0.1:5173`
- Vite browser URL: `http://localhost:5173`
- Backend API: `http://127.0.0.1:5000`
- Ganache RPC: `http://127.0.0.1:7545`
- Docker frontend: `http://localhost:8080`
- MQTT broker: `localhost:1883`

## Authentication

The frontend uses Firebase Web SDK auth.

Supported sign-in methods:

- Google
- Email/password

The backend verifies Firebase ID tokens and scopes scan history to the current user.

Each persisted scan stores user metadata such as:

- `user_id`
- `user_name`
- `user_email`

History is filtered by `user_id`, so users only see their own scans.

## Firebase Setup

The frontend requires Firebase web-app configuration.

Recommended approach:

Create `frontend/.env.local` with:

```bash
VITE_FIREBASE_API_KEY=...
VITE_FIREBASE_AUTH_DOMAIN=...
VITE_FIREBASE_PROJECT_ID=...
VITE_FIREBASE_APP_ID=...
VITE_FIREBASE_STORAGE_BUCKET=...
VITE_FIREBASE_MESSAGING_SENDER_ID=...
VITE_FIREBASE_MEASUREMENT_ID=...
```

Also make sure Firebase Authentication has these providers enabled:

- Google
- Email/Password

For local development, authorized domains should include:

- `localhost`
- `127.0.0.1`

## Dashboard Features

The dashboard includes:

- authenticated access control
- attack genre / attack type selectors
- live scan status polling
- normalized findings view
- lab action trace for completed attacks
- top-level stats for findings, SIEM alerts, compliance mappings, reports, and blockchain records
- persisted recent scan history
- backend module availability panel

## Attack Selection Model

The scan form uses:

- `Attack Genre`
- `Attack Type`

The selected attack type maps to backend modules and concrete local-lab behaviors.

Examples:

- `Credential Stuffing` performs live login attempts
- `Login Admin` uses SQLi-style login payloads
- `Union Search Injection` sends payloads to the Juice Shop search endpoint
- `View Basket` performs authenticated basket-access checks
- `Exposed Metrics` probes the metrics endpoint

The backend stores both:

- normalized findings
- `lab_actions`

The dashboard renders the recorded action trace so you can see what was actually attempted against the lab.

## SIEM, Compliance, and Reporting

Completed scans attach post-processing outputs including:

- SIEM alerts
- compliance mappings
- report summaries

These are shown in the scan details panel and included in dashboard summary counts.

## Blockchain Evidence

Completed scan records are hashed and sent to the blockchain layer.

When Ganache is running:

- evidence hashes are stored on-chain
- blockchain transaction IDs are included in persisted scans

When Ganache is unavailable:

- the platform can still run in offline blockchain mode

## Persistence

Scan records are stored in Firebase/Firestore when configured.

Persisted records can include:

- target
- attack profile
- findings
- SIEM payload
- blockchain transaction hash
- evidence hash
- timestamps
- user metadata

## Safety Notes

This project is intended for:

- local targets
- self-hosted labs
- explicitly authorized test environments

The backend safety checker blocks unsafe targets outside the expected local-lab usage.

## Useful Commands

```bash
make run
make run-local
make down
python3 -m compileall backend
cd frontend && npm run build
```

## Recent Implemented Changes

This repository now includes:

- Firebase-based Google and email login
- protected dashboard sessions
- user-scoped persisted history
- Ganache auto-start in local mode
- SIEM/compliance/reporting integration
- improved landing page and auth flow
- grouped findings UI
- manual-scroll animated history panel
- local-lab attack taxonomy in the dashboard
- Juice Shop-aware real interaction flows instead of passive-only scanning

## Notes For OWASP Juice Shop

If your local target is OWASP Juice Shop on `http://localhost:3000`, several attack types are wired to its real endpoints, including:

- `/rest/user/login`
- `/rest/user/whoami`
- `/rest/products/search`
- `/rest/basket/:id`
- `/api/Users`
- `/metrics`
- `/rest/admin/application-configuration`

That means the framework is not only labeling a run as an attack profile; it is actually sending requests to the running lab and recording what happened.
