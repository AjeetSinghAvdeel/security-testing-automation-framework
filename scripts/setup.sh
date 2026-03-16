#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required."
    exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
    echo "npm is required."
    exit 1
fi

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

mkdir -p logs reports/generated

pushd frontend >/dev/null
npm install
popd >/dev/null

echo "Local development dependencies are installed."
echo "Run ./scripts/run_local.sh for local mode or ./scripts/run_demo.sh for Docker mode."
