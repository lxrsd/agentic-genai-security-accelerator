#!/bin/bash
# Check demo mode readiness — uses .venv/bin/python explicitly
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

VENV_PYTHON="$PROJECT_DIR/.venv/bin/python"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "❌ .venv not found. Run ./scripts/setup_demo.sh first."
    exit 1
fi

if [ -f ".env" ]; then set -a; source .env; set +a; fi

exec "$VENV_PYTHON" -m backend.preflight
