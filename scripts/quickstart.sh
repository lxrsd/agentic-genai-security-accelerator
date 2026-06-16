#!/bin/bash
# One-command quickstart for the Agentic GenAI Security Accelerator
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Agentic GenAI Security Accelerator — Quickstart ==="
echo ""

# Run setup
./scripts/setup_demo.sh

echo ""
echo "=========================================="
echo "  Starting Dashboard..."
echo "=========================================="
echo ""

# Start server using run_demo (which uses .venv/bin/python)
exec ./scripts/run_demo.sh
