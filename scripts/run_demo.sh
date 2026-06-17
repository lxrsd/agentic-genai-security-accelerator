#!/bin/bash
# Start the Agentic Security Posture Command Center
# Always uses the project .venv Python to avoid environment mismatches.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

VENV_PYTHON="$PROJECT_DIR/.venv/bin/python"

# Check venv exists
if [ ! -f "$VENV_PYTHON" ]; then
    echo "❌ .venv not found. Run ./scripts/setup_demo.sh first."
    exit 1
fi

# Initialize .env from .env.demo if missing (safe default for new users)
if [ ! -f ".env" ]; then
    if [ -f ".env.demo" ]; then
        cp .env.demo .env
        echo "✅ Created .env from .env.demo (safe dry-run demo mode)"
        echo ""
    else
        echo "⚠️  No .env or .env.demo found. Agent features may be disabled."
        echo ""
    fi
fi

# Load .env
if [ -f ".env" ]; then
    set -a; source .env; set +a
fi

# Check for stale server on port 8080
STALE_PID=$(lsof -ti:8080 2>/dev/null || true)
if [ -n "$STALE_PID" ]; then
    echo "⚠️  Port 8080 is already in use (PID: $STALE_PID)"
    echo "   A stale server may be running."
    echo "   Kill it with: kill -9 $STALE_PID"
    echo ""
    read -p "   Kill it now and continue? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kill -9 $STALE_PID 2>/dev/null
        sleep 1
        echo "   ✅ Killed PID $STALE_PID"
    else
        echo "   Exiting. Kill the stale server manually."
        exit 1
    fi
fi

# Print runtime info
echo "=== Runtime Environment ==="
echo "Repo root: $PROJECT_DIR"
echo "Python:    $VENV_PYTHON"
echo "Version:   $($VENV_PYTHON --version 2>&1)"
echo "boto3:     $($VENV_PYTHON -c 'import boto3; print(boto3.__version__)' 2>/dev/null || echo 'NOT INSTALLED')"
echo ".env:      $([ -f .env ] && echo 'loaded' || echo 'not found')"
echo ""

# Print agent mode summary
echo "=== Agent Mode ==="
if [ "${REMEDIATION_EXECUTION_ENABLED:-false}" = "true" ]; then
    if [ "${DRY_RUN_REMEDIATION:-true}" = "true" ]; then
        echo "Mode:            Dry-Run Execution"
        echo "Live AWS changes: Disabled"
        echo "Safe demo mode: dry-run enabled. No AWS changes will be made."
    else
        echo "Mode:            ⚡ Live Low-Risk Execution"
        echo "Live AWS changes: ENABLED (low-risk only)"
        echo ""
        echo "WARNING: Live low-risk remediation is enabled."
        echo "         Approved low-risk AWS resources can be modified."
        if [ -z "${EXECUTION_ROLE_ARN}" ]; then
            echo ""
            echo "⚠️  Live execution requested but EXECUTION_ROLE_ARN is missing."
            echo "   Live execution will use current credentials."
        fi
    fi
else
    echo "Mode:            Planning Only"
    echo "Live AWS changes: Disabled"
fi
echo "Investigation:   ${INVESTIGATION_TOOLS_ENABLED:-false}"
echo "Planning:        ${REMEDIATION_PLANNING_ENABLED:-false}"
echo "Execution:       ${REMEDIATION_EXECUTION_ENABLED:-false}"
echo "Dry-run:         ${DRY_RUN_REMEDIATION:-true}"
echo "Approval:        ${REQUIRE_APPROVAL_FOR_ALL_REMEDIATION:-true}"
echo ""
echo "=== Startup Summary ==="
echo "Sample findings:  sample-data/prowler-output/sample-findings.json"
echo "Default mode:     Dry-Run Execution"
echo "Live AWS changes: Disabled"
echo "AWS credentials:  Optional for sample workflow, required for connected scan"
echo ""
echo "Starting Agentic Security Posture Command Center..."
echo "Dashboard: http://127.0.0.1:8080"
echo ""

exec "$VENV_PYTHON" -m backend.main --host 0.0.0.0
