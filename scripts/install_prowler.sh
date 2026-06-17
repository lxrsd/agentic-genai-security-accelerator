#!/bin/bash
# Install Prowler for connected AWS security scanning.
# This is optional — sample findings work without Prowler.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Prowler Installation ==="
echo ""
echo "Prowler is an open-source AWS security assessment tool."
echo "Installation may take several minutes due to its dependencies."
echo ""

# Check if already installed
if .venv/bin/prowler --version &> /dev/null 2>&1; then
    echo "✅ Prowler is already installed: $(.venv/bin/prowler --version 2>&1 | head -1)"
    exit 0
fi

if command -v prowler &> /dev/null 2>&1; then
    echo "✅ Prowler found on system: $(prowler --version 2>&1 | head -1)"
    exit 0
fi

# Ensure venv exists
if [ ! -d ".venv" ]; then
    echo "❌ .venv not found. Run ./scripts/setup_demo.sh first."
    exit 1
fi

source .venv/bin/activate

echo "Installing Prowler into .venv (this may take 5-10 minutes)..."
echo ""

if pip install prowler; then
    echo ""
    echo "✅ Prowler installed successfully"
    prowler --version 2>&1 | head -1
    echo ""
    echo "You can now run connected AWS scans from the dashboard."
else
    echo ""
    echo "❌ Prowler installation failed."
    echo ""
    echo "   The sample workflow is still available without Prowler."
    echo "   Sample findings: sample-data/prowler-output/sample-findings.json"
    echo ""
    echo "   Troubleshooting:"
    echo "   - Python 3.10+ is recommended for Prowler"
    echo "   - Try: pip install prowler --verbose"
    echo "   - Or install Prowler in a separate Python 3.12 venv:"
    echo "     python3.12 -m venv .prowler-venv && .prowler-venv/bin/pip install prowler"
    exit 1
fi
