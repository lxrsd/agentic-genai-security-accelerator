#!/bin/bash
# Setup script for Agentic GenAI Security Accelerator
# Installs core dependencies only. Prowler is NOT installed by default.
# Use --with-prowler flag or ./scripts/install_prowler.sh for connected AWS scans.
set -e

echo "=== Agentic GenAI Security Accelerator — Setup ==="
echo ""

INSTALL_PROWLER=false
for arg in "$@"; do
    if [ "$arg" = "--with-prowler" ]; then
        INSTALL_PROWLER=true
    fi
done

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "❌ ERROR: Python 3 is required. Install Python first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")

echo "✅ Python: $(python3 --version)"

if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]; then
    echo ""
    echo "⚠️  Python 3.10+ is recommended. Some dependencies may fail on Python $PYTHON_VERSION."
    echo "   The sample workflow may still work, but connected features require newer Python."
    echo ""
fi

# Create venv if missing
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate
echo "✅ Virtual environment activated"

# Upgrade pip
pip install --upgrade pip -q 2>/dev/null

# Install core dependencies
echo ""
echo "Installing Python dependencies..."
pip install -r requirements.txt -q
echo "✅ Core dependencies installed (boto3, botocore, python-dotenv)"

# Prowler — only if explicitly requested
echo ""
echo "─── Prowler Status ───"
if .venv/bin/prowler --version &> /dev/null 2>&1 || command -v prowler &> /dev/null 2>&1; then
    echo "✅ Prowler found"
elif [ "$INSTALL_PROWLER" = true ]; then
    echo "   Installing Prowler (this may take several minutes)..."
    if pip install prowler -q 2>/dev/null; then
        echo "✅ Prowler installed"
    else
        echo "⚠️  Prowler install failed."
        echo "   Sample workflow is still available."
        echo "   Try: pip install prowler"
    fi
else
    echo "   Prowler is an open-source AWS security assessment tool used to scan"
    echo "   an AWS account and generate real security findings."
    echo ""
    echo "   It is NOT required for the sample workflow because sample findings"
    echo "   are already included."
    echo ""
    echo "   Prowler status:       Not installed"
    echo "   Sample workflow:      Available"
    echo "   Connected AWS scan:   Requires Prowler"
    echo ""
    echo "   To install later:     ./scripts/install_prowler.sh"
    echo "   Or re-run with:       ./scripts/setup_demo.sh --with-prowler"
fi

# Install uv/uvx for MCP runtime (optional, quick)
echo ""
echo "Checking MCP runtime (uv/uvx)..."
if command -v uvx &> /dev/null; then
    echo "✅ uvx available"
elif command -v uv &> /dev/null; then
    echo "✅ uv available"
else
    if pip install uv -q 2>/dev/null; then
        echo "✅ uv installed"
    else
        echo "ℹ️  uv not available. MCP servers are optional."
    fi
fi

# Copy config files
echo ""
if [ ! -f ".env" ]; then
    cp .env.demo .env
    echo "✅ .env created from .env.demo (safe dry-run mode)"
else
    echo "✅ .env already exists (not overwriting)"
fi

if [ ! -f "mcp_config.json" ]; then
    if [ -f "mcp_config.example.json" ]; then
        cp mcp_config.example.json mcp_config.json
        echo "✅ mcp_config.json created"
    fi
else
    echo "✅ mcp_config.json already exists"
fi

# Confirm sample findings
echo ""
if [ -f "sample-data/prowler-output/sample-findings.json" ]; then
    echo "✅ Sample findings available: sample-data/prowler-output/sample-findings.json"
else
    echo "⚠️  Sample findings not found. Dashboard may show 0 findings."
fi

# Check AWS CLI (informational)
echo ""
if command -v aws &> /dev/null; then
    echo "✅ AWS CLI: $(aws --version 2>&1 | head -1)"
else
    echo "ℹ️  AWS CLI not found (optional for sample workflow)"
fi

# Summary
echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "  Sample findings: Included"
echo "  Default mode:    Dry-Run Execution (no AWS changes)"
echo "  AWS credentials: Optional for sample workflow"
echo "  Prowler:         $(command -v prowler &>/dev/null && echo 'Installed' || echo 'Not installed (optional)')"
echo ""
echo "Start the dashboard:"
echo "  ./scripts/run_demo.sh"
echo ""
echo "Dashboard: http://127.0.0.1:8080"
echo ""
