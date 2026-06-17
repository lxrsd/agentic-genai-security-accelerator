#!/bin/bash
# Setup script for Agentic GenAI Security Accelerator
# Installs all dependencies. Prowler is optional for the sample workflow.
# A teammate should only need to run this script after cloning.
set -e

echo "=== Agentic GenAI Security Accelerator — Setup ==="
echo ""

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

# Install Prowler (optional — sample workflow works without it)
echo ""
echo "Checking Prowler..."
if .venv/bin/prowler --version &> /dev/null 2>&1 || command -v prowler &> /dev/null 2>&1; then
    PROWLER_VER=$(prowler --version 2>&1 | head -1 || .venv/bin/prowler --version 2>&1 | head -1)
    echo "✅ Prowler found: $PROWLER_VER"
else
    echo "   Prowler not found. Attempting install (this may take a few minutes)..."
    echo "   (Prowler is optional — sample findings workflow works without it)"
    echo ""
    # Attempt install with a timeout to prevent indefinite hang
    if timeout 180 pip install prowler -q 2>/dev/null; then
        echo "✅ Prowler installed"
    elif pip install prowler --timeout 120 -q 2>/dev/null; then
        echo "✅ Prowler installed"
    else
        echo ""
        echo "ℹ️  Prowler not installed. This is OK for the sample workflow."
        echo "   Sample findings are already included at: sample-data/prowler-output/sample-findings.json"
        echo "   Connected AWS scans require Prowler. To install later:"
        echo "     source .venv/bin/activate && pip install prowler"
        echo ""
    fi
fi

# Install uv/uvx for MCP runtime (optional)
echo ""
echo "Checking MCP runtime (uv/uvx)..."
if command -v uvx &> /dev/null; then
    echo "✅ uvx already available"
elif command -v uv &> /dev/null; then
    echo "✅ uv already available"
else
    echo "   Installing uv..."
    if pip install uv -q 2>/dev/null; then
        echo "✅ uv installed via pip"
    else
        echo "ℹ️  uv install failed. MCP servers are optional."
        echo "   Install manually: brew install uv"
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

# Check AWS CLI (informational only)
echo ""
if command -v aws &> /dev/null; then
    echo "✅ AWS CLI: $(aws --version 2>&1 | head -1)"
else
    echo "ℹ️  AWS CLI not found (optional for sample workflow)"
    echo "   Required for: connected AWS scan, read-only investigation, live remediation"
fi

# Check Bedrock SDK support
echo ""
BEDROCK_OK=$(.venv/bin/python -c "import boto3; boto3.client('bedrock-runtime', region_name='us-east-1'); print('ok')" 2>/dev/null || echo "no")
if [ "$BEDROCK_OK" = "ok" ]; then
    echo "✅ Bedrock Runtime SDK support available"
else
    echo "ℹ️  Bedrock unavailable. Dashboard and sample workflow can still run;"
    echo "   AI chat requires Bedrock model access and boto3 >= 1.34."
fi

# Summary
echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "  Sample findings: sample-data/prowler-output/sample-findings.json"
echo "  Default mode:    Dry-Run Execution (no AWS changes)"
echo "  AWS credentials: Optional for sample workflow"
echo ""
echo "Start the dashboard:"
echo "  ./scripts/run_demo.sh"
echo ""
echo "Dashboard: http://127.0.0.1:8080"
echo ""
