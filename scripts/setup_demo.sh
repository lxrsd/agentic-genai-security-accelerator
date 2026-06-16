#!/bin/bash
# Setup script for Agentic GenAI Security Accelerator
# Installs all dependencies including Prowler and MCP runtime.
# A teammate should only need to run this script after cloning.
set -e

echo "=== Agentic GenAI Security Accelerator — Demo Setup ==="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ ERROR: Python 3.9+ is required. Install Python first."
    exit 1
fi
echo "✅ Python: $(python3 --version)"

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

# Install Prowler
echo ""
echo "Checking Prowler..."
if command -v prowler &> /dev/null; then
    echo "✅ Prowler already installed: $(prowler --version 2>&1 | head -1)"
else
    echo "   Installing Prowler into .venv..."
    if pip install prowler -q 2>/dev/null; then
        echo "✅ Prowler installed: $(prowler --version 2>&1 | head -1)"
    else
        echo "⚠️  Prowler install failed. Manual fix:"
        echo "   source .venv/bin/activate && pip install prowler"
    fi
fi

# Install uv/uvx for MCP runtime
echo ""
echo "Checking MCP runtime (uv/uvx)..."
if command -v uvx &> /dev/null; then
    echo "✅ uvx already available"
elif command -v uv &> /dev/null; then
    echo "✅ uv already available"
else
    echo "   Installing uv into .venv..."
    if pip install uv -q 2>/dev/null; then
        echo "✅ uv installed via pip"
    else
        echo "⚠️  uv install failed. Manual fix:"
        echo "   brew install uv"
        echo "   OR: curl -LsSf https://astral.sh/uv/install.sh | sh"
    fi
fi

# Copy config files
echo ""
if [ ! -f ".env" ]; then
    cp .env.demo .env
    echo "✅ .env created from .env.demo"
else
    echo "✅ .env already exists (not overwriting)"
fi

if [ ! -f "mcp_config.json" ]; then
    cp mcp_config.example.json mcp_config.json
    echo "✅ mcp_config.json created"
else
    echo "✅ mcp_config.json already exists"
fi

# Check AWS CLI (informational only — not required for demo)
echo ""
if command -v aws &> /dev/null; then
    echo "✅ AWS CLI: $(aws --version 2>&1 | head -1)"
else
    echo "ℹ️  AWS CLI not found (optional for Demo Mode)"
    echo "   Install for Connected AWS Mode: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
fi

# Run preflight check
echo ""
echo "=========================================="
echo "  Running Preflight Check..."
echo "=========================================="
python3 -m backend.preflight

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Start the dashboard:"
echo "  ./scripts/run_demo.sh"
echo ""
echo "Or one command:"
echo "  ./scripts/quickstart.sh"
echo ""
echo "Dashboard will be at: http://127.0.0.1:8080"
