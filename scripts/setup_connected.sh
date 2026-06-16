#!/bin/bash
# Setup script for Fully Operational Connected Mode
# Installs all dependencies and verifies AWS connectivity.
set -e

echo "=== Agentic GenAI Security Accelerator — Connected Mode Setup ==="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3.9+ is required."; exit 1
fi
echo "✅ Python: $(python3 --version)"

# Create/activate venv
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate
echo "✅ Virtual environment activated"

# Upgrade pip and install deps
pip install --upgrade pip -q 2>/dev/null
echo ""
echo "Installing Python dependencies..."
pip install -r requirements.txt -q
echo "✅ Core dependencies installed"

# Verify core imports
python3 -c "import boto3; print('✅ boto3:', boto3.__version__)" 2>/dev/null || echo "❌ boto3 failed"
python3 -c "import botocore" 2>/dev/null && echo "✅ botocore: installed" || echo "❌ botocore failed"
python3 -c "import dotenv" 2>/dev/null && echo "✅ python-dotenv: installed" || echo "⚠️  python-dotenv missing"

# Install Prowler
echo ""
echo "Checking Prowler..."
if command -v prowler &> /dev/null; then
    echo "✅ Prowler: $(prowler --version 2>&1 | head -1)"
else
    echo "   Installing Prowler..."
    if pip install prowler -q 2>/dev/null; then
        echo "✅ Prowler installed"
    else
        echo "❌ Prowler install failed. Manual fix: pip install prowler"
    fi
fi

# Install uv/uvx
echo ""
echo "Checking MCP runtime (uv/uvx)..."
if command -v uvx &> /dev/null; then
    echo "✅ uvx available"
elif command -v uv &> /dev/null; then
    echo "✅ uv available"
else
    echo "   Installing uv..."
    if pip install uv -q 2>/dev/null; then
        echo "✅ uv installed"
    else
        echo "⚠️  uv install failed. Manual fix: brew install uv"
    fi
fi

# AWS CLI check (required for connected mode)
echo ""
if command -v aws &> /dev/null; then
    echo "✅ AWS CLI: $(aws --version 2>&1 | head -1)"
else
    echo "❌ AWS CLI not found — required for Connected Mode"
    echo "   Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
fi

# AWS Identity check
echo ""
echo "Checking AWS identity..."
python3 -c "
import boto3
try:
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    print(f'✅ AWS Identity: {identity[\"Arn\"]}')
    print(f'   Account: {identity[\"Account\"]}')
except Exception as e:
    print(f'⚠️  AWS identity not available: {e}')
    print('   Fix: aws configure sso && aws sso login --profile <profile>')
" 2>/dev/null || echo "⚠️  Identity check failed"

# Config files
echo ""
if [ ! -f ".env" ]; then
    cp .env.connected.example .env
    echo "✅ .env created from .env.connected.example"
    echo "⚠️  Review .env and set BEDROCK_MODEL_ID for live AI chat"
else
    echo "✅ .env exists (not overwriting)"
fi

if [ ! -f "mcp_config.json" ]; then
    cp mcp_config.example.json mcp_config.json
    echo "✅ mcp_config.json created"
else
    echo "✅ mcp_config.json exists"
fi

# Run full preflight
echo ""
echo "=========================================="
echo "  Running Full Preflight Check..."
echo "=========================================="
if [ -f ".env" ]; then set -a; source .env; set +a; fi
python3 -m backend.preflight

echo ""
echo "=========================================="
echo "  Connected Mode Setup Complete"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  ./scripts/run_demo.sh   — start the dashboard"
echo ""
echo "For Bedrock: Set BEDROCK_MODEL_ID in .env"
echo "For Prowler scan: Use the Connect AWS button in the dashboard"
