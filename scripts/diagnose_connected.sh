#!/bin/bash
# Deep diagnostic for connected mode — shows exact state of every integration
set -e

echo "=== Agentic GenAI Security Accelerator — Deep Diagnostic ==="
echo ""

# Activate venv
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    echo "❌ .venv not found. Run ./scripts/setup_demo.sh first"
    exit 1
fi

# Load .env
if [ -f ".env" ]; then
    set -a; source .env; set +a
    echo "✅ .env loaded from: $(pwd)/.env"
else
    echo "⚠️ No .env file. Using defaults."
fi

echo ""
echo "=== Active Environment ==="
echo "APP_MODE=$APP_MODE"
echo "AWS_REGION=$AWS_REGION"
echo "AWS_PROFILE=$AWS_PROFILE"
echo "BEDROCK_ENABLED=$BEDROCK_ENABLED"
echo "BEDROCK_MODEL_ID=$BEDROCK_MODEL_ID"
echo "AWS_MCP_ENABLED=$AWS_MCP_ENABLED"
echo "AWS_KNOWLEDGE_MCP_ENABLED=$AWS_KNOWLEDGE_MCP_ENABLED"
echo "AWS_API_MCP_ENABLED=$AWS_API_MCP_ENABLED"
echo "IAM_MCP_ENABLED=$IAM_MCP_ENABLED"
echo "CLOUDTRAIL_MCP_ENABLED=$CLOUDTRAIL_MCP_ENABLED"
echo "SECURITYHUB_MCP_ENABLED=$SECURITYHUB_MCP_ENABLED"
echo "MCP_CONFIG_PATH=$MCP_CONFIG_PATH"
echo ""

echo "=== AWS Identity ==="
python3 -c "
import boto3, os
try:
    region = os.environ.get('AWS_REGION', 'us-east-1')
    profile = os.environ.get('AWS_PROFILE', '')
    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
        sts = session.client('sts')
    else:
        sts = boto3.client('sts', region_name=region)
    identity = sts.get_caller_identity()
    print(f'✅ Connected')
    print(f'   Account: {identity[\"Account\"]}')
    print(f'   ARN: {identity[\"Arn\"]}')
    print(f'   Region: {region}')
    print(f'   Profile: {profile or \"default\"}')
except Exception as e:
    print(f'❌ Not Connected: {e}')
" 2>&1

echo ""
echo "=== Full Preflight (with real health checks) ==="
python3 -m backend.preflight

echo ""
echo "=== Diagnostic Complete ==="
