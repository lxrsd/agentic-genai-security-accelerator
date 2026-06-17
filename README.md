# Agentic GenAI Security Accelerator

**From fragmented AWS findings to prioritized, governed, and audit-ready security improvement.**

## Quick Start: Sample Workflow

### Cross-platform launcher

Mac/Linux:
```bash
python3 quickstart.py
```

Windows:
```powershell
py quickstart.py
```

The quickstart detects your operating system, prepares the local environment, uses included sample findings, and starts the dashboard.

Open: **http://127.0.0.1:8080**

### Direct commands (Mac/Linux)

```bash
./scripts/setup_demo.sh
./scripts/run_demo.sh
```

### Direct commands (Windows PowerShell)

```powershell
.\scripts\setup_demo.ps1
.\scripts\run_demo.ps1
```

The repository includes sample findings, so you can evaluate the full workflow before connecting an AWS account.

**Default mode:**
- Investigation: enabled
- Planning: enabled
- Approval: required
- Dry-run execution: enabled
- Live AWS changes: **disabled**

AWS credentials are only required for connected AWS scans, read-only investigation, or optional controlled live remediation.

### What setup does

- Creates `.venv` (local Python virtual environment)
- Installs dependencies from `requirements.txt`
- Creates `.env` from `.env.demo`
- Validates optional AWS/Bedrock/Prowler/MCP components
- You may see terminal prompts during setup — these do not enable live remediation
- Prowler is optional for sample workflow; required only for connected AWS scans

---

## What This Is

The Agentic GenAI Security Accelerator imports AWS security findings from Prowler, calculates a deterministic 0–5 posture score across 5 security areas, and displays results in a dark-themed command-center dashboard. An Amazon Bedrock assistant uses your posture data plus real AWS MCP servers to answer questions and provide remediation guidance grounded in official AWS best practices.

## Architecture

```
Prowler Findings → Scoring Engine → Dashboard → Amazon Bedrock + AWS MCP
```

Prowler scans your AWS account and produces JSON findings. The scoring engine classifies findings into 5 security areas, calculates weighted scores, and exposes results via REST API. The dashboard visualizes posture and connects to Amazon Bedrock (via Converse API) for AI-powered Q&A with real AWS MCP servers providing best-practice context.

## 5 Security Areas

| Area | Covers |
|------|--------|
| Identity & Access | IAM, Organizations |
| Data Protection | S3, KMS |
| Network Security | EC2 security groups, VPC |
| Vulnerability Management | Inspector, SSM |
| Incident Readiness | GuardDuty, Security Hub, CloudTrail, CloudWatch, Config |

## Quick Start (Demo Mode)

```bash
# One-command setup
./scripts/setup_demo.sh

# Start the dashboard
./scripts/run_demo.sh
```

Or manually:

```bash
python -m backend.main
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

Demo Mode loads bundled sample findings and calculates scores without requiring AWS credentials. Bedrock and AWS MCP features show "Not connected" until configured.

## Team Fast Start

For team members cloning this repo:

```bash
# 1. Clone and setup
git clone https://github.com/lxrsd/agentic-genai-security-accelerator.git
cd agentic-genai-security-accelerator
./scripts/setup_demo.sh

# 2. Verify connections
./scripts/preflight_check.sh

# 3. Run the dashboard
./scripts/run_demo.sh
```

Open: http://127.0.0.1:8080

The setup script creates a `.env` file and `mcp_config.json` from examples. AWS Knowledge MCP is enabled by default — if `uvx` is installed, it auto-connects for best-practice context.

## Preflight Check

Run the full readiness check to see what is installed, connected, and missing:

```bash
./scripts/preflight_check.sh
```

This validates: Python, boto3, AWS CLI, AWS credentials, Prowler, MCP runtime, MCP servers, Bedrock, scoring engine, and findings.

## Fully Operational Mode

To run with everything enabled:

```bash
cp .env.connected.example .env
# Edit .env and set BEDROCK_MODEL_ID
./scripts/setup_connected.sh
./scripts/preflight_check.sh
./scripts/run_demo.sh
```

Requirements for Fully Operational Mode:
- AWS CLI configured with valid credentials
- Prowler installed
- uvx installed (for MCP runtime)
- Bedrock model access granted
- Read-only AWS permissions for optional MCPs

## Kiro MCP Sidebar vs App Runtime MCP

This project uses MCP in two distinct contexts:

| Context | Purpose | When Active |
|---------|---------|-------------|
| **Kiro Sidebar MCP** | IDE-level MCP servers configured in Kiro's MCP panel. Powers Kiro's AI assistant during development. | When editing code in Kiro |
| **App Runtime MCP** | MCP servers the application connects to at runtime (configured in `mcp_config.json`). Provides AWS best-practice context to the security dashboard. | When running `python -m backend.main` |

These are independent configurations. Kiro sidebar MCP helps YOU develop. App runtime MCP helps your APPLICATION provide AWS context to end users.

To configure app runtime MCP:
```bash
cp mcp_config.example.json mcp_config.json
# Edit mcp_config.json to enable/disable servers
```

To configure Kiro sidebar MCP, use Kiro's MCP configuration panel.

## Prerequisites

- Python 3.9+
- `pip install -r requirements.txt` (installs boto3)
- Prowler CLI (for Connected AWS Mode only)

## Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `BEDROCK_ENABLED` | Enable Amazon Bedrock assistant | `false` |
| `BEDROCK_MODEL_ID` | Bedrock model ID | `anthropic.claude-3-sonnet-20240229-v1:0` |
| `AWS_REGION` | AWS region for Bedrock and MCP | `us-east-1` |
| `AWS_MCP_ENABLED` | Master switch for AWS MCP connections | `false` |
| `AWS_KNOWLEDGE_MCP_ENABLED` | Enable AWS Knowledge/Documentation MCP | `false` |
| `AWS_API_MCP_ENABLED` | Enable AWS API MCP (read-only) | `false` |
| `IAM_MCP_ENABLED` | Enable IAM MCP (read-only) | `false` |
| `CLOUDTRAIL_MCP_ENABLED` | Enable CloudTrail MCP (optional) | `false` |
| `SECURITYHUB_MCP_ENABLED` | Enable Security Hub MCP (optional) | `false` |
| `AWS_API_MCP_READ_ONLY` | Enforce read-only on AWS API MCP | `true` |
| `IAM_MCP_READ_ONLY` | Enforce read-only on IAM MCP | `true` |
| `MCP_CONFIG_PATH` | Path to MCP server configuration | `mcp_config.json` |
| `PROWLER_DATA_DIR` | Directory containing Prowler JSON output | `sample-data/prowler-output` |
| `DEV_SIMULATED_ASSISTANT` | Dev-only simulated assistant fallback | `false` |

## MCP Setup

1. Copy the example configuration:

```bash
cp mcp_config.example.json mcp_config.json
```

2. Set the config path and enable MCP:

```bash
export MCP_CONFIG_PATH=./mcp_config.json
export AWS_MCP_ENABLED=true
export AWS_KNOWLEDGE_MCP_ENABLED=true
export AWS_API_MCP_ENABLED=true
export IAM_MCP_ENABLED=true
```

3. Verify connections:

```bash
python -m backend.main --check-connections
```

4. Start the server:

```bash
python -m backend.main
```

See [docs/aws-mcp-integration.md](docs/aws-mcp-integration.md) for detailed MCP server configuration.

## Connected AWS Mode

Run Prowler against your own AWS account to see real posture scores:

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Run Prowler scan
prowler aws --output-formats json csv html --output-directory ./sample-data/prowler-output/

# Or scan with an assumed role
prowler aws -R arn:aws:iam::<ACCOUNT_ID>:role/ProwlerSecurityAuditRole \
  --output-formats json csv html --output-directory ./sample-data/prowler-output/

# Restart the accelerator to import findings
python -m backend.main
```

See [docs/connected-aws-mode.md](docs/connected-aws-mode.md) for detailed setup instructions.

## Scoring Methodology

Each security area receives a 0–5 score using:

```
Area Score = (Passed Weighted Points / Total Weighted Points) × 5
```

**Severity weights:** Critical=5, High=4, Medium=2, Low=1, Informational=0

**Overall score** = arithmetic mean of evaluated areas only.

Areas with zero findings are marked **Not Evaluated** and excluded from the overall average.

| Score Range | Label |
|-------------|-------|
| 0–1 | Critical Gaps |
| 1–2 | Needs Attention |
| 2–3 | Developing |
| 3–4 | Strong |
| 4–5 | Optimized |

Scoring is deterministic and local — no LLM or MCP connection is needed for score calculation.

## Remediation

All remediation in this accelerator is **planning-only**. No AWS changes are executed. The assistant provides recommendations and prioritization, but does not modify your AWS environment.

**Future:** Approval-based remediation execution with Preview → Approve → Execute → Verify → Rescan workflow.

## Future Roadmap

- Live Amazon Bedrock integration with full Converse API tool use
- Live AWS MCP server connections for real-time best-practice guidance
- Approval-based remediation execution
- Additional AWS MCP servers (CloudTrail, Security Hub)
- Multi-account support

## Documentation

- [Demo Guide](docs/demo-guide.md) — Step-by-step customer demo walkthrough
- [AWS MCP Integration](docs/aws-mcp-integration.md) — How external AWS MCP servers work
- [Connected AWS Mode](docs/connected-aws-mode.md) — Prowler setup and real findings import

## GitHub Pages

[https://lxrsd.github.io/agentic-genai-security-accelerator/](https://lxrsd.github.io/agentic-genai-security-accelerator/)

## Agent Safety and Usage

This project includes a controlled remediation agent with multiple safety modes, dry-run execution, approval workflows, and audit logging. The agent can investigate, plan, and — when explicitly enabled — execute approved low-risk remediations in AWS.

Read the full guide here: [Agent Safety and Usage Guide](docs/AGENT_SAFETY_AND_USAGE.md)

## Quick Customer Demo

This project starts in safe dry-run demo mode by default.

```bash
git clone https://github.com/lxrsd/agentic-genai-security-accelerator.git
cd agentic-genai-security-accelerator
cp .env.demo .env
./scripts/setup_demo.sh
./scripts/run_demo.sh
```

Open the dashboard, connect AWS, run a scan, review findings, create a remediation plan, approve an action, and run dry-run execution.

Dry-run mode shows the full remediation workflow without changing AWS.

For more details:
- [Agent Safety and Usage Guide](docs/AGENT_SAFETY_AND_USAGE.md)
- [Customer Demo Walkthrough](docs/CUSTOMER_DEMO_WALKTHROUGH.md)
- [Demo Scenarios](docs/DEMO_SCENARIOS.md)
