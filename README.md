# Agentic GenAI Security Accelerator

**From fragmented AWS findings to prioritized, governed, and audit-ready security improvement.**

---

## What This Is

The Agentic GenAI Security Accelerator is an AWS security posture workflow that uses included sample findings or connected AWS findings to calculate a 0–5 maturity score, group and prioritize findings, support AI-assisted investigation, generate remediation plans, route actions through approval, execute dry-runs by default, and preserve audit evidence.

It is designed for security teams who want to move from scattered findings to prioritized, measurable, and governed improvement — without giving AI unrestricted access to AWS resources.

---

## Quick Start

### Mac / Linux

```bash
git clone https://github.com/lxrsd/agentic-genai-security-accelerator.git
cd agentic-genai-security-accelerator
python3 quickstart.py
```

### Windows PowerShell

```powershell
git clone https://github.com/lxrsd/agentic-genai-security-accelerator.git
cd agentic-genai-security-accelerator
py quickstart.py
```

Open: **http://127.0.0.1:8080**

---

## What Works Immediately

The default sample workflow works without:
- Prowler
- AWS credentials
- Amazon Bedrock access
- Live remediation permissions

It uses included sample findings at:

```
sample-data/prowler-output/sample-findings.json
```

---

## Default Safety Mode

```
Mode:              Dry-Run Execution
Live AWS changes:  Disabled
Approval:          Required
Sample findings:   Included
```

Live remediation is not automatic. Connecting AWS does not enable live remediation. Live execution requires explicit configuration (`DRY_RUN_REMEDIATION=false` + `EXECUTION_ROLE_ARN`).

---

## Architecture

```
Sample or Connected Findings → Normalization & Deduplication → 0–5 Security Score
→ Dashboard → Bedrock Reasoning → Approval-Gated Dry-Run / Optional Controlled Execution
```

### 5 Security Areas

| Area | Covers |
|------|--------|
| Identity & Access | IAM, Organizations |
| Data Protection | S3, KMS |
| Network Security | EC2 security groups, VPC |
| Vulnerability Management | Inspector, SSM |
| Incident Readiness | GuardDuty, Security Hub, CloudTrail, Config |

---

## Optional: Connected AWS Scan

Prowler is an open-source AWS security assessment tool used to scan a real AWS account and generate security findings. It is **optional** for the sample workflow and only needed when you want to run a connected AWS scan.

### Install Prowler

Mac/Linux:
```bash
./scripts/install_prowler.sh
```

Windows:
```powershell
.\scripts\install_prowler.ps1
```

Or during setup:
```bash
./scripts/setup_demo.sh --with-prowler
```

---

## Direct Script Commands

These are available as an alternative to `quickstart.py`:

### Mac / Linux

```bash
./scripts/setup_demo.sh
./scripts/run_demo.sh
```

### Windows PowerShell

```powershell
.\scripts\setup_demo.ps1
.\scripts\run_demo.ps1
```

---

## Requirements

### Required for sample workflow

- Git
- Python 3.9+ (3.10+ recommended)
- Local terminal (Mac/Linux) or PowerShell (Windows)

### Optional

- AWS CLI and credentials — for connected AWS assessment
- Prowler — for connected AWS scans
- Amazon Bedrock model access — for AI chat
- uvx/MCP runtime — for AWS documentation context

---

## Where Connected Scan Results Are Stored

Sample findings run locally and do not require AWS.

Connected AWS scans write raw Prowler results locally under:

```
data/tmp/prowler-runs/<scan_id>/<timestamp>/
```

For audit and repeatability, connected scan reports can also be saved to a private S3 bucket in the connected AWS account using date/hour prefixes:

```
s3://<bucket>/agentic-security-posture/scans/<account-id>/year=YYYY/month=MM/day=DD/hour=HH/<scan-id>/
```

The dashboard shows the storage destination before the scan starts. S3 bucket creation or upload requires explicit confirmation. Set `REPORT_STORAGE_MODE=local+s3` to enable dual storage.

---

## Cost and Safety

The sample workflow runs locally with included findings. AWS usage is only introduced when the user chooses connected AWS scans, Bedrock-powered AI, or optional live remediation.

Live remediation is disabled by default and requires explicit configuration:
- `DRY_RUN_REMEDIATION=false`
- `EXECUTION_ROLE_ARN` configured
- Approved remediation action ID
- Low-risk allowlisted action only

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `.venv` not found | Run setup again: `python3 quickstart.py --setup-only` |
| Port 8080 busy | Stop old process: `kill -9 $(lsof -ti:8080)` |
| PowerShell blocks scripts | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| Prowler missing | Sample workflow still works. Install later with `./scripts/install_prowler.sh` |
| Bedrock unavailable | Dashboard works; AI chat requires Bedrock model access |
| Sample findings show 0 | Confirm `sample-data/prowler-output/sample-findings.json` exists |

---

## Documentation

- [Agent Safety and Usage Guide](docs/AGENT_SAFETY_AND_USAGE.md)
- [Customer Demo Walkthrough](docs/CUSTOMER_DEMO_WALKTHROUGH.md)
- [Demo Scenarios](docs/DEMO_SCENARIOS.md)
- [Connected AWS Mode](docs/connected-aws-mode.md)
- [AWS MCP Integration](docs/aws-mcp-integration.md)

---

## GitHub Pages

[https://lxrsd.github.io/agentic-genai-security-accelerator/](https://lxrsd.github.io/agentic-genai-security-accelerator/)
