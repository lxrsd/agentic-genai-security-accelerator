# Demo Guide

A 5-minute walkthrough of the Agentic GenAI Security Accelerator for customer presentations.

## Prerequisites

- Python 3.9+ installed
- Dependencies installed: `pip install -r requirements.txt`

## Start the Demo

```bash
python -m backend.main
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

## Demo Flow (5 Minutes)

### 1. View the Dashboard (30 seconds)

Show the dark-themed command-center dashboard. Point out the overall posture score gauge and explain that scores are calculated from real Prowler findings using a deterministic formula.

### 2. Show the Overall Score (30 seconds)

Highlight the overall 0–5 score. Explain the score labels:
- 0–1: Critical Gaps
- 1–2: Needs Attention
- 2–3: Developing
- 3–4: Strong
- 4–5: Optimized

The score is an average of all evaluated security areas.

### 3. Walk Through the 5 Security Areas (1 minute)

Show each area card:
- **Identity & Access** — IAM, Organizations
- **Data Protection** — S3, KMS
- **Network Security** — EC2 security groups, VPC
- **Vulnerability Management** — Inspector, SSM
- **Incident Readiness** — GuardDuty, Security Hub, CloudTrail

If an area has no findings, it displays "Not Evaluated" and is excluded from the overall score.

### 4. Show Top Security Gaps (1 minute)

Scroll to the gaps table. Highlight highest-severity findings. Explain that each gap is a real Prowler finding with severity, affected area, and resource details.

### 5. Show the Remediation Plan (1 minute)

Show the planning-only remediation section. Explain:
- Actions are prioritized by impact and difficulty
- Each action shows estimated score improvement
- **Remediation is planning-only — no AWS changes are executed**

### 6. Use the Score Simulator (30 seconds)

Demonstrate the improvement simulator. Select findings to hypothetically remediate and show how the projected score changes. This helps customers prioritize which findings to fix first.

### 7. Show the AI Chat Panel (30 seconds)

Open the chat panel. Note the Bedrock connection status:
- If Bedrock is connected: ask a question like "What are my top risks?"
- If Bedrock is not connected: show the "Not connected" message and explain that full AI answers require Bedrock configuration

## What Works Without Bedrock

Everything in the scoring and dashboard layer works without Bedrock or AWS MCP:

- ✅ Prowler findings import and normalization
- ✅ Security area classification (5 areas)
- ✅ Deterministic 0–5 scoring per area
- ✅ Overall posture score calculation
- ✅ Not Evaluated state for empty areas
- ✅ Top security gaps display
- ✅ Remediation plan (planning-only)
- ✅ Score improvement simulator
- ✅ Connection status display
- ✅ Mode selector (Demo / Connected AWS)

## What Requires Bedrock

The AI assistant chat requires Amazon Bedrock:

- Ask questions about your security posture
- Get explanations of specific findings
- Receive prioritized remediation guidance
- Understand business impact of gaps

Without Bedrock configured, the chat panel shows: "Bedrock not connected. Configure BEDROCK_ENABLED=true and set AWS credentials."

## What Requires AWS MCP

AWS best-practice guidance in assistant answers requires connected AWS MCP servers:

- Official AWS documentation references
- AWS-recommended remediation steps
- IAM policy best practices
- Service-specific security guidance

Without AWS MCP, the assistant answers using local posture data only and notes that "AWS MCP not connected for best-practice guidance."

## Expected "Not Connected" States

During a demo without full AWS configuration, you will see:

| Service | Expected State | Meaning |
|---------|---------------|---------|
| Prowler Data | ✅ Connected | Sample findings are loaded |
| Bedrock | ❌ Not Connected | BEDROCK_ENABLED not set to true |
| AWS Knowledge MCP | ❌ Not Connected | AWS_KNOWLEDGE_MCP_ENABLED not set |
| AWS API MCP | ❌ Not Connected | AWS_API_MCP_ENABLED not set |
| IAM MCP | ❌ Not Connected | IAM_MCP_ENABLED not set |
| CloudTrail MCP | ❌ Not Connected | Optional, not configured |
| Security Hub MCP | ❌ Not Connected | Optional, not configured |

These states are honest — the system never fakes connections or fabricates AWS data. This is by design: customers see exactly what is and isn't connected.

## Demo Talking Points

- "Scoring is fully deterministic — no AI needed to calculate your score"
- "The 5 security areas map directly to Prowler findings by AWS service"
- "Remediation is planning-only — the tool never modifies your AWS environment"
- "When Bedrock and AWS MCP are connected, you get AI answers grounded in your real posture data and official AWS documentation"
- "Not Connected states are honest — we never fake AWS guidance"
