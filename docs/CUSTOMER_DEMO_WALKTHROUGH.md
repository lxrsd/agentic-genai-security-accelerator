# Customer Demo Walkthrough

## What This Demo Shows

The Agentic Security Posture Accelerator demonstrates an AI-powered security assistant that can:

1. **Ingest findings** — Import AWS security findings from Prowler scans
2. **Explain posture** — Score and explain your security posture across 5 areas
3. **Investigate AWS** — Query live IAM, S3, CloudTrail, Security Hub, GuardDuty, Inspector (read-only)
4. **Create remediation plans** — Generate implementation steps, CLI commands, Terraform/CloudFormation patches
5. **Queue remediation actions** — Track planned remediations with risk classification
6. **Require approval** — Every action needs explicit UI approval before execution
7. **Run dry-run execution** — Simulate the full execution workflow without making changes
8. **Write audit logs** — Full audit trail of all actions
9. **Optionally execute** — Approved low-risk actions can be executed live (when explicitly enabled)

---

## Recommended Demo Mode

Use **dry-run mode** for all customer demos:

```
DRY_RUN_REMEDIATION=true
```

This shows the complete remediation workflow — plan, queue, approve, execute, verify, audit — without making any AWS changes. All results are clearly labeled as dry-run.

---

## Setup

```bash
git clone https://github.com/lxrsd/agentic-genai-security-accelerator.git
cd agentic-genai-security-accelerator
cp .env.demo .env
./scripts/setup_demo.sh
./scripts/run_demo.sh
```

Open: **http://127.0.0.1:8080**

---

## Demo Flow

### 1. Start the Dashboard
Run `./scripts/run_demo.sh` and open the dashboard in your browser.

### 2. Connect AWS
Click "Connect AWS" in the AWS Setup card. The system verifies your credentials via STS.

### 3. Run a Prowler Scan
Select a scan mode (Ultra Micro for speed, Quick Report for real assessment) and click "Run Scan." Watch progress inline.

### 4. Review the Score
After scan completes, the hero section shows your overall posture score (0–5) with metrics.

### 5. Explore Security Areas
Click "View Details" on any pillar card. Show:
- Deduplicated findings grouped by control
- Affected resource counts
- AWS documentation links
- Source attribution

### 6. Ask the Assistant
Try these prompts:
- "Why is my score low?"
- "What should I fix first?"
- "Create a 30-day remediation plan"
- "Generate AWS CLI commands to fix S3 public access"

### 7. Generate a Remediation Plan
Ask: "Create a remediation plan for S3 public access"

The assistant returns: risk category, blast radius, implementation steps, CLI commands, rollback plan, and AWS documentation.

### 8. Add to Queue
Use the API or UI to add the planned action to the remediation queue.

### 9. Open the Approval Modal
Click "Review" on the queued action. The modal shows:
- Action ID, finding, resource, API action
- Risk category, blast radius
- Rollback plan, score impact
- Warning: "No AWS changes will be made"

### 10. Approve
Click "Approve" in the modal.

### 11. Run Dry-Run
Click "Run Dry-Run" on the approved action. The result shows:
- Simulated before-state
- Simulated after-state
- Simulated verification
- Audit log reference
- Clear message: "No AWS changes were made"

### 12. Show Audit Log
The audit section shows the full lifecycle: queued → approved → dry_run.

### 13. Explain Safety
Point out:
- No AWS resources were changed
- Approval was required
- Action IDs are single-use
- Medium/high-risk actions are blocked
- Chat text cannot trigger execution

---

## Example Customer Prompts

```
Why is my score low?
What should I fix first?
Explain this finding.
Create a 30-day remediation plan.
Show me the AWS documentation for this issue.
Generate AWS CLI commands to fix S3 public access.
What would improve my score the most?
What happens if I approve this action?
Did this change AWS?
```

---

## Live Low-Risk Remediation Demo

> **Warning:** Live remediation should only be demonstrated against a safe test account or disposable resources.

To show live execution:

1. Create a disposable test S3 bucket (without Block Public Access)
2. Set in `.env`:
   ```
   DRY_RUN_REMEDIATION=false
   EXECUTION_ROLE_ARN=arn:aws:iam::<account-id>:role/SecurityRemediationRole
   ```
3. Restart the server
4. Generate a plan for the test bucket
5. Queue and approve the action
6. Click "Run Live"
7. Show real before-state (public access not blocked)
8. Show real after-state (public access now blocked)
9. Show verification and audit log

Emphasize: medium-risk and high-risk actions remain blocked even in live mode.
