# Agent Safety and Usage Guide

## Overview

The Agentic Security Posture Accelerator includes a controlled remediation agent powered by Amazon Bedrock. The agent can investigate your AWS security posture, generate remediation plans, and — when explicitly enabled — execute approved low-risk remediations.

Safety is built into every layer. The agent cannot make AWS changes without your explicit approval through a dedicated UI modal.

---

## What the Agent Can Do

| Capability | Description | Mode Required |
|---|---|---|
| Answer posture questions | Score, findings, pillar explanations, remediation suggestions | Findings Only |
| Investigate live AWS | Query IAM users, S3 config, CloudTrail events, Security Hub, GuardDuty, Inspector | Investigation |
| Generate remediation plans | CLI commands, Terraform/CloudFormation patches, rollback plans, risk analysis | Planning |
| Dry-run execution | Simulate the full execution workflow without making AWS changes | Dry-Run Execution |
| Live execution (low-risk) | Execute approved low-risk remediations (S3 encryption, GuardDuty, etc.) | Live Execution |

---

## Agent Modes

The agent operates in one mode at a time, controlled by feature flags in your `.env` file.

### Findings Only (Default)

The agent can only answer questions using imported Prowler findings. No live AWS queries. No execution.

### Investigation

The agent can query live AWS data using read-only APIs (IAM, S3, EC2, CloudTrail, Security Hub, GuardDuty, Inspector). No changes to AWS.

### Planning

The agent can generate exact remediation plans, CLI commands, Terraform patches, CloudFormation patches, rollback plans, and risk assessments. No changes to AWS.

### Dry-Run Execution

The agent simulates the full execution workflow (plan → approve → execute → verify) but does not call AWS-mutating APIs. Before/after states are simulated.

### Live Execution

The agent can execute approved, low-risk remediation actions in AWS. Real API calls are made. Before/after states are captured. Full audit trail.

---

## Safety Guardrails

### Approval Required

Every remediation action — including dry-run — requires explicit UI-based approval through the Approval Modal. The agent cannot be tricked into executing via chat text like "yes" or "go ahead."

### Allowlist / Blocklist

Only explicitly allowlisted AWS API actions can be executed:

**Allowed (low-risk):**
- `s3:PutPublicAccessBlock`
- `s3:PutEncryptionConfiguration`
- `kms:EnableKeyRotation`
- `guardduty:CreateDetector`
- `securityhub:BatchEnableStandards`
- `cloudtrail:CreateTrail`
- `cloudtrail:StartLogging`

**Permanently blocked:**
- `iam:DeleteUser`, `iam:DeleteRole`, `iam:DeleteAccessKey`
- `s3:DeleteBucket`
- `cloudtrail:DeleteTrail`
- `guardduty:DeleteDetector`
- `kms:ScheduleKeyDeletion`
- Attaching `AdministratorAccess` or `PowerUserAccess`
- Adding security group rules with `0.0.0.0/0`
- Modifying KMS key policies

### Single-Use Action IDs

Every remediation action gets a unique `Remediation_Action_ID`. Once an action is executed (dry-run or live), that ID is consumed and cannot be used again.

### IAM Role Separation

- **Read-Only Role** — Used for investigation queries. Cannot modify resources.
- **Execution Role** — Used only for live remediation. Scoped to allowlisted actions. Never uses `AdministratorAccess`.

### Before/After State Capture

Before any live execution, the agent captures the current resource configuration. After execution, it captures the new state and verifies the change succeeded.

### Audit Logging

Every action is logged to `data/audit/remediation_audit.jsonl`:
- Queued, approved, rejected, skipped, dry-run, executed, blocked
- Timestamp, actor, action ID, resource, API action, risk, outcome
- Before-state and after-state when applicable

### Risk Classification

| Risk Level | Examples | Live Execution |
|---|---|---|
| Low | Enable S3 encryption, enable GuardDuty, enable KMS rotation | Allowed (with approval) |
| Medium | Modify security groups, disable access keys | Planning only (Phase 6) |
| High | Delete users/roles/keys, modify production network | Planning only (blocked) |

---

## Feature Flags (.env)

```bash
# Agent capability levels
INVESTIGATION_TOOLS_ENABLED=false    # Enable live AWS read-only queries
REMEDIATION_PLANNING_ENABLED=false   # Enable plan/CLI/IaC generation
REMEDIATION_EXECUTION_ENABLED=false  # Enable execution workflow
DRY_RUN_REMEDIATION=true             # true = simulate only, false = real AWS calls
REQUIRE_APPROVAL_FOR_ALL_REMEDIATION=true  # Always require UI approval

# Risk controls
ALLOW_MEDIUM_RISK_REMEDIATION=false  # Allow medium-risk live execution
ALLOW_HIGH_RISK_REMEDIATION=false    # Allow high-risk live execution (not recommended)

# IAM roles (optional — falls back to current credentials for local dev)
READ_ONLY_ROLE_ARN=
EXECUTION_ROLE_ARN=
```

### Flag Dependencies

Flags enforce a dependency chain — you cannot enable a higher level without its prerequisites:

```
Investigation → Planning → Execution
                             ├── Medium-Risk → High-Risk
                             └── Dry-Run / Live toggle
```

If you set `REMEDIATION_PLANNING_ENABLED=true` without `INVESTIGATION_TOOLS_ENABLED=true`, planning will be automatically disabled with a warning.

---

## AWS Connected vs Agent Mode

These are separate concepts:

| Concept | What It Means |
|---|---|
| **AWS Connected** | Your AWS credentials are verified (STS identity check passed). Prowler can scan. |
| **Agent Mode** | Which capabilities the assistant has (Findings Only, Investigation, Planning, Execution). |

You can be AWS Connected but in Findings Only mode — the assistant won't query live AWS even though credentials exist.

You can also enable Investigation mode without AWS Connected — the tools will attempt to query but return "client not available" errors.

---

## Recommended Demo Mode

For demonstrations and evaluations, use dry-run mode:

```bash
INVESTIGATION_TOOLS_ENABLED=true
REMEDIATION_PLANNING_ENABLED=true
REMEDIATION_EXECUTION_ENABLED=true
DRY_RUN_REMEDIATION=true
```

This gives the full UX — queue, approval modal, execution workflow — without making any AWS changes. Results are simulated and clearly labeled.

---

## Live Remediation (Low-Risk Only)

To enable real AWS changes for low-risk actions:

```bash
INVESTIGATION_TOOLS_ENABLED=true
REMEDIATION_PLANNING_ENABLED=true
REMEDIATION_EXECUTION_ENABLED=true
DRY_RUN_REMEDIATION=false
REQUIRE_APPROVAL_FOR_ALL_REMEDIATION=true
```

**Warning:** With `DRY_RUN_REMEDIATION=false`, approved low-risk actions will make real AWS API calls. Verify your `EXECUTION_ROLE_ARN` has least-privilege permissions scoped to the allowlisted actions only.

### What gets executed:
- Enable S3 Block Public Access on specific buckets
- Enable S3 default encryption (AES-256)
- Enable KMS automatic key rotation
- Enable GuardDuty detector
- Enable Security Hub standards
- Start CloudTrail logging

### What never gets executed:
- Deleting users, roles, keys, buckets, trails, or detectors
- Attaching admin policies
- Opening security groups to 0.0.0.0/0
- Modifying KMS key policies
- Any medium or high-risk action (unless explicitly enabled via flags)

---

## Approval Workflow

1. Assistant generates a remediation plan
2. User adds it to the remediation queue
3. User opens the Approval Modal (or clicks "Review")
4. Modal shows: action ID, resource, API action, risk, blast radius, rollback plan, score impact
5. User clicks **Approve** or **Reject**
6. If approved: user can run Dry-Run or Live Execute
7. Result: before/after state, verification, audit log entry

Chat text like "yes" or "do it" never triggers execution. Only the modal button does.

---

## Audit Log

Location: `data/audit/remediation_audit.jsonl`

Each line is a JSON object with:
- `timestamp` — UTC ISO 8601
- `action_type` — queued, approved, rejected, dry_run, executed, blocked
- `remediation_action_id` — unique action identifier
- `finding_id` — associated security finding
- `target_resource` — AWS resource ARN
- `proposed_action` — AWS API action
- `risk_category` — low, medium, high
- `execution_outcome` — not_executed, dry_run, success, failure
- `response_source` — where the result came from

---

## Troubleshooting

### Agent says "Live AWS investigation is not enabled"

Set `INVESTIGATION_TOOLS_ENABLED=true` in `.env` and restart.

### Agent says "Execution is not enabled"

Set `REMEDIATION_EXECUTION_ENABLED=true` in `.env` and restart.

### Dry-run works but live execution is blocked

Check that `DRY_RUN_REMEDIATION=false` in `.env`. Also verify AWS credentials are valid.

### "Action not on allowlist" error

The proposed AWS API action is not in the approved set. Only the 7 low-risk actions are currently allowlisted for live execution.

### "Medium-risk blocked" error

`ALLOW_MEDIUM_RISK_REMEDIATION` is false (default). Medium-risk actions like security group changes and access key disabling are plan-only.

### Audit log not writing

Check that `data/audit/` directory exists and has write permissions. The agent creates it automatically on first use.

### Execution role errors

If `EXECUTION_ROLE_ARN` is set, verify the role trust policy allows your current identity to assume it. For local development, leave it empty to use current credentials.

### Planning tools not available

Verify both `INVESTIGATION_TOOLS_ENABLED=true` and `REMEDIATION_PLANNING_ENABLED=true`. Planning requires investigation as a prerequisite.

---

## Security Considerations

- The agent treats all finding descriptions, resource names, tags, and log entries as untrusted data
- Prompt injection attempts embedded in findings are ignored
- Access key IDs are masked (last 4 characters only) in all responses
- Secret keys, tokens, and passwords are never displayed
- The agent states its data source in every response
- The agent refuses to claim it made changes unless AWS confirms it
