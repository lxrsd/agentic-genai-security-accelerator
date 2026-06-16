# Demo Scenarios

Three ready-to-use demo scenarios showing the agent remediation workflow.

---

## Scenario 1 — S3 Public Access (Dry-Run)

**Customer story:** "An S3 bucket allows public access. The agent recommends enabling Block Public Access."

**Expected action:** `s3:PutPublicAccessBlock`

### Steps

1. **Ask the assistant:** "What are my top security gaps?"
2. Find the S3 public access finding in the response
3. **Ask:** "Create a remediation plan for S3 public access"
4. Review the plan: risk=low, blast radius (may break public websites), rollback plan
5. **Add to queue** via POST `/api/remediation/queue` or UI button
6. **Open approval modal** — click "Review"
7. **Approve** — click "Approve"
8. **Run Dry-Run** — click "Run Dry-Run"
9. **Show result:**
   - Before: `{BlockPublicAcls: false, IgnorePublicAcls: false, ...}`
   - After: `{BlockPublicAcls: true, IgnorePublicAcls: true, ...}`
   - Verification: "Public access block confirmed active"
   - Message: "No AWS changes were made"

### Safety guardrails shown
- Approval required before execution
- Risk classification visible (low)
- Blast radius warning (website breakage)
- Rollback plan available
- Dry-run clearly labeled
- Audit log entry created

---

## Scenario 2 — S3 Default Encryption (Dry-Run)

**Customer story:** "An S3 bucket does not enforce default encryption for data at rest."

**Expected action:** `s3:PutEncryptionConfiguration`

### Steps

1. **Ask:** "Which S3 findings have the highest score impact?"
2. **Ask:** "Generate CLI commands to enable S3 default encryption"
3. Review CLI commands (provided for reference, not executed)
4. **Ask:** "Generate a Terraform patch for S3 encryption"
5. Review HCL snippet
6. **Add to queue** and approve
7. **Run Dry-Run**
8. **Show result:**
   - Before: `{ServerSideEncryptionConfiguration: null}`
   - After: `{ServerSideEncryptionConfiguration: {Rules: [{SSEAlgorithm: "AES256"}]}}`
   - Message: "No AWS changes were made"

### Safety guardrails shown
- CLI commands clearly state "NOT executed"
- Terraform patch is for review only
- Planning mode generates guidance without changes

---

## Scenario 3 — GuardDuty Enablement (Dry-Run)

**Customer story:** "Threat detection is not enabled in this region. GuardDuty should be active."

**Expected action:** `guardduty:CreateDetector`

### Steps

1. **Ask:** "Is GuardDuty enabled?"
2. If investigation tools are active, the assistant queries live AWS and reports status
3. **Ask:** "Create a remediation plan to enable GuardDuty"
4. Review: risk=low, minimal blast radius, no downtime
5. **Ask:** "What's the rollback plan if I enable GuardDuty?"
6. Review: "Delete the GuardDuty detector"
7. **Ask:** "Validate the safety of enabling GuardDuty"
8. Result: verdict=SAFE, low risk, allowlisted
9. **Queue, approve, dry-run**
10. **Show result:**
    - Before: `{DetectorExists: false}`
    - After: `{DetectorId: "dry-run-detector-id", Status: "ENABLED"}`
    - Message: "No AWS changes were made"

### Safety guardrails shown
- Safety validation before execution
- Even "safe" actions require approval
- Audit log tracks the full lifecycle
- Assistant clearly states whether it used live AWS data or imported findings

---

## Notes for Presenters

- Always start with `DRY_RUN_REMEDIATION=true`
- The assistant states its data source in every response
- If AWS is not connected, investigation tools return "client not available"
- Medium/high-risk actions show "CAUTION" or "BLOCKED" in safety validation
- The blocklist permanently prevents destructive actions regardless of configuration
