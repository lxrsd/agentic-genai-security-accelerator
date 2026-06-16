# Connected AWS Mode

Use Connected AWS Mode to scan your own AWS account with Prowler and view your real security posture in the accelerator.

## Prerequisites

- **AWS CLI** installed and configured
- **AWS credentials** with sufficient permissions (see below)
- **Prowler CLI** installed ([Prowler installation guide](https://docs.prowler.com/projects/prowler-open-source/en/latest/getting-started/requirements/))
- **Python 3.9+** with `pip install -r requirements.txt`

## IAM Permissions

Prowler requires read-only access to scan your AWS account. Use one of these approaches:

| Approach | Policy |
|----------|--------|
| AWS managed policy | `SecurityAudit` |
| Broader read access | `ReadOnlyAccess` |
| Custom role | `ProwlerSecurityAuditRole` with SecurityAudit attached |

The accelerator itself does not require AWS write permissions. All operations are read-only.

## Authentication Options

### Option 1: CLI Credentials

Configure AWS CLI credentials directly:

```bash
aws configure
# Enter Access Key ID, Secret Access Key, and Region
```

### Option 2: AWS SSO

Use AWS IAM Identity Center (SSO):

```bash
aws sso login --profile your-profile
export AWS_PROFILE=your-profile
```

### Option 3: Assumed Role

Create a dedicated Prowler role and assume it:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<ACCOUNT_ID>:role/ProwlerSecurityAuditRole \
  --role-session-name prowler-scan
```

## Running a Prowler Scan

### Step 1: Verify AWS Credentials

```bash
aws sts get-caller-identity
```

Expected output shows your account ID, ARN, and user/role. If this fails, fix your credentials before proceeding.

### Step 2: Run Prowler

**Standard scan with your current credentials:**

```bash
prowler aws --output-formats json csv html --output-directory ./sample-data/prowler-output/
```

**Scan using an assumed role:**

```bash
prowler aws -R arn:aws:iam::<ACCOUNT_ID>:role/ProwlerSecurityAuditRole \
  --output-formats json csv html --output-directory ./sample-data/prowler-output/
```

Prowler will scan your account and write findings to the output directory. A full scan typically takes 15–45 minutes depending on account size.

### Step 3: Import Findings

Restart the accelerator to pick up the new findings:

```bash
python -m backend.main
```

Or specify the data directory explicitly:

```bash
python -m backend.main --data-dir ./sample-data/prowler-output/
```

### Step 4: Verify in Dashboard

Open [http://localhost:8080](http://localhost:8080) and confirm:

- The overall score reflects your real findings
- All 5 security areas show scores based on your account's findings
- Top gaps list shows your actual highest-severity issues
- Connection status shows "Prowler Data: Connected"

## Troubleshooting

### "No findings loaded" in dashboard

- Check that Prowler output directory contains `.json` files
- Verify the JSON files follow Prowler output format
- Check the terminal for import warnings about malformed entries

### Prowler scan fails with access denied

- Verify your credentials: `aws sts get-caller-identity`
- Ensure the IAM user/role has `SecurityAudit` or `ReadOnlyAccess` policy
- Check that the role trust policy allows your user to assume it

### Scores seem wrong

- Findings are mapped by AWS service name to security areas
- If a service isn't recognized, findings default to Incident Readiness
- Areas with zero findings show "Not Evaluated" (not zero)
- The overall score averages only evaluated areas

### Prowler produces empty output

- Ensure you're scanning the correct AWS account and region
- Some checks require specific services to be enabled (e.g., GuardDuty, CloudTrail)
- Try running Prowler with verbose output: `prowler aws -v`

### Dashboard doesn't update after new scan

- Stop and restart the accelerator — it loads findings at startup
- Confirm the new JSON files are in the configured data directory
- Check for file permission issues on the output directory

## Tips

- Start with a single-region scan for faster results: `prowler aws --region us-east-1 --output-formats json --output-directory ./sample-data/prowler-output/`
- Use `--severity critical high` to focus on high-impact findings first
- The accelerator processes all JSON files in the data directory — remove old scans if you want fresh results only
- Prowler's HTML report provides a complementary detailed view alongside the accelerator's scored dashboard
