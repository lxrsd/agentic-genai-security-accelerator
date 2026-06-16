"""Remediation Planning Tools — Generate plans, CLI commands, IaC patches, rollback plans.

PLANNING-ONLY: These tools generate guidance and implementation steps but
NEVER call mutating AWS APIs. They do not Create, Put, Update, Delete,
Attach, Detach, Enable, Disable, Start, Stop, Revoke, Authorize, or Modify
any AWS resource.

Every plan includes: risk category, blast radius, prerequisites, rollback
plan, implementation steps, and response source.
"""

import logging
from typing import Any, Dict, List, Optional

from backend.aws_best_practice_docs import get_docs_for_finding

logger = logging.getLogger(__name__)


# ─── Risk Classification ────────────────────────────────────────────────────

RISK_CLASSIFICATIONS: Dict[str, str] = {
    # Low-risk candidates (still require pre-checks and approval)
    "s3_block_public_access": "low",
    "s3_default_encryption": "low",
    "kms_key_rotation": "low",
    "guardduty_enable": "low",
    "securityhub_enable": "low",
    "cloudtrail_enable": "low",
    # Medium-risk
    "bucket_policy_modify": "medium",
    "security_group_modify": "medium",
    "iam_access_key_disable": "medium",
    "iam_permission_boundary": "medium",
    "iam_policy_detach": "medium",
    # High-risk
    "iam_user_delete": "high",
    "iam_key_delete": "high",
    "iam_role_delete": "high",
    "iam_policy_remove_active": "high",
    "network_production_modify": "high",
    "kms_key_policy_modify": "high",
}

# Finding keyword → risk action mapping
_FINDING_RISK_MAP: Dict[str, str] = {
    "public access": "s3_block_public_access",
    "block public": "s3_block_public_access",
    "default encryption": "s3_default_encryption",
    "server-side encryption": "s3_default_encryption",
    "key rotation": "kms_key_rotation",
    "guardduty": "guardduty_enable",
    "security hub": "securityhub_enable",
    "cloudtrail": "cloudtrail_enable",
    "bucket policy": "bucket_policy_modify",
    "security group": "security_group_modify",
    "ingress": "security_group_modify",
    "ssh": "security_group_modify",
    "rdp": "security_group_modify",
    "access key": "iam_access_key_disable",
    "permission boundary": "iam_permission_boundary",
    "detach": "iam_policy_detach",
    "delete user": "iam_user_delete",
    "delete key": "iam_key_delete",
    "delete role": "iam_role_delete",
}


def _classify_risk(finding_title: str, check_id: str = "") -> str:
    """Classify the risk category for a remediation based on finding context."""
    text = (finding_title + " " + check_id).lower()
    for keyword, action in _FINDING_RISK_MAP.items():
        if keyword in text:
            return RISK_CLASSIFICATIONS.get(action, "medium")
    return "medium"  # Default to medium if unknown


def _get_blast_radius(risk_category: str, finding_title: str) -> str:
    """Assess blast radius based on risk and finding type."""
    text = finding_title.lower()
    if "s3" in text and "public" in text:
        return "Public websites or applications serving content from this bucket may break. External integrations relying on public read access will fail."
    if "s3" in text and "encryption" in text:
        return "Existing unencrypted objects remain unencrypted. New objects will be encrypted. Applications with custom encryption logic should be verified."
    if "kms" in text and "rotation" in text:
        return "Minimal impact. AWS manages key rotation transparently. Applications using the key continue to work."
    if "guardduty" in text:
        return "Minimal operational impact. Enables threat detection. May generate new findings that require triage."
    if "security hub" in text:
        return "Minimal operational impact. Enables compliance monitoring. May generate findings requiring triage."
    if "cloudtrail" in text:
        return "Minimal operational impact. Enables audit logging. Incurs S3 storage costs for log files."
    if "security group" in text or "ssh" in text or "ingress" in text:
        return "Active connections using the revoked rules will be dropped. Remote access via SSH/RDP may be lost if no alternative (VPN, Session Manager) is configured."
    if "access key" in text:
        return "Applications or scripts using the disabled key will fail authentication. Verify no active workloads depend on this key before disabling."
    if risk_category == "high":
        return "HIGH BLAST RADIUS. This action may break applications, remove access for active users, or disrupt production workloads. Manual review strongly recommended."
    return "Moderate. Review dependent services and integrations before executing."


# ─── Planning Tools ─────────────────────────────────────────────────────────

class PlanningTools:
    """Remediation planning tools — generates guidance without making AWS changes.

    All methods return structured plans. None call mutating AWS APIs.
    """

    def __init__(self, posture_tools=None):
        """Initialize with posture tools for score impact estimation.

        Args:
            posture_tools: MCPServer instance for score simulation.
        """
        self._posture_tools = posture_tools

    def generate_remediation_plan(self, params: Dict = None) -> Dict[str, Any]:
        """Generate a complete remediation plan for a finding.

        Returns: finding details, resource, steps, risk, blast radius,
        time estimate, prerequisites, rollback, and documentation.
        """
        params = params or {}
        finding_title = params.get("finding_title", "")
        check_id = params.get("check_id", "")
        resource_arn = params.get("resource_arn", "")
        service = params.get("service", "")
        pillar = params.get("pillar", "")

        if not finding_title:
            return {"error": "finding_title parameter is required"}

        risk = _classify_risk(finding_title, check_id)
        blast_radius = _get_blast_radius(risk, finding_title)
        steps = self._generate_steps(finding_title, check_id, service)
        prerequisites = self._generate_prerequisites(finding_title, risk)
        rollback = self._generate_rollback_summary(finding_title, check_id)
        doc_links = get_docs_for_finding(check_id, service, pillar)

        return {
            "finding_title": finding_title,
            "check_id": check_id,
            "resource_arn": resource_arn or "Not specified",
            "service": service,
            "pillar": pillar,
            "risk_category": risk,
            "blast_radius": blast_radius,
            "prerequisites": prerequisites,
            "implementation_steps": steps,
            "estimated_time": self._estimate_time(risk),
            "rollback_summary": rollback,
            "doc_links": [{"title": d.title, "url": d.url, "reason": d.reason} for d in doc_links],
            "warnings": self._generate_warnings(risk, finding_title),
            "response_source": "Remediation Planning Engine",
            "note": "This is a plan only. No AWS changes have been made.",
        }

    def estimate_score_impact(self, params: Dict = None) -> Dict[str, Any]:
        """Estimate posture score improvement from remediating a finding."""
        params = params or {}
        finding_ids = params.get("finding_ids", [])

        if not finding_ids:
            return {"error": "finding_ids parameter is required (list of finding IDs)"}

        if not self._posture_tools:
            return {"error": "Score simulation not available."}

        try:
            result = self._posture_tools.simulate_score_improvement(finding_ids)
            result["response_source"] = "Remediation Planning Engine"
            result["note"] = "Estimated improvement. Actual score will be recalculated after remediation."
            return result
        except Exception as e:
            return {"error": f"Score impact estimation failed: {e}"}

    def generate_aws_cli_commands(self, params: Dict = None) -> Dict[str, Any]:
        """Generate AWS CLI commands for a remediation action.

        Returns commands for review — NOT for automatic execution.
        """
        params = params or {}
        finding_title = params.get("finding_title", "")
        check_id = params.get("check_id", "")
        resource_arn = params.get("resource_arn", "")
        bucket_name = params.get("bucket_name", "")
        group_id = params.get("group_id", "")

        if not finding_title:
            return {"error": "finding_title parameter is required"}

        commands = self._build_cli_commands(finding_title, check_id, resource_arn, bucket_name, group_id)
        risk = _classify_risk(finding_title, check_id)

        return {
            "finding_title": finding_title,
            "commands": commands,
            "risk_category": risk,
            "warning": "⚠️ Review these commands carefully before executing. They are provided for reference only and have NOT been executed.",
            "response_source": "Remediation Planning Engine",
        }

    def generate_terraform_patch(self, params: Dict = None) -> Dict[str, Any]:
        """Generate a Terraform HCL patch for a remediation."""
        params = params or {}
        finding_title = params.get("finding_title", "")
        check_id = params.get("check_id", "")
        resource_name = params.get("resource_name", "example")

        if not finding_title:
            return {"error": "finding_title parameter is required"}

        patch = self._build_terraform_patch(finding_title, check_id, resource_name)
        return {
            "finding_title": finding_title,
            "terraform_patch": patch,
            "warning": "Review and apply via terraform plan/apply after verifying resource names and configuration.",
            "response_source": "Remediation Planning Engine",
        }

    def generate_cloudformation_patch(self, params: Dict = None) -> Dict[str, Any]:
        """Generate a CloudFormation YAML patch for a remediation."""
        params = params or {}
        finding_title = params.get("finding_title", "")
        check_id = params.get("check_id", "")
        resource_name = params.get("resource_name", "ExampleResource")

        if not finding_title:
            return {"error": "finding_title parameter is required"}

        patch = self._build_cloudformation_patch(finding_title, check_id, resource_name)
        return {
            "finding_title": finding_title,
            "cloudformation_patch": patch,
            "warning": "Review and deploy via CloudFormation change set after verifying resource configuration.",
            "response_source": "Remediation Planning Engine",
        }

    def generate_rollback_plan(self, params: Dict = None) -> Dict[str, Any]:
        """Generate a rollback plan for a remediation action."""
        params = params or {}
        finding_title = params.get("finding_title", "")
        check_id = params.get("check_id", "")

        if not finding_title:
            return {"error": "finding_title parameter is required"}

        rollback = self._generate_detailed_rollback(finding_title, check_id)
        return {
            "finding_title": finding_title,
            "rollback_plan": rollback,
            "note": "Rollback requires capturing the before-state prior to execution. If executed manually, document the original configuration first.",
            "response_source": "Remediation Planning Engine",
        }

    def validate_remediation_safety(self, params: Dict = None) -> Dict[str, Any]:
        """Validate whether a remediation action is safe to execute.

        Checks: risk category, allowlist status, blast radius, dependent services.
        """
        params = params or {}
        finding_title = params.get("finding_title", "")
        check_id = params.get("check_id", "")
        action = params.get("action", "")

        if not finding_title:
            return {"error": "finding_title parameter is required"}

        risk = _classify_risk(finding_title, check_id)
        blast_radius = _get_blast_radius(risk, finding_title)

        # Check if action would be on the allowlist (informational only — no execution)
        from backend.allowlist import ALLOWED_ACTIONS, BLOCKED_ACTIONS
        action_allowed = action in ALLOWED_ACTIONS if action else None
        action_blocked = action in BLOCKED_ACTIONS if action else None

        if action_blocked:
            verdict = "BLOCKED"
            reason = f"Action '{action}' is on the permanent blocklist and cannot be executed."
        elif risk == "high":
            verdict = "CAUTION"
            reason = "High-risk action. Requires explicit high-risk flag enabled + manual review + approval."
        elif risk == "medium":
            verdict = "CAUTION"
            reason = "Medium-risk action. Requires medium-risk flag enabled + approval."
        elif action_allowed is False and action:
            verdict = "BLOCKED"
            reason = f"Action '{action}' is not on the execution allowlist."
        else:
            verdict = "SAFE"
            reason = "Low-risk candidate. Still requires pre-checks and explicit approval before execution."

        return {
            "finding_title": finding_title,
            "risk_category": risk,
            "blast_radius": blast_radius,
            "safety_verdict": verdict,
            "reason": reason,
            "action_on_allowlist": action_allowed,
            "action_on_blocklist": action_blocked,
            "prerequisites": self._generate_prerequisites(finding_title, risk),
            "response_source": "Remediation Planning Engine",
        }

    # ─── Internal Helpers ───────────────────────────────────────────

    def _generate_steps(self, title: str, check_id: str, service: str) -> List[str]:
        """Generate implementation steps based on finding type."""
        text = (title + " " + check_id).lower()

        if "public access" in text or "block public" in text:
            return [
                "1. Identify affected S3 bucket(s)",
                "2. Verify no public websites or integrations depend on public access",
                "3. Enable S3 Block Public Access at bucket level",
                "4. If account-wide: enable S3 Block Public Access at account level",
                "5. Verify bucket is no longer publicly accessible",
                "6. Monitor for application errors over 24 hours",
            ]
        if "encryption" in text and "s3" in text.lower():
            return [
                "1. Identify affected S3 bucket(s)",
                "2. Choose encryption method: SSE-S3 (AES-256) or SSE-KMS",
                "3. Enable default encryption on the bucket",
                "4. Note: existing objects remain unencrypted unless re-uploaded",
                "5. Verify new objects are encrypted",
            ]
        if "key rotation" in text or "kms" in text:
            return [
                "1. Identify affected KMS key(s)",
                "2. Verify key is customer-managed (AWS-managed keys rotate automatically)",
                "3. Enable automatic key rotation",
                "4. Verify rotation is active (takes effect within 365 days)",
            ]
        if "guardduty" in text:
            return [
                "1. Navigate to GuardDuty console or use CLI",
                "2. Enable GuardDuty detector in the target region",
                "3. Configure notification settings (SNS, EventBridge)",
                "4. Review initial findings after 24 hours",
            ]
        if "security hub" in text:
            return [
                "1. Navigate to Security Hub console or use CLI",
                "2. Enable Security Hub",
                "3. Enable desired security standards (CIS, PCI DSS, AWS Foundational)",
                "4. Review initial compliance status after 24 hours",
            ]
        if "cloudtrail" in text:
            return [
                "1. Create or verify a CloudTrail trail exists",
                "2. Enable multi-region logging",
                "3. Configure S3 bucket for log delivery (with encryption)",
                "4. Enable log file validation",
                "5. Verify events are being recorded",
            ]
        if "ssh" in text or ("security group" in text and "ingress" in text):
            return [
                "1. Identify the security group allowing unrestricted SSH/RDP",
                "2. Determine legitimate source IPs (office IP, VPN CIDR, bastion host)",
                "3. Revoke the 0.0.0.0/0 ingress rule",
                "4. Add restricted rule with specific source CIDR",
                "5. Consider using AWS Systems Manager Session Manager instead of SSH",
                "6. Verify connectivity from legitimate sources",
            ]
        if "access key" in text:
            return [
                "1. Identify the IAM user and access key",
                "2. Verify no active applications use this key (check CloudTrail)",
                "3. Create a new access key if rotation is needed",
                "4. Update applications with the new key",
                "5. Disable the old access key",
                "6. After verification period (7 days), delete the old key",
            ]
        if "mfa" in text:
            return [
                "1. Identify users without MFA enabled",
                "2. Notify users to enable MFA",
                "3. Provide instructions for virtual MFA setup",
                "4. Set a deadline for MFA enablement",
                "5. Consider enforcing MFA via IAM policy condition",
            ]
        return [
            "1. Review the finding details and affected resources",
            "2. Assess the blast radius and dependent services",
            "3. Plan the remediation steps specific to this control",
            "4. Test in a non-production environment if possible",
            "5. Execute with proper change management",
            "6. Verify the remediation was successful",
        ]

    def _generate_prerequisites(self, title: str, risk: str) -> List[str]:
        """Generate prerequisites for a remediation action."""
        prereqs = ["Verify AWS identity and permissions"]
        if risk in ("medium", "high"):
            prereqs.append("Confirm no active workloads depend on current configuration")
            prereqs.append("Document current resource state (before-state capture)")
        if risk == "high":
            prereqs.append("Obtain change management approval")
            prereqs.append("Prepare rollback plan with specific CLI commands")
            prereqs.append("Schedule maintenance window if needed")
        if "s3" in title.lower() and "public" in title.lower():
            prereqs.append("Verify no public websites or integrations rely on S3 public access")
        if "security group" in title.lower() or "ssh" in title.lower():
            prereqs.append("Verify alternative access method (VPN, Session Manager, bastion) is available")
        return prereqs

    def _generate_rollback_summary(self, title: str, check_id: str) -> str:
        """Generate a brief rollback summary."""
        text = (title + " " + check_id).lower()
        if "public access" in text:
            return "Remove S3 Block Public Access configuration to restore previous state."
        if "encryption" in text:
            return "Remove default encryption configuration. Note: already-encrypted objects remain encrypted."
        if "key rotation" in text:
            return "Disable automatic key rotation on the KMS key."
        if "guardduty" in text:
            return "Delete the GuardDuty detector to disable threat detection."
        if "security hub" in text:
            return "Disable Security Hub to stop compliance monitoring."
        if "cloudtrail" in text:
            return "Stop logging on the CloudTrail trail (not recommended for audit)."
        if "security group" in text or "ssh" in text:
            return "Re-add the revoked ingress rule with the original CIDR and port range."
        if "access key" in text:
            return "Re-activate the disabled access key using iam:UpdateAccessKey with Status=Active."
        return "Restore the resource to its previous configuration using the captured before-state."

    def _generate_detailed_rollback(self, title: str, check_id: str) -> Dict[str, Any]:
        """Generate a detailed rollback plan."""
        text = (title + " " + check_id).lower()
        steps = []
        cli_commands = []

        if "public access" in text:
            steps = ["Capture current Block Public Access config", "Remove Block Public Access", "Verify public access is restored"]
            cli_commands = ["aws s3api delete-public-access-block --bucket <BUCKET_NAME>"]
        elif "encryption" in text and "s3" in text:
            steps = ["Capture current encryption config", "Delete bucket encryption", "Verify default encryption is removed"]
            cli_commands = ["aws s3api delete-bucket-encryption --bucket <BUCKET_NAME>"]
        elif "key rotation" in text:
            steps = ["Identify KMS key", "Disable auto rotation"]
            cli_commands = ["aws kms disable-key-rotation --key-id <KEY_ID>"]
        elif "security group" in text or "ssh" in text:
            steps = ["Identify the security group", "Re-add the original ingress rule", "Verify connectivity"]
            cli_commands = ["aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr <ORIGINAL_CIDR>"]
        elif "access key" in text:
            steps = ["Identify the access key", "Re-activate the key"]
            cli_commands = ["aws iam update-access-key --user-name <USER> --access-key-id <KEY_ID> --status Active"]
        else:
            steps = ["Retrieve the before-state from audit log", "Apply the reverse configuration", "Verify resource state"]
            cli_commands = ["(Depends on specific action — use before-state to determine exact commands)"]

        return {
            "steps": steps,
            "cli_commands": cli_commands,
            "warning": "Rollback should only be performed if the remediation caused issues. Always verify before rolling back.",
        }

    def _generate_warnings(self, risk: str, title: str) -> List[str]:
        """Generate warnings based on risk and finding type."""
        warnings = []
        if risk == "high":
            warnings.append("⚠️ HIGH-RISK action. May break applications or remove access for active users.")
        if risk == "medium":
            warnings.append("⚠️ Medium-risk action. Verify no active workloads are affected.")
        if "low" == risk:
            warnings.append("ℹ️ Low-risk candidate. Still requires pre-checks and approval before execution.")
        if "public" in title.lower() and "s3" in title.lower():
            warnings.append("⚠️ Enabling Block Public Access may break public websites hosted on S3.")
        return warnings

    def _estimate_time(self, risk: str) -> str:
        """Estimate time to implement."""
        if risk == "low":
            return "5-15 minutes"
        if risk == "medium":
            return "15-60 minutes (includes verification)"
        return "1-4 hours (includes planning, approval, execution, verification)"

    def _build_cli_commands(self, title: str, check_id: str, resource_arn: str, bucket_name: str, group_id: str) -> List[Dict[str, str]]:
        """Build CLI command examples for the remediation."""
        text = (title + " " + check_id).lower()
        bucket = bucket_name or "<BUCKET_NAME>"
        sg = group_id or "<SECURITY_GROUP_ID>"

        if "public access" in text or "block public" in text:
            return [
                {"command": f"aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", "description": "Enable S3 Block Public Access on the bucket"},
            ]
        if "encryption" in text and "s3" in text:
            return [
                {"command": f"aws s3api put-bucket-encryption --bucket {bucket} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'", "description": "Enable default SSE-S3 encryption"},
            ]
        if "key rotation" in text:
            return [
                {"command": "aws kms enable-key-rotation --key-id <KEY_ID>", "description": "Enable automatic key rotation (365-day cycle)"},
            ]
        if "guardduty" in text:
            return [
                {"command": "aws guardduty create-detector --enable", "description": "Enable GuardDuty detector in current region"},
            ]
        if "security hub" in text:
            return [
                {"command": "aws securityhub enable-security-hub", "description": "Enable Security Hub with default standards"},
            ]
        if "cloudtrail" in text:
            return [
                {"command": "aws cloudtrail create-trail --name security-audit-trail --s3-bucket-name <LOG_BUCKET> --is-multi-region-trail --enable-log-file-validation", "description": "Create multi-region trail with log validation"},
                {"command": "aws cloudtrail start-logging --name security-audit-trail", "description": "Start logging events"},
            ]
        if "ssh" in text or ("security group" in text and "ingress" in text):
            return [
                {"command": f"aws ec2 revoke-security-group-ingress --group-id {sg} --protocol tcp --port 22 --cidr 0.0.0.0/0", "description": "Revoke SSH access from 0.0.0.0/0"},
                {"command": f"aws ec2 authorize-security-group-ingress --group-id {sg} --protocol tcp --port 22 --cidr <YOUR_IP>/32", "description": "Add SSH access from specific IP only"},
            ]
        if "access key" in text:
            return [
                {"command": "aws iam update-access-key --user-name <USER> --access-key-id <KEY_ID> --status Inactive", "description": "Disable the old access key"},
            ]
        if "mfa" in text:
            return [
                {"command": "aws iam create-virtual-mfa-device --virtual-mfa-device-name <USER>-mfa --outfile /tmp/qr.png --bootstrap-method QRCodePNG", "description": "Create virtual MFA device"},
                {"command": "aws iam enable-mfa-device --user-name <USER> --serial-number <MFA_ARN> --authentication-code1 <CODE1> --authentication-code2 <CODE2>", "description": "Enable MFA for user"},
            ]
        return [{"command": "# No specific CLI command template available for this control", "description": "Refer to AWS documentation for manual remediation steps"}]

    def _build_terraform_patch(self, title: str, check_id: str, resource_name: str) -> str:
        """Build Terraform HCL patch for the remediation."""
        text = (title + " " + check_id).lower()

        if "public access" in text or "block public" in text:
            return f'''resource "aws_s3_bucket_public_access_block" "{resource_name}" {{
  bucket = aws_s3_bucket.{resource_name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}'''
        if "encryption" in text and "s3" in text:
            return f'''resource "aws_s3_bucket_server_side_encryption_configuration" "{resource_name}" {{
  bucket = aws_s3_bucket.{resource_name}.id

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}'''
        if "key rotation" in text:
            return f'''resource "aws_kms_key" "{resource_name}" {{
  # ... existing config ...
  enable_key_rotation = true
}}'''
        if "guardduty" in text:
            return f'''resource "aws_guardduty_detector" "{resource_name}" {{
  enable = true
}}'''
        if "cloudtrail" in text:
            return f'''resource "aws_cloudtrail" "{resource_name}" {{
  name                          = "security-audit-trail"
  s3_bucket_name                = aws_s3_bucket.trail_logs.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}}'''
        return f"# No Terraform template available for this control.\n# Refer to AWS provider documentation for resource: {resource_name}"

    def _build_cloudformation_patch(self, title: str, check_id: str, resource_name: str) -> str:
        """Build CloudFormation YAML patch for the remediation."""
        text = (title + " " + check_id).lower()

        if "public access" in text or "block public" in text:
            return f'''  {resource_name}PublicAccessBlock:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true'''
        if "encryption" in text and "s3" in text:
            return f'''  {resource_name}:
    Type: AWS::S3::Bucket
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256'''
        if "guardduty" in text:
            return f'''  {resource_name}Detector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true'''
        return f"# No CloudFormation template available for this control.\n# Resource: {resource_name}"
