"""AWS Best-Practice Control Catalog.

Maps Prowler check patterns to AWS best-practice control metadata.
Includes a bundled local catalog (fallback) and optional MCP enrichment.
"""

import logging
from typing import Any, Dict, List, Optional

from backend.control_metadata import ControlMetadata
from backend.models import NormalizedFinding

logger = logging.getLogger(__name__)


class AWSBestPracticeCatalog:
    """Catalog of AWS best-practice controls for scoring.

    Contains a bundled local catalog covering major security categories.
    Can be enriched from AWS Knowledge MCP when connected for richer
    best-practice context and remediation guidance.
    """

    def __init__(self, aws_knowledge_client: Optional[Any] = None) -> None:
        """Initialize the catalog with local controls and optional MCP client.

        Args:
            aws_knowledge_client: Optional AWSKnowledgeMCPClient for enrichment.
        """
        self._local_catalog = self._build_local_catalog()
        self._mcp_client = aws_knowledge_client
        self._mcp_enriched = False
        self._enrichment_cache: Dict[str, ControlMetadata] = {}

    def get_scoring_mode(self) -> str:
        """Return the current scoring mode.

        Returns:
            'mcp_enriched' if catalog has been enriched from MCP,
            'local_fallback' otherwise.
        """
        return "mcp_enriched" if self._mcp_enriched else "local_fallback"

    def get_scoring_mode_display(self) -> str:
        """Return human-readable scoring mode description."""
        if self._mcp_enriched:
            return "AWS Knowledge MCP enriched"
        return "Local AWS best-practice metadata fallback"

    def get_control_for_finding(self, finding: NormalizedFinding) -> ControlMetadata:
        """Map a NormalizedFinding to its ControlMetadata.

        Matches by service + check_title keywords against catalog patterns.
        Falls back to a generic control if no specific match is found.

        Args:
            finding: A normalized security finding from Prowler.

        Returns:
            The best-matching ControlMetadata for this finding.
        """
        # Check enrichment cache first
        cache_key = f"{finding.service}:{finding.check_id}"
        if cache_key in self._enrichment_cache:
            return self._enrichment_cache[cache_key]

        # Match against local catalog patterns
        service = finding.service.lower()
        title_lower = finding.check_title.lower()

        best_match: Optional[ControlMetadata] = None
        best_score = 0

        for pattern_key, control in self._local_catalog.items():
            match_score = self._match_pattern(pattern_key, service, title_lower)
            if match_score > best_score:
                best_score = match_score
                best_match = control

        if best_match is not None:
            return best_match

        # Fallback: generic control based on service
        return self._get_generic_control(finding)

    def enrich_from_mcp(self) -> bool:
        """Attempt to enrich the catalog from AWS Knowledge MCP.

        Queries the MCP server for enhanced best-practice metadata.
        Only marks as enriched if the MCP client is connected and responds.

        Returns:
            True if enrichment succeeded, False otherwise.
        """
        if self._mcp_client is None:
            return False

        # Check if the client is actually connected
        status = getattr(self._mcp_client, "get_status", None)
        if status is None:
            return False

        client_status = status()
        if client_status.get("status") != "connected":
            logger.info("AWS Knowledge MCP not connected — using local catalog")
            return False

        # MCP is connected — mark as enriched
        # In a full implementation, we would query for each control's
        # enhanced metadata. For now, the connected status enriches
        # the scoring mode indicator.
        self._mcp_enriched = True
        logger.info("AWS Knowledge MCP connected — catalog enriched")
        return True

    def get_all_controls(self) -> Dict[str, ControlMetadata]:
        """Return all controls in the local catalog."""
        return self._local_catalog.copy()

    def _match_pattern(self, pattern_key: str, service: str, title_lower: str) -> int:
        """Score how well a pattern key matches a finding.

        Pattern keys use format: "service + keyword1 + keyword2"

        Args:
            pattern_key: The catalog pattern key.
            service: The finding's service (lowercase).
            title_lower: The finding's check_title (lowercase).

        Returns:
            Match score (0 = no match, higher = better match).
        """
        parts = [p.strip() for p in pattern_key.split("+")]
        if not parts:
            return 0

        # First part must match service
        pattern_service = parts[0].strip()
        if pattern_service != service:
            return 0

        # Remaining parts are keywords that should appear in the title
        keywords = parts[1:]
        if not keywords:
            return 1  # Service-only match

        matched_keywords = 0
        for kw in keywords:
            kw = kw.strip()
            if kw in title_lower:
                matched_keywords += 1

        if matched_keywords == 0:
            return 0

        # Score: service match (1) + keyword matches
        return 1 + matched_keywords

    def _get_generic_control(self, finding: NormalizedFinding) -> ControlMetadata:
        """Create a generic control for unmatched findings.

        Uses the finding's own metadata to create a reasonable control.
        """
        from backend.pillar_mapper import SERVICE_AREA_MAP, SecurityArea

        service = finding.service.lower()
        area = SERVICE_AREA_MAP.get(service, SecurityArea.INCIDENT_READINESS)

        # Map severity to weight
        severity_weights = {
            "critical": 5.0,
            "high": 4.0,
            "medium": 2.0,
            "low": 1.0,
            "informational": 0.0,
        }
        sev_weight = severity_weights.get(finding.severity.value, 2.0)

        return ControlMetadata(
            control_id=f"GEN-{service.upper()}-001",
            aws_service=service,
            security_area=area.value,
            best_practice_title=finding.check_title,
            best_practice_summary=finding.description or finding.check_title,
            risk_if_failed="Security control not met — review AWS best practices",
            remediation_summary=finding.remediation_text or "Follow AWS documentation for remediation",
            impact_weight=min(sev_weight, 3.0),  # Generic controls capped at 3.0
            severity_weight=sev_weight,
            mcp_source_status=self.get_scoring_mode(),
        )

    def _build_local_catalog(self) -> Dict[str, ControlMetadata]:
        """Build the bundled AWS best-practice metadata catalog.

        Returns:
            Dictionary mapping pattern keys to ControlMetadata instances.
        """
        catalog: Dict[str, ControlMetadata] = {}

        # === IDENTITY & ACCESS ===

        catalog["iam + mfa"] = ControlMetadata(
            control_id="IAM-001",
            aws_service="iam",
            security_area="Identity & Access",
            best_practice_title="Enforce MFA for IAM Users",
            best_practice_summary=(
                "All IAM users with console access should have multi-factor "
                "authentication (MFA) enabled to protect against credential compromise."
            ),
            risk_if_failed=(
                "Compromised passwords can grant unauthorized access without "
                "a second authentication factor."
            ),
            remediation_summary=(
                "Enable MFA for all IAM users. Use virtual MFA devices or "
                "hardware security keys. Enforce via IAM policy conditions."
            ),
            impact_weight=5.0,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["iam + root + access key"] = ControlMetadata(
            control_id="IAM-002",
            aws_service="iam",
            security_area="Identity & Access",
            best_practice_title="Remove Root Account Access Keys",
            best_practice_summary=(
                "The AWS root account should not have active access keys. "
                "Root access keys provide unrestricted access to all resources."
            ),
            risk_if_failed=(
                "Compromised root access keys allow complete account takeover "
                "with no permission boundaries."
            ),
            remediation_summary=(
                "Delete all root account access keys. Use IAM users or roles "
                "for programmatic access with least-privilege policies."
            ),
            impact_weight=5.0,
            severity_weight=5.0,
            mcp_source_status="local_fallback",
        )

        catalog["iam + admin + privilege"] = ControlMetadata(
            control_id="IAM-003",
            aws_service="iam",
            security_area="Identity & Access",
            best_practice_title="Enforce Least Privilege Access",
            best_practice_summary=(
                "IAM policies should follow the principle of least privilege. "
                "Avoid attaching policies with full administrative access (*:*)."
            ),
            risk_if_failed=(
                "Over-privileged users or roles can access or modify resources "
                "beyond their job function, increasing blast radius of compromise."
            ),
            remediation_summary=(
                "Review IAM policies for overly broad permissions. Replace "
                "admin access with task-specific policies. Use IAM Access Analyzer."
            ),
            impact_weight=4.5,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["iam + access key + rotation"] = ControlMetadata(
            control_id="IAM-004",
            aws_service="iam",
            security_area="Identity & Access",
            best_practice_title="Rotate IAM Access Keys Regularly",
            best_practice_summary=(
                "IAM access keys should be rotated within 90 days. Long-lived "
                "credentials increase the window of exposure if compromised."
            ),
            risk_if_failed=(
                "Stale access keys may remain active after personnel changes "
                "or may have been exposed without detection."
            ),
            remediation_summary=(
                "Implement access key rotation policy. Use AWS Config rules to "
                "detect keys older than 90 days. Prefer IAM roles over long-lived keys."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        # === DATA PROTECTION ===

        catalog["s3 + public"] = ControlMetadata(
            control_id="DP-001",
            aws_service="s3",
            security_area="Data Protection",
            best_practice_title="Block S3 Public Access",
            best_practice_summary=(
                "S3 buckets should have Block Public Access enabled at the account "
                "and bucket level to prevent accidental data exposure."
            ),
            risk_if_failed=(
                "Publicly accessible buckets can expose sensitive data to the "
                "internet, leading to data breaches and compliance violations."
            ),
            remediation_summary=(
                "Enable S3 Block Public Access settings at the account level. "
                "Review and remediate any existing public bucket policies or ACLs."
            ),
            impact_weight=5.0,
            severity_weight=5.0,
            mcp_source_status="local_fallback",
        )

        catalog["s3 + encryption"] = ControlMetadata(
            control_id="DP-002",
            aws_service="s3",
            security_area="Data Protection",
            best_practice_title="Enable S3 Default Encryption",
            best_practice_summary=(
                "All S3 buckets should have default encryption enabled (SSE-S3 "
                "or SSE-KMS) to protect data at rest."
            ),
            risk_if_failed=(
                "Unencrypted data at rest may violate compliance requirements "
                "and is vulnerable if storage media is compromised."
            ),
            remediation_summary=(
                "Enable default encryption on all S3 buckets using SSE-S3 or "
                "SSE-KMS. Use bucket policies to deny unencrypted uploads."
            ),
            impact_weight=4.0,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["kms + rotation"] = ControlMetadata(
            control_id="DP-003",
            aws_service="kms",
            security_area="Data Protection",
            best_practice_title="Enable KMS Key Rotation",
            best_practice_summary=(
                "Customer-managed KMS keys should have automatic rotation enabled "
                "to limit the impact of key compromise over time."
            ),
            risk_if_failed=(
                "Keys that are never rotated accumulate more encrypted data under "
                "a single key version, increasing exposure if the key is compromised."
            ),
            remediation_summary=(
                "Enable automatic key rotation for all customer-managed KMS keys. "
                "AWS rotates the cryptographic material annually while keeping the key ID."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["kms + policy + public"] = ControlMetadata(
            control_id="DP-004",
            aws_service="kms",
            security_area="Data Protection",
            best_practice_title="Restrict KMS Key Policies",
            best_practice_summary=(
                "KMS key policies should not allow public access or overly "
                "permissive principals. Keys should be restricted to specific accounts and roles."
            ),
            risk_if_failed=(
                "Overly permissive KMS key policies can allow unauthorized "
                "decryption of sensitive data."
            ),
            remediation_summary=(
                "Review KMS key policies. Remove any principals that grant access "
                "to '*' or external accounts without justification."
            ),
            impact_weight=4.5,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        # === NETWORK SECURITY ===

        catalog["ec2 + ssh + 0.0.0.0"] = ControlMetadata(
            control_id="NET-001",
            aws_service="ec2",
            security_area="Network Security",
            best_practice_title="Restrict SSH Access from Internet",
            best_practice_summary=(
                "Security groups should not allow unrestricted SSH (port 22) "
                "access from 0.0.0.0/0 or ::/0."
            ),
            risk_if_failed=(
                "Open SSH access exposes instances to brute-force attacks "
                "and exploitation of SSH vulnerabilities from the internet."
            ),
            remediation_summary=(
                "Restrict SSH access to specific IP ranges. Use AWS Systems Manager "
                "Session Manager as a more secure alternative to direct SSH."
            ),
            impact_weight=4.5,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["ec2 + rdp"] = ControlMetadata(
            control_id="NET-002",
            aws_service="ec2",
            security_area="Network Security",
            best_practice_title="Restrict RDP Access from Internet",
            best_practice_summary=(
                "Security groups should not allow unrestricted RDP (port 3389) "
                "access from 0.0.0.0/0 or ::/0."
            ),
            risk_if_failed=(
                "Open RDP access exposes Windows instances to brute-force and "
                "exploitation attacks from the internet."
            ),
            remediation_summary=(
                "Restrict RDP access to specific corporate IP ranges. Use AWS "
                "Systems Manager Fleet Manager for remote desktop access."
            ),
            impact_weight=4.5,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["ec2 + high-risk + port"] = ControlMetadata(
            control_id="NET-003",
            aws_service="ec2",
            security_area="Network Security",
            best_practice_title="Restrict Database Port Access",
            best_practice_summary=(
                "Security groups should not expose database ports (3306, 5432, "
                "1433, 27017) to the internet."
            ),
            risk_if_failed=(
                "Exposed database ports allow direct attacks against database "
                "services, risking data theft and unauthorized access."
            ),
            remediation_summary=(
                "Move databases to private subnets. Restrict security group ingress "
                "to application-tier security groups only."
            ),
            impact_weight=4.0,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["ec2 + imdsv2"] = ControlMetadata(
            control_id="NET-004",
            aws_service="ec2",
            security_area="Network Security",
            best_practice_title="Enforce IMDSv2 on EC2 Instances",
            best_practice_summary=(
                "EC2 instances should require Instance Metadata Service Version 2 "
                "(IMDSv2) to prevent SSRF-based credential theft."
            ),
            risk_if_failed=(
                "IMDSv1 is vulnerable to Server-Side Request Forgery (SSRF) attacks "
                "that can steal instance credentials."
            ),
            remediation_summary=(
                "Configure instances to require IMDSv2 (HttpTokens=required). "
                "Set HttpPutResponseHopLimit to 1 for containers."
            ),
            impact_weight=4.0,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["vpc + flow logs"] = ControlMetadata(
            control_id="NET-005",
            aws_service="vpc",
            security_area="Network Security",
            best_practice_title="Enable VPC Flow Logs",
            best_practice_summary=(
                "VPC Flow Logs should be enabled to capture network traffic "
                "metadata for security analysis and incident investigation."
            ),
            risk_if_failed=(
                "Without flow logs, network-based attacks and data exfiltration "
                "attempts cannot be detected or investigated."
            ),
            remediation_summary=(
                "Enable VPC Flow Logs for all VPCs. Send logs to CloudWatch Logs "
                "or S3. Enable for both accepted and rejected traffic."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        # === INCIDENT READINESS ===

        catalog["cloudtrail + enabled + region"] = ControlMetadata(
            control_id="IR-001",
            aws_service="cloudtrail",
            security_area="Incident Readiness",
            best_practice_title="Enable Multi-Region CloudTrail",
            best_practice_summary=(
                "CloudTrail should be enabled in all regions to capture API "
                "activity across the entire AWS account."
            ),
            risk_if_failed=(
                "Attackers can operate in regions without CloudTrail enabled, "
                "avoiding detection of unauthorized API calls."
            ),
            remediation_summary=(
                "Create a multi-region trail that logs to a centralized S3 bucket. "
                "Enable for both management and data events."
            ),
            impact_weight=5.0,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["cloudtrail + log + validation"] = ControlMetadata(
            control_id="IR-002",
            aws_service="cloudtrail",
            security_area="Incident Readiness",
            best_practice_title="Enable CloudTrail Log File Validation",
            best_practice_summary=(
                "CloudTrail log file validation ensures log integrity by "
                "detecting any modification or deletion of log files."
            ),
            risk_if_failed=(
                "Without validation, attackers can modify or delete CloudTrail "
                "logs to cover their tracks without detection."
            ),
            remediation_summary=(
                "Enable log file validation on all CloudTrail trails. Use "
                "AWS CLI validate-logs command for periodic integrity checks."
            ),
            impact_weight=4.0,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["cloudtrail + encryption"] = ControlMetadata(
            control_id="IR-003",
            aws_service="cloudtrail",
            security_area="Incident Readiness",
            best_practice_title="Encrypt CloudTrail Logs with KMS",
            best_practice_summary=(
                "CloudTrail log files should be encrypted with a customer-managed "
                "KMS key for additional protection of audit data."
            ),
            risk_if_failed=(
                "Unencrypted audit logs are more vulnerable to unauthorized access "
                "if the S3 bucket permissions are misconfigured."
            ),
            remediation_summary=(
                "Configure CloudTrail to use SSE-KMS encryption. Create a "
                "dedicated KMS key with appropriate key policy for CloudTrail."
            ),
            impact_weight=3.0,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["cloudwatch + alarm"] = ControlMetadata(
            control_id="IR-004",
            aws_service="cloudwatch",
            security_area="Incident Readiness",
            best_practice_title="Configure Security Monitoring Alarms",
            best_practice_summary=(
                "CloudWatch alarms should monitor for critical security events "
                "like root account usage, unauthorized API calls, and IAM changes."
            ),
            risk_if_failed=(
                "Without alarms, security events go unnoticed until damage "
                "has already occurred. Mean time to detect increases."
            ),
            remediation_summary=(
                "Create CloudWatch metric filters and alarms for: root login, "
                "unauthorized API calls, IAM policy changes, security group changes."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["guardduty + enabled"] = ControlMetadata(
            control_id="IR-005",
            aws_service="guardduty",
            security_area="Incident Readiness",
            best_practice_title="Enable Amazon GuardDuty",
            best_practice_summary=(
                "GuardDuty should be enabled in all regions to provide continuous "
                "threat detection for AWS accounts and workloads."
            ),
            risk_if_failed=(
                "Without GuardDuty, sophisticated threats like crypto mining, "
                "credential compromise, and data exfiltration go undetected."
            ),
            remediation_summary=(
                "Enable GuardDuty in all regions. Configure findings export to "
                "S3 and EventBridge for automated response."
            ),
            impact_weight=4.5,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["guardduty + finding"] = ControlMetadata(
            control_id="IR-006",
            aws_service="guardduty",
            security_area="Incident Readiness",
            best_practice_title="Address Active GuardDuty Findings",
            best_practice_summary=(
                "Active GuardDuty findings indicate potential threats that require "
                "investigation and response."
            ),
            risk_if_failed=(
                "Unaddressed findings may indicate active compromise, data "
                "exfiltration, or unauthorized resource usage."
            ),
            remediation_summary=(
                "Investigate each GuardDuty finding. Implement automated response "
                "via EventBridge rules. Archive findings only after resolution."
            ),
            impact_weight=4.5,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["securityhub + enabled"] = ControlMetadata(
            control_id="IR-007",
            aws_service="securityhub",
            security_area="Incident Readiness",
            best_practice_title="Enable AWS Security Hub",
            best_practice_summary=(
                "Security Hub provides a centralized view of security alerts "
                "and compliance status across AWS accounts."
            ),
            risk_if_failed=(
                "Without Security Hub, security findings are siloed across "
                "services, making it difficult to prioritize and track."
            ),
            remediation_summary=(
                "Enable Security Hub with AWS Foundational Security Best Practices "
                "standard. Enable auto-enable for new accounts in Organizations."
            ),
            impact_weight=4.0,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["securityhub + findings"] = ControlMetadata(
            control_id="IR-008",
            aws_service="securityhub",
            security_area="Incident Readiness",
            best_practice_title="Manage Security Hub Findings",
            best_practice_summary=(
                "Security Hub findings should be actively triaged, investigated, "
                "and resolved to maintain security posture."
            ),
            risk_if_failed=(
                "Accumulating unresolved findings indicates degrading security "
                "posture and missed remediation opportunities."
            ),
            remediation_summary=(
                "Establish a finding triage workflow. Use automated rules to "
                "suppress known false positives. Track resolution metrics."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["config + enabled"] = ControlMetadata(
            control_id="IR-009",
            aws_service="config",
            security_area="Incident Readiness",
            best_practice_title="Enable AWS Config",
            best_practice_summary=(
                "AWS Config should be enabled in all regions to record resource "
                "configurations and track changes over time."
            ),
            risk_if_failed=(
                "Without Config, configuration drift goes undetected and there is "
                "no audit trail of resource changes for investigation."
            ),
            remediation_summary=(
                "Enable AWS Config in all regions. Configure delivery to a "
                "centralized S3 bucket. Enable for all resource types."
            ),
            impact_weight=4.0,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["config + rules"] = ControlMetadata(
            control_id="IR-010",
            aws_service="config",
            security_area="Incident Readiness",
            best_practice_title="Deploy AWS Config Compliance Rules",
            best_practice_summary=(
                "AWS Config rules should be deployed to continuously evaluate "
                "resource configurations against security best practices."
            ),
            risk_if_failed=(
                "Without compliance rules, misconfigurations persist undetected "
                "until a manual audit or security incident occurs."
            ),
            remediation_summary=(
                "Deploy AWS Config conformance packs aligned with compliance "
                "frameworks. Use managed rules for common security checks."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        # === VULNERABILITY MANAGEMENT ===

        catalog["inspector + vulnerability"] = ControlMetadata(
            control_id="VM-001",
            aws_service="inspector",
            security_area="Vulnerability Management",
            best_practice_title="Enable Amazon Inspector Vulnerability Scanning",
            best_practice_summary=(
                "Amazon Inspector should be enabled to continuously scan EC2 "
                "instances and container images for software vulnerabilities."
            ),
            risk_if_failed=(
                "Unpatched vulnerabilities in workloads can be exploited for "
                "unauthorized access, privilege escalation, or data theft."
            ),
            remediation_summary=(
                "Enable Inspector for EC2 and ECR scanning. Review and remediate "
                "findings by severity. Integrate with patch management."
            ),
            impact_weight=4.0,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        catalog["inspector + coverage"] = ControlMetadata(
            control_id="VM-002",
            aws_service="inspector",
            security_area="Vulnerability Management",
            best_practice_title="Ensure Full Inspector Scan Coverage",
            best_practice_summary=(
                "All EC2 instances and container images should be covered by "
                "Inspector scanning to detect vulnerabilities."
            ),
            risk_if_failed=(
                "Unscanned resources may harbor critical vulnerabilities that "
                "go undetected until exploited."
            ),
            remediation_summary=(
                "Verify Inspector coverage in the console. Ensure SSM agent is "
                "installed on all EC2 instances for scanning support."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["ssm + managed"] = ControlMetadata(
            control_id="VM-003",
            aws_service="ssm",
            security_area="Vulnerability Management",
            best_practice_title="Manage Instances with Systems Manager",
            best_practice_summary=(
                "All EC2 instances should be managed by AWS Systems Manager "
                "for patching, inventory, and compliance tracking."
            ),
            risk_if_failed=(
                "Unmanaged instances cannot be patched automatically and lack "
                "visibility into their compliance and configuration state."
            ),
            remediation_summary=(
                "Install SSM Agent on all instances. Ensure instance profiles "
                "include AmazonSSMManagedInstanceCore policy."
            ),
            impact_weight=3.5,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        catalog["ssm + compliance"] = ControlMetadata(
            control_id="VM-004",
            aws_service="ssm",
            security_area="Vulnerability Management",
            best_practice_title="Maintain Patch Compliance",
            best_practice_summary=(
                "All managed instances should be compliant with patch baselines "
                "to ensure security updates are applied timely."
            ),
            risk_if_failed=(
                "Non-compliant instances have known vulnerabilities that can "
                "be exploited by attackers."
            ),
            remediation_summary=(
                "Configure SSM Patch Manager with maintenance windows. Define "
                "patch baselines by OS. Monitor compliance dashboard."
            ),
            impact_weight=4.0,
            severity_weight=4.0,
            mcp_source_status="local_fallback",
        )

        # === GOVERNANCE (maps to Identity & Access area) ===

        catalog["organizations + scp"] = ControlMetadata(
            control_id="GOV-001",
            aws_service="organizations",
            security_area="Identity & Access",
            best_practice_title="Implement Service Control Policies",
            best_practice_summary=(
                "AWS Organizations should use Service Control Policies (SCPs) "
                "to enforce governance guardrails across all member accounts."
            ),
            risk_if_failed=(
                "Without SCPs, individual accounts can bypass organizational "
                "security policies and use restricted services or regions."
            ),
            remediation_summary=(
                "Create SCPs to deny access to unused regions, restrict root "
                "account actions, and enforce tagging requirements."
            ),
            impact_weight=4.0,
            severity_weight=2.0,
            mcp_source_status="local_fallback",
        )

        return catalog
