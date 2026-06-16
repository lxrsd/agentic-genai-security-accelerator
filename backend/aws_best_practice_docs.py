"""AWS Best Practice Documentation Mapping.

Maps security control categories, check IDs, and services to official
AWS documentation URLs. Only verified official AWS URLs are included.
Never generates or invents URLs.
"""

from typing import List, NamedTuple, Optional


class DocLink(NamedTuple):
    """A link to official AWS documentation."""
    title: str
    url: str
    reason: str
    category: str


# ---------------------------------------------------------------------------
# Documentation Registry
# Keyed by check_id patterns, specific check_ids, and service+keyword combos.
# Only https://docs.aws.amazon.com/ and https://aws.amazon.com/ URLs allowed.
# ---------------------------------------------------------------------------

# Specific check_id → doc links mapping
_CHECK_ID_DOCS: dict[str, list[DocLink]] = {
    # IAM
    "iam_root_mfa_enabled": [
        DocLink("Enable MFA for the root user", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa", "Root account requires MFA for security", "IAM"),
        DocLink("AWS security best practices in IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html", "IAM security best practices overview", "IAM"),
    ],
    "iam_root_hardware_mfa_enabled": [
        DocLink("Enable hardware MFA for root", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html", "Hardware MFA provides strongest protection", "IAM"),
    ],
    "iam_user_mfa_enabled_console_access": [
        DocLink("Enable MFA for IAM users", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html", "Console users should have MFA enabled", "IAM"),
        DocLink("AWS security best practices in IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html", "IAM security best practices overview", "IAM"),
    ],
    "iam_root_credentials_management_enabled": [
        DocLink("Safeguard root user credentials", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials", "Root credentials should not be used for daily tasks", "IAM"),
    ],
    # S3
    "s3_bucket_public_access": [
        DocLink("Block public access to S3 buckets", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "Prevent unintended public exposure of S3 data", "S3"),
        DocLink("S3 security best practices", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html", "Comprehensive S3 security guidance", "S3"),
    ],
    "s3_bucket_public_write_acl": [
        DocLink("Block public access to S3 buckets", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "Public write ACLs allow unauthorized data modification", "S3"),
        DocLink("S3 bucket policies", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html", "Review bucket policies for public grants", "S3"),
    ],
    "s3_bucket_public_list_acl": [
        DocLink("Block public access to S3 buckets", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "Public list ACLs expose bucket contents", "S3"),
    ],
    "s3_bucket_default_encryption": [
        DocLink("S3 default encryption", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html", "Enable default encryption for data at rest protection", "S3"),
        DocLink("S3 security best practices", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html", "Comprehensive S3 security guidance", "S3"),
    ],
    # EC2 / Network Security
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports": [
        DocLink("Security group rules reference", "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html", "Restrict inbound rules to specific ports and sources", "Network"),
        DocLink("Restrict access to EC2 instances", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html", "Security groups control instance-level traffic", "Network"),
        DocLink("AWS Well-Architected: Infrastructure protection", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/infrastructure-protection.html", "Well-Architected guidance on network security", "Network"),
    ],
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": [
        DocLink("Restrict SSH access to instances", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html", "SSH should be restricted to trusted IPs or VPN only", "Network"),
        DocLink("Connect using Session Manager", "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html", "Use Session Manager instead of opening SSH to the internet", "Network"),
        DocLink("Security group rules reference", "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html", "Restrict inbound rules to specific sources", "Network"),
        DocLink("AWS Well-Architected: Infrastructure protection", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/infrastructure-protection.html", "Well-Architected guidance on access control", "Network"),
    ],
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": [
        DocLink("Restrict RDP access to instances", "https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/ec2-security-groups.html", "RDP should be restricted to trusted IPs or VPN only", "Network"),
        DocLink("Security group rules reference", "https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html", "Restrict inbound rules to specific sources", "Network"),
        DocLink("Connect using Session Manager", "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html", "Use Session Manager instead of opening RDP to the internet", "Network"),
    ],
    # CloudTrail / Incident Readiness
    "cloudtrail_multi_region_enabled": [
        DocLink("CloudTrail best practices", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html", "Multi-region trails capture activity across all regions", "CloudTrail"),
        DocLink("Creating a trail", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html", "Enable CloudTrail for audit and investigation", "CloudTrail"),
    ],
    "cloudtrail_s3_bucket_mfa_delete": [
        DocLink("CloudTrail S3 bucket security", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html", "Protect CloudTrail logs from deletion", "CloudTrail"),
        DocLink("S3 MFA delete", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html", "MFA delete prevents unauthorized log removal", "CloudTrail"),
    ],
    "cloudtrail_log_file_validation_enabled": [
        DocLink("CloudTrail log file integrity validation", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html", "Validate that log files have not been tampered with", "CloudTrail"),
    ],
    # GuardDuty
    "guardduty_is_enabled": [
        DocLink("Getting started with GuardDuty", "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html", "Enable GuardDuty for threat detection", "GuardDuty"),
        DocLink("GuardDuty best practices", "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_best-practices.html", "Best practices for GuardDuty deployment", "GuardDuty"),
    ],
    # Security Hub
    "securityhub_enabled": [
        DocLink("Setting up Security Hub", "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-settingup.html", "Enable Security Hub for consolidated findings", "SecurityHub"),
        DocLink("Security Hub best practices", "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html", "Enable security standards for continuous compliance", "SecurityHub"),
    ],
    # KMS
    "kms_key_rotation_enabled": [
        DocLink("KMS key rotation", "https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html", "Automatic key rotation reduces exposure from compromised keys", "KMS"),
        DocLink("KMS best practices", "https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html", "KMS security best practices", "KMS"),
    ],
}

# Service prefix fallback → doc links (used when exact check_id not found)
_SERVICE_PREFIX_DOCS: dict[str, list[DocLink]] = {
    "iam": [
        DocLink("AWS security best practices in IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html", "General IAM security guidance", "IAM"),
    ],
    "s3": [
        DocLink("S3 security best practices", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html", "General S3 security guidance", "S3"),
    ],
    "ec2": [
        DocLink("EC2 security groups", "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html", "General EC2 network security guidance", "Network"),
    ],
    "vpc": [
        DocLink("VPC security best practices", "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html", "General VPC security guidance", "Network"),
    ],
    "cloudtrail": [
        DocLink("CloudTrail best practices", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html", "General CloudTrail security guidance", "CloudTrail"),
    ],
    "guardduty": [
        DocLink("GuardDuty best practices", "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_best-practices.html", "General GuardDuty guidance", "GuardDuty"),
    ],
    "securityhub": [
        DocLink("Security Hub standards", "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html", "General Security Hub guidance", "SecurityHub"),
    ],
    "kms": [
        DocLink("KMS best practices", "https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html", "General KMS security guidance", "KMS"),
    ],
    "inspector": [
        DocLink("Inspector getting started", "https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html", "General Inspector guidance", "Inspector"),
    ],
    "config": [
        DocLink("AWS Config best practices", "https://docs.aws.amazon.com/config/latest/developerguide/security-best-practices.html", "General AWS Config guidance", "Config"),
    ],
    "ssm": [
        DocLink("Systems Manager Session Manager", "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html", "Use Session Manager for secure instance access", "SSM"),
    ],
}

# Pillar-level fallback docs
_PILLAR_DOCS: dict[str, list[DocLink]] = {
    "Identity & Access": [
        DocLink("AWS security best practices in IAM", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html", "Identity and access management best practices", "IAM"),
        DocLink("AWS Well-Architected: Identity and access management", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/identity-and-access-management.html", "Well-Architected identity guidance", "IAM"),
    ],
    "Data Protection": [
        DocLink("S3 security best practices", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html", "Data protection for S3 storage", "S3"),
        DocLink("AWS Well-Architected: Data protection", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/data-protection.html", "Well-Architected data protection guidance", "DataProtection"),
    ],
    "Network Security": [
        DocLink("VPC security best practices", "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html", "Network security configuration", "Network"),
        DocLink("AWS Well-Architected: Infrastructure protection", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/infrastructure-protection.html", "Well-Architected infrastructure guidance", "Network"),
    ],
    "Vulnerability Management": [
        DocLink("Inspector getting started", "https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html", "Vulnerability scanning with Inspector", "Inspector"),
        DocLink("AWS Well-Architected: Security", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html", "Well-Architected security overview", "Security"),
    ],
    "Incident Readiness": [
        DocLink("CloudTrail best practices", "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html", "Audit trail for incident investigation", "CloudTrail"),
        DocLink("AWS Well-Architected: Incident response", "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/incident-response.html", "Well-Architected incident response guidance", "IncidentResponse"),
    ],
}


def get_docs_for_finding(
    check_id: str,
    service: str = "",
    pillar: str = "",
) -> List[DocLink]:
    """Get official AWS documentation links for a finding.

    Lookup order:
    1. Exact check_id match
    2. Service prefix match (e.g., "iam" from "iam_root_mfa_enabled")
    3. Pillar fallback
    4. Empty list (no mapping found)

    Args:
        check_id: The Prowler check ID (e.g., "s3_bucket_public_access")
        service: AWS service name (e.g., "s3", "iam", "ec2")
        pillar: Security area name (e.g., "Data Protection")

    Returns:
        List of DocLink namedtuples. Empty list if no mapping exists.
        Never returns invented URLs.
    """
    # 1. Exact check_id match
    if check_id in _CHECK_ID_DOCS:
        return _CHECK_ID_DOCS[check_id]

    # 2. Service prefix match
    prefix = check_id.split("_")[0] if check_id else ""
    if prefix and prefix in _SERVICE_PREFIX_DOCS:
        return _SERVICE_PREFIX_DOCS[prefix]

    # 3. Service name fallback
    svc = service.lower().strip() if service else ""
    if svc and svc in _SERVICE_PREFIX_DOCS:
        return _SERVICE_PREFIX_DOCS[svc]

    # 4. Pillar fallback
    if pillar and pillar in _PILLAR_DOCS:
        return _PILLAR_DOCS[pillar]

    # 5. No mapping found
    return []


def get_pillar_docs(pillar: str) -> List[DocLink]:
    """Get pillar-level AWS documentation links.

    Args:
        pillar: Security area name (e.g., "Identity & Access")

    Returns:
        List of DocLink namedtuples for the pillar. Empty list if no mapping.
    """
    return _PILLAR_DOCS.get(pillar, [])
