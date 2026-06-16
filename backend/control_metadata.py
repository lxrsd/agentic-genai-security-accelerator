"""Control Metadata — dataclass for AWS best-practice control information."""

from dataclasses import dataclass


@dataclass
class ControlMetadata:
    """Metadata for a single AWS best-practice security control.

    Each control maps a Prowler finding pattern to its AWS best-practice context,
    including risk information, remediation summary, and scoring weights.

    Attributes:
        control_id: Unique identifier for the control (e.g., "IAM-001").
        aws_service: The AWS service this control relates to (e.g., "iam", "s3").
        security_area: One of the 5 security areas this control maps to.
        best_practice_title: Short title of the AWS best practice.
        best_practice_summary: Description of what this best practice entails.
        risk_if_failed: What happens if this control is not satisfied.
        remediation_summary: High-level steps to remediate.
        impact_weight: Criticality weight (1.0-5.0) based on AWS best-practice importance.
        severity_weight: Weight derived from Prowler severity mapping.
        mcp_source_status: Whether metadata is from MCP enrichment or local fallback.
    """

    control_id: str
    aws_service: str
    security_area: str
    best_practice_title: str
    best_practice_summary: str
    risk_if_failed: str
    remediation_summary: str
    impact_weight: float  # 1.0-5.0 based on AWS best-practice criticality
    severity_weight: float  # From Prowler severity mapping
    mcp_source_status: str  # "mcp_enriched" or "local_fallback"
