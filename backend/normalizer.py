"""Normalizer - transforms raw Prowler findings into consistent internal schema."""

import logging
from typing import Any, Dict, List, Optional

from backend.models import FindingStatus, NormalizedFinding, Severity

logger = logging.getLogger(__name__)

# Case-insensitive mapping of severity strings to Severity enum
_SEVERITY_MAP: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}

# Mapping of StatusCode strings to FindingStatus enum
_STATUS_MAP: Dict[str, FindingStatus] = {
    "PASS": FindingStatus.PASS,
    "FAIL": FindingStatus.FAIL,
}


def _derive_check_id(finding_id: str) -> str:
    """Derive check_id by removing the trailing unique suffix.

    The check_id is the finding_id with the last dash-separated segment removed.
    For example: "prowler-iam-user-mfa-enabled-001" → "prowler-iam-user-mfa-enabled"
    """
    parts = finding_id.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return finding_id


class Normalizer:
    """Transforms raw Prowler findings into NormalizedFinding instances."""

    def normalize(self, raw_finding: Dict[str, Any]) -> NormalizedFinding:
        """Convert a raw Prowler finding dict into a NormalizedFinding.

        Args:
            raw_finding: A validated raw finding dictionary from the importer.

        Returns:
            A NormalizedFinding instance.

        Raises:
            KeyError: If a required field is missing.
            ValueError: If severity or status cannot be mapped.
        """
        # Detect format: OCSF (Prowler 5.x) vs legacy (Prowler 3.x)
        if "status_code" in raw_finding and "metadata" in raw_finding:
            return self._normalize_ocsf(raw_finding)
        
        # Legacy Prowler 3.x format
        # Extract FindingInfo fields
        finding_info = raw_finding["FindingInfo"]
        finding_id = finding_info["FindingId"]
        check_id = _derive_check_id(finding_id)
        check_title = finding_info["Title"]

        # Map severity (case-insensitive)
        raw_severity = raw_finding["Severity"].lower()
        severity = _SEVERITY_MAP.get(raw_severity)
        if severity is None:
            raise ValueError(
                f"Unknown severity value: {raw_finding['Severity']}"
            )

        # Map status
        raw_status = raw_finding["StatusCode"]
        status = _STATUS_MAP.get(raw_status)
        if status is None:
            raise ValueError(f"Unknown StatusCode value: {raw_status}")

        # Extract required top-level fields
        resource_arn = raw_finding["ResourceArn"]
        resource_type = raw_finding["ResourceType"]
        region = raw_finding["Region"]
        service = raw_finding["ServiceName"]
        description = raw_finding["Description"]

        # Extract optional remediation fields
        remediation_text = None
        remediation_url = None
        remediation = raw_finding.get("Remediation")
        if isinstance(remediation, dict):
            recommendation = remediation.get("Recommendation")
            if isinstance(recommendation, dict):
                remediation_text = recommendation.get("Text")
                remediation_url = recommendation.get("Url")

        return NormalizedFinding(
            finding_id=finding_id,
            check_id=check_id,
            check_title=check_title,
            severity=severity,
            status=status,
            resource_arn=resource_arn,
            resource_type=resource_type,
            region=region,
            service=service,
            description=description,
            remediation_text=remediation_text,
            remediation_url=remediation_url,
        )

    def normalize_batch(
        self, raw_findings: List[Dict[str, Any]]
    ) -> List[NormalizedFinding]:
        """Normalize a list of raw findings, skipping invalid ones.

        Invalid findings (those that raise KeyError or ValueError during
        normalization) are logged and skipped.

        Args:
            raw_findings: A list of raw finding dictionaries.

        Returns:
            A list of successfully normalized findings.
        """
        results: List[NormalizedFinding] = []

        for raw_finding in raw_findings:
            try:
                normalized = self.normalize(raw_finding)
                results.append(normalized)
            except (KeyError, ValueError, TypeError) as e:
                finding_id = self._extract_finding_id(raw_finding)
                logger.warning(
                    "Skipping invalid finding %s: %s",
                    finding_id or "<unknown>",
                    e,
                )

        return results

    def _normalize_ocsf(self, raw_finding: Dict[str, Any]) -> NormalizedFinding:
        """Normalize a Prowler 5.x OCSF format finding."""
        metadata = raw_finding.get("metadata", {})
        finding_info = raw_finding.get("finding_info", {})
        resources = raw_finding.get("resources", [{}])
        resource = resources[0] if resources else {}
        
        # Extract fields
        finding_id = finding_info.get("uid", "") or f"prowler-{metadata.get('event_code', 'unknown')}"
        check_id = metadata.get("event_code", "")
        check_title = finding_info.get("title", "") or raw_finding.get("message", "")
        
        # Severity mapping (OCSF uses severity string)
        raw_severity = raw_finding.get("severity", "medium").lower()
        severity = _SEVERITY_MAP.get(raw_severity, Severity.MEDIUM)
        
        # Status mapping
        raw_status = raw_finding.get("status_code", "FAIL")
        status = _STATUS_MAP.get(raw_status, FindingStatus.FAIL)
        
        # Resource info
        resource_arn = resource.get("uid", "") or ""
        resource_type = resource.get("type", "") or ""
        region = resource.get("region", "") or raw_finding.get("cloud", {}).get("region", "")
        
        # Service from check_id pattern or resource
        service = check_id.split("_")[0] if "_" in check_id else ""
        
        # Description
        description = raw_finding.get("status_detail", "") or raw_finding.get("message", "")
        
        # Remediation
        remediation_text = None
        remediation_url = None
        remediation = raw_finding.get("remediation", {})
        if isinstance(remediation, dict):
            remediation_text = remediation.get("desc", "") or remediation.get("recommendation", "")
            refs = remediation.get("references", [])
            if refs:
                remediation_url = refs[0] if isinstance(refs[0], str) else None
        # Also check unmapped.additional_urls
        unmapped = raw_finding.get("unmapped", {})
        if not remediation_url and unmapped:
            urls = unmapped.get("additional_urls", [])
            if urls:
                remediation_url = urls[0]
        
        return NormalizedFinding(
            finding_id=finding_id,
            check_id=check_id,
            check_title=check_title,
            severity=severity,
            status=status,
            resource_arn=resource_arn,
            resource_type=resource_type,
            region=region,
            service=service,
            description=description,
            remediation_text=remediation_text,
            remediation_url=remediation_url,
        )

    @staticmethod
    def _extract_finding_id(raw_finding: Dict[str, Any]) -> Optional[str]:
        """Try to extract FindingId for logging purposes."""
        if not isinstance(raw_finding, dict):
            return None
        # OCSF format
        finding_info = raw_finding.get("finding_info")
        if isinstance(finding_info, dict) and finding_info.get("uid"):
            return finding_info.get("uid")
        # Legacy format
        fi = raw_finding.get("FindingInfo")
        if isinstance(fi, dict):
            return fi.get("FindingId")
        return None
