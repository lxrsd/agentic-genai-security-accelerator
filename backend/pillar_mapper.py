"""Security Area Mapper — classifies findings into 5 security areas."""

from enum import Enum
from typing import Dict, List

from backend.models import NormalizedFinding


class SecurityArea(Enum):
    """The 5 security posture areas."""

    IDENTITY_ACCESS = "Identity & Access"
    DATA_PROTECTION = "Data Protection"
    NETWORK_SECURITY = "Network Security"
    VULNERABILITY_MANAGEMENT = "Vulnerability Management"
    INCIDENT_READINESS = "Incident Readiness"


SERVICE_AREA_MAP: Dict[str, SecurityArea] = {
    "iam": SecurityArea.IDENTITY_ACCESS,
    "organizations": SecurityArea.IDENTITY_ACCESS,
    "s3": SecurityArea.DATA_PROTECTION,
    "kms": SecurityArea.DATA_PROTECTION,
    "ec2": SecurityArea.NETWORK_SECURITY,
    "vpc": SecurityArea.NETWORK_SECURITY,
    "inspector": SecurityArea.VULNERABILITY_MANAGEMENT,
    "ssm": SecurityArea.VULNERABILITY_MANAGEMENT,
    "guardduty": SecurityArea.INCIDENT_READINESS,
    "securityhub": SecurityArea.INCIDENT_READINESS,
    "cloudtrail": SecurityArea.INCIDENT_READINESS,
    "cloudwatch": SecurityArea.INCIDENT_READINESS,
    "config": SecurityArea.INCIDENT_READINESS,
}


class SecurityAreaMapper:
    """Classifies normalized findings into one of 5 security areas."""

    def __init__(self) -> None:
        """Initialize mapping rules from services to security areas."""
        self._service_map = SERVICE_AREA_MAP.copy()

    def map_finding(self, finding: NormalizedFinding) -> SecurityArea:
        """Map a single normalized finding to its security area.

        Uses the finding's service field to determine the area.
        Unmapped services default to Incident Readiness.

        Args:
            finding: A normalized security finding.

        Returns:
            Exactly one SecurityArea value.
        """
        service = finding.service.lower()
        return self._service_map.get(service, SecurityArea.INCIDENT_READINESS)

    def map_batch(
        self, findings: List[NormalizedFinding]
    ) -> Dict[SecurityArea, List[NormalizedFinding]]:
        """Group all findings by their mapped security area.

        Initializes all 5 areas with empty lists, then populates them.
        Every finding is assigned to exactly one area.

        Args:
            findings: List of normalized security findings.

        Returns:
            Dictionary mapping each SecurityArea to its list of findings.
        """
        result: Dict[SecurityArea, List[NormalizedFinding]] = {
            area: [] for area in SecurityArea
        }

        for finding in findings:
            area = self.map_finding(finding)
            result[area].append(finding)

        return result


# Backward-compatible aliases
SecurityPillar = SecurityArea
PillarMapper = SecurityAreaMapper
