"""Data models for the Agentic GenAI Security Accelerator."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Security finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(Enum):
    """Security finding pass/fail status."""

    PASS = "PASS"
    FAIL = "FAIL"


@dataclass
class NormalizedFinding:
    """A normalized security finding with consistent field naming."""

    finding_id: str
    check_id: str
    check_title: str
    severity: Severity
    status: FindingStatus
    resource_arn: str
    resource_type: str
    region: str
    service: str
    description: str
    remediation_text: Optional[str] = None
    remediation_url: Optional[str] = None
