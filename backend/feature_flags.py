"""Feature Flag System for the Controlled Remediation Agent.

Loads feature flags from environment variables with safe defaults.
Enforces dependency ordering between capability levels.
No flag enables AWS-mutating behavior unless explicitly set.
"""

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FeatureFlags:
    """Feature flags controlling agent capability levels.

    Dependency DAG:
      investigation_tools_enabled
        └── remediation_planning_enabled
              └── remediation_execution_enabled
                    ├── allow_medium_risk_remediation
                    │     └── allow_high_risk_remediation
                    └── dry_run_remediation (toggles live vs dry-run)
    """

    # Level 2-3: Investigation
    investigation_tools_enabled: bool = False

    # Level 4: Planning
    remediation_planning_enabled: bool = False

    # Level 5: Execution
    remediation_execution_enabled: bool = False
    allow_medium_risk_remediation: bool = False
    allow_high_risk_remediation: bool = False
    require_approval_for_all_remediation: bool = True
    dry_run_remediation: bool = True

    @classmethod
    def from_env(cls) -> "FeatureFlags":
        """Load feature flags from environment variables with safe defaults."""
        flags = cls(
            investigation_tools_enabled=_env_bool("INVESTIGATION_TOOLS_ENABLED", False),
            remediation_planning_enabled=_env_bool("REMEDIATION_PLANNING_ENABLED", False),
            remediation_execution_enabled=_env_bool("REMEDIATION_EXECUTION_ENABLED", False),
            allow_medium_risk_remediation=_env_bool("ALLOW_MEDIUM_RISK_REMEDIATION", False),
            allow_high_risk_remediation=_env_bool("ALLOW_HIGH_RISK_REMEDIATION", False),
            require_approval_for_all_remediation=_env_bool("REQUIRE_APPROVAL_FOR_ALL_REMEDIATION", True),
            dry_run_remediation=_env_bool("DRY_RUN_REMEDIATION", True),
        )
        flags.validate_dependencies()
        return flags

    def validate_dependencies(self) -> None:
        """Enforce dependency DAG. Disable dependent flags if prerequisites are missing."""
        # Planning requires investigation
        if self.remediation_planning_enabled and not self.investigation_tools_enabled:
            logger.warning(
                "REMEDIATION_PLANNING_ENABLED requires INVESTIGATION_TOOLS_ENABLED. "
                "Disabling planning."
            )
            self.remediation_planning_enabled = False

        # Execution requires planning
        if self.remediation_execution_enabled and not self.remediation_planning_enabled:
            logger.warning(
                "REMEDIATION_EXECUTION_ENABLED requires REMEDIATION_PLANNING_ENABLED. "
                "Disabling execution."
            )
            self.remediation_execution_enabled = False

        # High-risk requires medium-risk
        if self.allow_high_risk_remediation and not self.allow_medium_risk_remediation:
            logger.warning(
                "ALLOW_HIGH_RISK_REMEDIATION requires ALLOW_MEDIUM_RISK_REMEDIATION. "
                "Disabling high-risk."
            )
            self.allow_high_risk_remediation = False

        # Medium-risk requires execution
        if self.allow_medium_risk_remediation and not self.remediation_execution_enabled:
            logger.warning(
                "ALLOW_MEDIUM_RISK_REMEDIATION requires REMEDIATION_EXECUTION_ENABLED. "
                "Disabling medium-risk."
            )
            self.allow_medium_risk_remediation = False
            self.allow_high_risk_remediation = False

    def get_capability_mode(self) -> str:
        """Return the current capability mode string."""
        if not self.investigation_tools_enabled:
            return "Findings Only"
        if not self.remediation_planning_enabled:
            return "Investigation"
        if not self.remediation_execution_enabled:
            return "Planning"
        if self.dry_run_remediation:
            return "Dry-Run Execution"
        return "Live Execution"

    def get_remediation_mode(self) -> str:
        """Return the current remediation mode string."""
        if not self.remediation_execution_enabled:
            return "Planning Only"
        if self.dry_run_remediation:
            return "Dry-Run Execution"
        return "Live Execution"

    def get_guardrail_status(self) -> list[str]:
        """Return active guardrail labels."""
        guardrails = []
        if self.require_approval_for_all_remediation:
            guardrails.append("Approval Required")
        if not self.remediation_execution_enabled:
            guardrails.append("Execution Disabled")
        if self.dry_run_remediation:
            guardrails.append("Dry-Run Enabled")
        if not self.allow_medium_risk_remediation:
            guardrails.append("Medium-Risk Blocked")
        if not self.allow_high_risk_remediation:
            guardrails.append("High-Risk Blocked")
        return guardrails

    def to_dict(self) -> dict:
        """Return all flags as a dictionary."""
        return {
            "investigation_tools_enabled": self.investigation_tools_enabled,
            "remediation_planning_enabled": self.remediation_planning_enabled,
            "remediation_execution_enabled": self.remediation_execution_enabled,
            "allow_medium_risk_remediation": self.allow_medium_risk_remediation,
            "allow_high_risk_remediation": self.allow_high_risk_remediation,
            "require_approval_for_all_remediation": self.require_approval_for_all_remediation,
            "dry_run_remediation": self.dry_run_remediation,
        }


def _env_bool(key: str, default: bool) -> bool:
    """Read a boolean from an environment variable."""
    val = os.environ.get(key, "").lower().strip()
    if val in ("true", "1", "yes"):
        return True
    if val in ("false", "0", "no"):
        return False
    return default
