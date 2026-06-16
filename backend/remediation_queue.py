"""Remediation Queue — Manages queued remediation actions.

Stores planned remediation actions with unique IDs, priority ordering,
and status tracking. Does NOT execute anything. This is the control-plane
for remediation workflow management.

MVP: In-memory queue (does not persist across restarts).
"""

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RemediationAction:
    """A queued remediation action awaiting approval."""

    action_id: str
    finding_id: str
    finding_title: str
    target_resource: str
    aws_service: str
    proposed_action: str  # AWS API action (e.g., "s3:PutPublicAccessBlock")
    risk_category: str  # "low" | "medium" | "high"
    blast_radius: str
    rollback_summary: str
    estimated_score_impact: float
    status: str  # "pending" | "awaiting_approval" | "approved" | "rejected" | "skipped"
    created_at: str  # ISO 8601 UTC
    session_id: str
    check_id: str = ""
    pillar: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Risk priority order (lower = higher priority in queue)
_RISK_PRIORITY = {"low": 0, "medium": 1, "high": 2}


class RemediationQueue:
    """In-memory remediation queue with priority ordering.

    Actions are sorted: low-risk first, medium-risk second, high-risk last.
    MVP: In-memory only. Does not persist across restarts.
    """

    def __init__(self):
        self._actions: Dict[str, RemediationAction] = {}
        self._session_id = str(uuid.uuid4())[:8]

    @property
    def session_id(self) -> str:
        return self._session_id

    def add(self, action_data: Dict[str, Any]) -> RemediationAction:
        """Add a planned remediation action to the queue.

        Args:
            action_data: Dict with finding_id, finding_title, target_resource,
                        aws_service, proposed_action, risk_category, blast_radius,
                        rollback_summary, estimated_score_impact, check_id, pillar.

        Returns:
            The created RemediationAction with unique action_id.
        """
        action_id = str(uuid.uuid4())[:12]
        action = RemediationAction(
            action_id=action_id,
            finding_id=action_data.get("finding_id", ""),
            finding_title=action_data.get("finding_title", ""),
            target_resource=action_data.get("target_resource", ""),
            aws_service=action_data.get("aws_service", ""),
            proposed_action=action_data.get("proposed_action", ""),
            risk_category=action_data.get("risk_category", "medium"),
            blast_radius=action_data.get("blast_radius", ""),
            rollback_summary=action_data.get("rollback_summary", ""),
            estimated_score_impact=action_data.get("estimated_score_impact", 0.0),
            status="pending",
            created_at=datetime.now(timezone.utc).isoformat(),
            session_id=self._session_id,
            check_id=action_data.get("check_id", ""),
            pillar=action_data.get("pillar", ""),
        )
        self._actions[action_id] = action
        logger.info("Queued remediation action %s: %s", action_id, action.finding_title)
        return action

    def get_all(self) -> List[RemediationAction]:
        """Get all queued actions sorted by risk priority (low first)."""
        actions = list(self._actions.values())
        actions.sort(key=lambda a: (_RISK_PRIORITY.get(a.risk_category, 9), a.created_at))
        return actions

    def get_pending(self) -> List[RemediationAction]:
        """Get actions that are pending or awaiting approval."""
        return [a for a in self.get_all() if a.status in ("pending", "awaiting_approval")]

    def get_action(self, action_id: str) -> Optional[RemediationAction]:
        """Get a specific action by ID."""
        return self._actions.get(action_id)

    def present_for_approval(self, action_id: str) -> Optional[RemediationAction]:
        """Mark an action as awaiting approval."""
        action = self._actions.get(action_id)
        if action and action.status == "pending":
            action.status = "awaiting_approval"
            return action
        return action

    def approve(self, action_id: str) -> Optional[RemediationAction]:
        """Approve a specific action. Does NOT execute.

        Returns None if action doesn't exist or is not in approvable state.
        """
        action = self._actions.get(action_id)
        if not action:
            return None
        if action.status not in ("pending", "awaiting_approval"):
            return None  # Cannot approve already-approved/rejected/skipped
        action.status = "approved"
        logger.info("Approved remediation action %s", action_id)
        return action

    def reject(self, action_id: str) -> Optional[RemediationAction]:
        """Reject a specific action."""
        action = self._actions.get(action_id)
        if not action:
            return None
        if action.status not in ("pending", "awaiting_approval"):
            return None
        action.status = "rejected"
        logger.info("Rejected remediation action %s", action_id)
        return action

    def skip(self, action_id: str) -> Optional[RemediationAction]:
        """Skip a specific action."""
        action = self._actions.get(action_id)
        if not action:
            return None
        if action.status not in ("pending", "awaiting_approval"):
            return None
        action.status = "skipped"
        return action

    def get_summary(self) -> Dict[str, Any]:
        """Get queue summary with counts by status."""
        all_actions = list(self._actions.values())
        return {
            "total": len(all_actions),
            "pending": len([a for a in all_actions if a.status == "pending"]),
            "awaiting_approval": len([a for a in all_actions if a.status == "awaiting_approval"]),
            "approved": len([a for a in all_actions if a.status == "approved"]),
            "rejected": len([a for a in all_actions if a.status == "rejected"]),
            "skipped": len([a for a in all_actions if a.status == "skipped"]),
        }


# Global queue instance
remediation_queue = RemediationQueue()
