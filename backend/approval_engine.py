"""Approval Engine — Manages remediation approval lifecycle.

Controls the approve/reject workflow for queued remediation actions.
Does NOT execute anything. Approval only records intent.

Key safety rules:
- Approval can only happen through API endpoints, never through chat text
- An approved action cannot be approved again (idempotency)
- A rejected action cannot be approved later (must regenerate)
- Approval does not trigger execution in this phase
"""

import logging
from typing import Any, Dict, Optional

from backend.remediation_queue import remediation_queue, RemediationAction
from backend.audit_logger import audit_logger

logger = logging.getLogger(__name__)


class ApprovalEngine:
    """Manages the approval lifecycle for remediation actions.

    Approval is API-based only. Chat text never triggers approval.
    No execution occurs in Phase 4.
    """

    def __init__(self):
        self._queue = remediation_queue

    def get_approval_payload(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Get the data to display in the approval modal.

        Returns None if action doesn't exist.
        """
        action = self._queue.get_action(action_id)
        if not action:
            return None

        # Mark as awaiting approval
        self._queue.present_for_approval(action_id)

        # Log the presentation
        audit_logger.log_event(
            action_type="presented_for_approval",
            remediation_action_id=action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="awaiting_approval",
            session_id=action.session_id,
        )

        return {
            "action_id": action.action_id,
            "finding_id": action.finding_id,
            "finding_title": action.finding_title,
            "target_resource": action.target_resource,
            "aws_service": action.aws_service,
            "proposed_action": action.proposed_action,
            "risk_category": action.risk_category,
            "blast_radius": action.blast_radius,
            "rollback_summary": action.rollback_summary,
            "estimated_score_impact": action.estimated_score_impact,
            "status": action.status,
            "execution_mode": "Not Executed — Approval Only",
            "warning": "Approval records intent only in this phase. No AWS changes will be made.",
        }

    def approve(self, action_id: str) -> Dict[str, Any]:
        """Approve a remediation action via API.

        Does NOT execute. Only updates status.
        Returns error if action cannot be approved.
        """
        action = self._queue.get_action(action_id)
        if not action:
            return {"status": "error", "message": f"Action '{action_id}' not found in queue."}

        if action.status == "approved":
            return {"status": "error", "message": f"Action '{action_id}' is already approved. Cannot approve twice."}

        if action.status == "rejected":
            return {"status": "error", "message": f"Action '{action_id}' was rejected. Cannot approve a rejected action. Regenerate the plan."}

        if action.status == "skipped":
            return {"status": "error", "message": f"Action '{action_id}' was skipped. Cannot approve a skipped action."}

        result = self._queue.approve(action_id)
        if not result:
            return {"status": "error", "message": f"Failed to approve action '{action_id}'."}

        # Log approval
        audit_logger.log_event(
            action_type="approved",
            remediation_action_id=action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="approved",
            execution_outcome="not_executed",
            session_id=action.session_id,
        )

        return {
            "status": "approved",
            "action_id": action_id,
            "message": f"Action '{action_id}' approved. Execution is not enabled in this phase.",
            "execution_outcome": "not_executed",
        }

    def reject(self, action_id: str) -> Dict[str, Any]:
        """Reject a remediation action via API."""
        action = self._queue.get_action(action_id)
        if not action:
            return {"status": "error", "message": f"Action '{action_id}' not found."}

        if action.status in ("approved", "rejected", "skipped"):
            return {"status": "error", "message": f"Action '{action_id}' is already {action.status}. Cannot reject."}

        result = self._queue.reject(action_id)
        if not result:
            return {"status": "error", "message": f"Failed to reject action '{action_id}'."}

        # Log rejection
        audit_logger.log_event(
            action_type="rejected",
            remediation_action_id=action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="rejected",
            execution_outcome="not_executed",
            session_id=action.session_id,
        )

        return {"status": "rejected", "action_id": action_id, "message": f"Action '{action_id}' rejected."}

    def skip(self, action_id: str) -> Dict[str, Any]:
        """Skip a remediation action."""
        action = self._queue.get_action(action_id)
        if not action:
            return {"status": "error", "message": f"Action '{action_id}' not found."}

        if action.status in ("approved", "rejected", "skipped"):
            return {"status": "error", "message": f"Action '{action_id}' is already {action.status}."}

        result = self._queue.skip(action_id)
        if not result:
            return {"status": "error", "message": f"Failed to skip action '{action_id}'."}

        audit_logger.log_event(
            action_type="skipped",
            remediation_action_id=action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="skipped",
            execution_outcome="not_executed",
            session_id=action.session_id,
        )

        return {"status": "skipped", "action_id": action_id}


# Global approval engine instance
approval_engine = ApprovalEngine()
