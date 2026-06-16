"""Audit Logger — Append-only JSON Lines audit log for remediation actions.

Records all remediation lifecycle events: queued, presented_for_approval,
approved, rejected, skipped, blocked. Each entry is a single JSON line
appended atomically.

Storage: data/audit/remediation_audit.jsonl
Permissions: 0o600 file, 0o700 directory (set on creation)
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

AUDIT_LOG_PATH = Path("data/audit/remediation_audit.jsonl")


class AuditLogger:
    """Append-only JSON Lines audit logger for remediation actions."""

    def __init__(self, path: Path = AUDIT_LOG_PATH):
        self._path = path
        self._ensure_directory()

    def _ensure_directory(self):
        """Create audit directory with secure permissions if it doesn't exist."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:
            pass  # May not work on all platforms

    def log_event(
        self,
        action_type: str,
        remediation_action_id: str = "",
        finding_id: str = "",
        target_resource: str = "",
        proposed_action: str = "",
        risk_category: str = "",
        status: str = "",
        execution_outcome: str = "not_executed",
        error_message: str = "",
        session_id: str = "",
        actor: str = "",
        response_source: str = "Remediation Planning Engine",
    ) -> Dict[str, Any]:
        """Append an audit event to the log file.

        Args:
            action_type: Event type (queued, presented_for_approval, approved, rejected, skipped, blocked)
            remediation_action_id: Unique action identifier
            finding_id: Associated finding ID
            target_resource: Target AWS resource ARN or identifier
            proposed_action: AWS API action proposed
            risk_category: low, medium, high
            status: Current status after this event
            execution_outcome: not_executed (Phase 4)
            error_message: Error details if applicable
            session_id: Session identifier
            actor: Who performed the action
            response_source: Data source label

        Returns:
            The audit entry dict that was written.
        """
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_type": action_type,
            "remediation_action_id": remediation_action_id,
            "finding_id": finding_id,
            "target_resource": target_resource,
            "proposed_action": proposed_action,
            "risk_category": risk_category,
            "status": status,
            "execution_outcome": execution_outcome,
            "error_message": error_message,
            "session_id": session_id,
            "actor": actor,
            "response_source": response_source,
        }

        try:
            line = json.dumps(entry) + "\n"
            with open(self._path, "a") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            # Set file permissions on first write
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                pass
        except Exception as e:
            logger.error("Failed to write audit log: %s", e)

        return entry

    def get_entries(
        self,
        action_type: str = "",
        status: str = "",
        risk_category: str = "",
        resource: str = "",
        remediation_action_id: str = "",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Read audit log entries with optional filters.

        Args:
            action_type: Filter by action type
            status: Filter by status
            risk_category: Filter by risk category
            resource: Filter by target resource (substring match)
            remediation_action_id: Filter by specific action ID
            limit: Max entries to return (most recent first)

        Returns:
            List of audit entry dicts, most recent first.
        """
        if not self._path.exists():
            return []

        entries = []
        try:
            with open(self._path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue  # Skip malformed lines
        except Exception as e:
            logger.error("Failed to read audit log: %s", e)
            return []

        # Apply filters
        if action_type:
            entries = [e for e in entries if e.get("action_type") == action_type]
        if status:
            entries = [e for e in entries if e.get("status") == status]
        if risk_category:
            entries = [e for e in entries if e.get("risk_category") == risk_category]
        if resource:
            entries = [e for e in entries if resource.lower() in e.get("target_resource", "").lower()]
        if remediation_action_id:
            entries = [e for e in entries if e.get("remediation_action_id") == remediation_action_id]

        # Return most recent first, limited
        entries.reverse()
        return entries[:limit]

    def get_entry_count(self) -> int:
        """Get total number of audit entries."""
        if not self._path.exists():
            return 0
        try:
            with open(self._path, "r") as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0


# Global audit logger instance
audit_logger = AuditLogger()
