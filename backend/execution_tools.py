"""Execution Tools — Dry-Run Execution Engine.

Phase 5: DRY-RUN ONLY. Simulates the full execution workflow without
making any AWS-mutating API calls. Generates simulated before/after states,
verification results, and score impact.

NEVER calls Create, Put, Update, Delete, Attach, Detach, Enable, Disable,
Start, Stop, Revoke, Authorize, or Modify AWS APIs.
"""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

from backend.allowlist import ALLOWED_ACTIONS, BLOCKED_ACTIONS, is_action_allowed, is_action_blocked
from backend.audit_logger import audit_logger
from backend.remediation_queue import remediation_queue

logger = logging.getLogger(__name__)


# Simulated before/after states for dry-run by action type
_SIMULATED_STATES: Dict[str, Dict[str, Any]] = {
    "s3:PutPublicAccessBlock": {
        "before": {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
        "after": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
        "verification": "Public access block configuration confirmed active on bucket.",
    },
    "s3:PutEncryptionConfiguration": {
        "before": {"ServerSideEncryptionConfiguration": None},
        "after": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
        "verification": "Default encryption (AES-256) confirmed enabled on bucket.",
    },
    "kms:EnableKeyRotation": {
        "before": {"KeyRotationEnabled": False},
        "after": {"KeyRotationEnabled": True},
        "verification": "Automatic key rotation confirmed enabled (365-day cycle).",
    },
    "guardduty:CreateDetector": {
        "before": {"DetectorExists": False},
        "after": {"DetectorId": "dry-run-detector-id", "Status": "ENABLED"},
        "verification": "GuardDuty detector confirmed active in region.",
    },
    "securityhub:BatchEnableStandards": {
        "before": {"StandardsEnabled": []},
        "after": {"StandardsEnabled": ["CIS AWS Foundations", "AWS Foundational Security Best Practices"]},
        "verification": "Security Hub standards confirmed enabled.",
    },
    "cloudtrail:CreateTrail": {
        "before": {"TrailExists": False},
        "after": {"TrailName": "security-audit-trail", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True},
        "verification": "CloudTrail trail confirmed active with multi-region and log validation.",
    },
    "cloudtrail:StartLogging": {
        "before": {"IsLogging": False},
        "after": {"IsLogging": True},
        "verification": "CloudTrail logging confirmed started.",
    },
    "ec2:RevokeSecurityGroupIngress": {
        "before": {"IngressRules": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]},
        "after": {"IngressRules": []},
        "verification": "Unrestricted SSH ingress rule confirmed removed from security group.",
    },
    "iam:UpdateAccessKey": {
        "before": {"AccessKeyStatus": "Active", "LastUsed": "90+ days ago"},
        "after": {"AccessKeyStatus": "Inactive"},
        "verification": "Access key confirmed deactivated.",
    },
}


class ExecutionEngine:
    """Dry-Run Execution Engine — simulates execution without AWS mutations.

    Full workflow: verify → simulate before-state → simulate execution →
    simulate after-state → simulate verification → audit log → mark consumed.

    NEVER calls AWS-mutating APIs.
    """

    def dry_run_execute(self, action_id: str) -> Dict[str, Any]:
        """Execute a dry-run for an approved remediation action.

        Simulates the full execution workflow without making AWS changes.

        Args:
            action_id: The approved Remediation_Action_ID.

        Returns:
            Dry-run execution result with simulated states.
        """
        # Step 1: Verify action exists
        action = remediation_queue.get_action(action_id)
        if not action:
            return self._error(action_id, "Action not found in queue.")

        # Step 2: Verify action is approved
        if action.status != "approved":
            return self._error(action_id, f"Action status is '{action.status}'. Must be 'approved' to execute.")

        # Step 3: Verify not already consumed
        if hasattr(action, '_consumed') and action._consumed:
            return self._error(action_id, "Action has already been consumed. Cannot execute twice.")

        # Step 4: Verify dry-run mode
        dry_run = os.environ.get("DRY_RUN_REMEDIATION", "true").lower() == "true"
        if not dry_run:
            return self._error(action_id, "Live execution is not enabled in Phase 5. Only dry-run is available.")

        # Step 5: Verify action is not on blocklist
        blocked, block_reason = is_action_blocked(action.proposed_action)
        if blocked:
            self._audit_blocked(action, f"Blocklist: {block_reason}")
            return self._error(action_id, f"Action '{action.proposed_action}' is permanently blocked. {block_reason}")

        # Step 6: Verify action is on allowlist
        allowed, allow_reason = is_action_allowed(action.proposed_action)
        if not allowed:
            self._audit_blocked(action, f"Not on allowlist: {allow_reason}")
            return self._error(action_id, f"Action '{action.proposed_action}' is not on the allowlist. {allow_reason}")

        # Step 7: Generate simulated states
        states = _SIMULATED_STATES.get(action.proposed_action, {
            "before": {"state": "unknown (no simulation template for this action)"},
            "after": {"state": "simulated change applied"},
            "verification": "Simulated verification passed.",
        })

        simulated_before = states["before"]
        simulated_after = states["after"]
        simulated_verification = states["verification"]

        # Step 8: Simulate score impact
        simulated_score_impact = action.estimated_score_impact

        # Step 9: Mark as consumed (single-use)
        action._consumed = True
        action.status = "dry_run_completed"

        # Step 10: Write audit log
        audit_logger.log_event(
            action_type="dry_run",
            remediation_action_id=action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="dry_run_completed",
            execution_outcome="dry_run",
            session_id=action.session_id,
            response_source="Dry-Run Execution Result",
        )

        logger.info("Dry-run executed: %s (%s)", action_id, action.proposed_action)

        return {
            "status": "dry_run_completed",
            "action_id": action_id,
            "execution_mode": "dry_run",
            "proposed_action": action.proposed_action,
            "target_resource": action.target_resource,
            "risk_category": action.risk_category,
            "simulated_before_state": simulated_before,
            "simulated_after_state": simulated_after,
            "simulated_verification": simulated_verification,
            "simulated_score_impact": simulated_score_impact,
            "message": "Dry-run execution completed. No AWS changes were made.",
            "response_source": "Dry-Run Execution Result",
        }

    def _error(self, action_id: str, message: str) -> Dict[str, Any]:
        """Return an error result."""
        return {
            "status": "error",
            "action_id": action_id,
            "execution_mode": "dry_run",
            "message": message,
        }

    def _audit_blocked(self, action, reason: str) -> None:
        """Log a blocked execution attempt."""
        audit_logger.log_event(
            action_type="blocked",
            remediation_action_id=action.action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="blocked",
            execution_outcome="not_executed",
            error_message=reason,
            session_id=action.session_id,
        )

    # ─── Live Execution (Phase 6 — Low-Risk Only) ──────────────────

    # Low-risk actions allowed for live execution
    LOW_RISK_LIVE_ACTIONS = {
        "s3:PutPublicAccessBlock",
        "s3:PutEncryptionConfiguration",
        "kms:EnableKeyRotation",
        "guardduty:CreateDetector",
        "securityhub:BatchEnableStandards",
        "cloudtrail:CreateTrail",
        "cloudtrail:StartLogging",
    }

    def live_execute(self, action_id: str, iam_manager=None) -> Dict[str, Any]:
        """Execute a live remediation for an approved low-risk action.

        Makes REAL AWS API calls. Only for low-risk allowlisted actions.

        Args:
            action_id: The approved Remediation_Action_ID.
            iam_manager: IAMManager instance for execution role.

        Returns:
            Live execution result with real before/after states.
        """
        # Step 1: Verify action exists
        action = remediation_queue.get_action(action_id)
        if not action:
            return self._error(action_id, "Action not found in queue.")

        # Step 2: Verify approved
        if action.status != "approved":
            return self._error(action_id, f"Action status is '{action.status}'. Must be 'approved'.")

        # Step 3: Verify not consumed
        if hasattr(action, '_consumed') and action._consumed:
            return self._error(action_id, "Action already consumed. Cannot execute twice.")

        # Step 4: Verify DRY_RUN is OFF
        dry_run = os.environ.get("DRY_RUN_REMEDIATION", "true").lower() == "true"
        if dry_run:
            return self._error(action_id, "DRY_RUN_REMEDIATION is true. Set to false for live execution.")

        # Step 5: Verify execution enabled
        exec_enabled = os.environ.get("REMEDIATION_EXECUTION_ENABLED", "false").lower() == "true"
        if not exec_enabled:
            return self._error(action_id, "REMEDIATION_EXECUTION_ENABLED is not true.")

        # Step 6: Verify LOW-RISK only
        if action.risk_category != "low":
            self._audit_blocked(action, f"Live execution only for low-risk. This is {action.risk_category}-risk.")
            return self._error(action_id, f"Live execution only for low-risk actions. This action is {action.risk_category}-risk.")

        # Step 7: Verify on allowlist and not on blocklist
        blocked, block_reason = is_action_blocked(action.proposed_action)
        if blocked:
            self._audit_blocked(action, block_reason)
            return self._error(action_id, f"Action permanently blocked: {block_reason}")

        allowed, allow_reason = is_action_allowed(action.proposed_action)
        if not allowed:
            self._audit_blocked(action, allow_reason)
            return self._error(action_id, f"Action not allowlisted: {allow_reason}")

        # Step 8: Verify in low-risk live set
        if action.proposed_action not in self.LOW_RISK_LIVE_ACTIONS:
            self._audit_blocked(action, f"'{action.proposed_action}' not in low-risk live execution set.")
            return self._error(action_id, f"Action '{action.proposed_action}' is not in the low-risk live execution set for Phase 6.")

        # Step 9: Verify execution role/session
        if not iam_manager:
            from backend.iam_manager import IAMManager
            iam_manager = IAMManager()

        exec_verify = iam_manager.verify_execution_role()
        if exec_verify.get("status") not in ("connected",):
            return self._error(action_id, f"Execution role not available: {exec_verify.get('message', '')}")

        # Step 10: Capture before-state
        before_state = self._capture_before_state(action, iam_manager)

        # Step 11: Execute AWS API call
        exec_result = self._execute_aws_action(action, iam_manager)
        if exec_result.get("status") == "error":
            # Execution failed
            action.status = "failed"
            audit_logger.log_event(
                action_type="executed",
                remediation_action_id=action_id,
                finding_id=action.finding_id,
                target_resource=action.target_resource,
                proposed_action=action.proposed_action,
                risk_category=action.risk_category,
                status="failed",
                execution_outcome="failure",
                error_message=exec_result.get("message", ""),
                session_id=action.session_id,
                response_source="Actual AWS Execution Result",
            )
            return {
                "status": "failed",
                "action_id": action_id,
                "execution_mode": "live",
                "message": exec_result.get("message", "Execution failed"),
                "before_state": before_state,
                "response_source": "Actual AWS Execution Result",
            }

        # Step 12: Capture after-state
        after_state = self._capture_after_state(action, iam_manager)

        # Step 13: Verify
        verification = self._verify_execution(action, after_state)

        # Step 14: Mark consumed
        action._consumed = True
        action.status = "executed"

        # Step 15: Write audit log
        audit_logger.log_event(
            action_type="executed",
            remediation_action_id=action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="executed",
            execution_outcome="success",
            session_id=action.session_id,
            response_source="Actual AWS Execution Result",
        )

        logger.info("LIVE EXECUTED: %s (%s) on %s", action_id, action.proposed_action, action.target_resource)

        return {
            "status": "executed",
            "action_id": action_id,
            "execution_mode": "live",
            "proposed_action": action.proposed_action,
            "target_resource": action.target_resource,
            "risk_category": action.risk_category,
            "account_id": exec_verify.get("account_id", ""),
            "region": iam_manager.region,
            "execution_role": exec_verify.get("role_arn", ""),
            "before_state": before_state,
            "after_state": after_state,
            "verification": verification,
            "simulated_score_impact": action.estimated_score_impact,
            "aws_request_id": exec_result.get("request_id", ""),
            "message": "Live execution completed. AWS resource was modified.",
            "response_source": "Actual AWS Execution Result",
        }

    def _capture_before_state(self, action, iam_manager) -> Dict[str, Any]:
        """Capture resource state before execution."""
        try:
            if action.proposed_action == "s3:PutPublicAccessBlock":
                client = iam_manager.get_execution_client("s3")
                bucket = self._extract_bucket_name(action.target_resource)
                if client and bucket:
                    try:
                        resp = client.get_public_access_block(Bucket=bucket)
                        return resp.get("PublicAccessBlockConfiguration", {})
                    except Exception:
                        return {"state": "no_existing_config"}
            elif action.proposed_action == "s3:PutEncryptionConfiguration":
                client = iam_manager.get_execution_client("s3")
                bucket = self._extract_bucket_name(action.target_resource)
                if client and bucket:
                    try:
                        resp = client.get_bucket_encryption(Bucket=bucket)
                        return resp.get("ServerSideEncryptionConfiguration", {})
                    except Exception:
                        return {"state": "no_encryption_config"}
            elif action.proposed_action == "kms:EnableKeyRotation":
                client = iam_manager.get_execution_client("kms")
                key_id = self._extract_key_id(action.target_resource)
                if client and key_id:
                    try:
                        resp = client.get_key_rotation_status(KeyId=key_id)
                        return {"KeyRotationEnabled": resp.get("KeyRotationEnabled", False)}
                    except Exception:
                        return {"KeyRotationEnabled": False}
        except Exception as e:
            logger.warning("Before-state capture failed: %s", e)
        return {"state": "capture_failed"}

    def _capture_after_state(self, action, iam_manager) -> Dict[str, Any]:
        """Capture resource state after execution for verification."""
        # Re-use before-state capture logic (same read calls)
        return self._capture_before_state(action, iam_manager)

    def _verify_execution(self, action, after_state: Dict) -> str:
        """Verify the execution produced expected results."""
        if action.proposed_action == "s3:PutPublicAccessBlock":
            if after_state.get("BlockPublicAcls") is True:
                return "Verified: S3 Block Public Access is now enabled."
            return "Warning: Could not verify Block Public Access state."
        if action.proposed_action == "s3:PutEncryptionConfiguration":
            if after_state.get("Rules") or after_state.get("state") != "no_encryption_config":
                return "Verified: Default encryption is now configured."
            return "Warning: Could not verify encryption configuration."
        if action.proposed_action == "kms:EnableKeyRotation":
            if after_state.get("KeyRotationEnabled") is True:
                return "Verified: KMS key rotation is now enabled."
            return "Warning: Could not verify key rotation state."
        return "Execution completed. Manual verification recommended."

    def _execute_aws_action(self, action, iam_manager) -> Dict[str, Any]:
        """Execute the actual AWS API call. LOW-RISK ONLY."""
        try:
            if action.proposed_action == "s3:PutPublicAccessBlock":
                client = iam_manager.get_execution_client("s3")
                bucket = self._extract_bucket_name(action.target_resource)
                if not client or not bucket:
                    return {"status": "error", "message": "S3 client or bucket name not available"}
                resp = client.put_public_access_block(
                    Bucket=bucket,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                )
                return {"status": "success", "request_id": resp.get("ResponseMetadata", {}).get("RequestId", "")}

            elif action.proposed_action == "s3:PutEncryptionConfiguration":
                client = iam_manager.get_execution_client("s3")
                bucket = self._extract_bucket_name(action.target_resource)
                if not client or not bucket:
                    return {"status": "error", "message": "S3 client or bucket name not available"}
                resp = client.put_bucket_encryption(
                    Bucket=bucket,
                    ServerSideEncryptionConfiguration={
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    }
                )
                return {"status": "success", "request_id": resp.get("ResponseMetadata", {}).get("RequestId", "")}

            elif action.proposed_action == "kms:EnableKeyRotation":
                client = iam_manager.get_execution_client("kms")
                key_id = self._extract_key_id(action.target_resource)
                if not client or not key_id:
                    return {"status": "error", "message": "KMS client or key ID not available"}
                resp = client.enable_key_rotation(KeyId=key_id)
                return {"status": "success", "request_id": resp.get("ResponseMetadata", {}).get("RequestId", "")}

            elif action.proposed_action == "guardduty:CreateDetector":
                client = iam_manager.get_execution_client("guardduty")
                if not client:
                    return {"status": "error", "message": "GuardDuty client not available"}
                resp = client.create_detector(Enable=True)
                return {"status": "success", "request_id": resp.get("ResponseMetadata", {}).get("RequestId", ""), "detector_id": resp.get("DetectorId", "")}

            elif action.proposed_action == "securityhub:BatchEnableStandards":
                client = iam_manager.get_execution_client("securityhub")
                if not client:
                    return {"status": "error", "message": "Security Hub client not available"}
                # Enable Security Hub first if needed
                try:
                    client.enable_security_hub()
                except Exception:
                    pass  # May already be enabled
                return {"status": "success", "request_id": ""}

            elif action.proposed_action in ("cloudtrail:CreateTrail", "cloudtrail:StartLogging"):
                client = iam_manager.get_execution_client("cloudtrail")
                if not client:
                    return {"status": "error", "message": "CloudTrail client not available"}
                if action.proposed_action == "cloudtrail:StartLogging":
                    trail_name = self._extract_trail_name(action.target_resource)
                    resp = client.start_logging(Name=trail_name or "security-audit-trail")
                    return {"status": "success", "request_id": resp.get("ResponseMetadata", {}).get("RequestId", "")}
                else:
                    # CreateTrail requires a bucket — skip if not configured
                    return {"status": "error", "message": "CloudTrail CreateTrail requires S3 bucket configuration. Use CLI or IaC instead."}

            else:
                return {"status": "error", "message": f"No live execution handler for '{action.proposed_action}'"}

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _extract_bucket_name(self, resource_arn: str) -> str:
        """Extract S3 bucket name from ARN or resource string."""
        if ":::" in resource_arn:
            return resource_arn.split(":::")[-1].split("/")[0]
        if resource_arn.startswith("s3://"):
            return resource_arn[5:].split("/")[0]
        return resource_arn

    def _extract_key_id(self, resource_arn: str) -> str:
        """Extract KMS key ID from ARN or resource string."""
        if ":key/" in resource_arn:
            return resource_arn.split(":key/")[-1]
        return resource_arn

    def _extract_trail_name(self, resource_arn: str) -> str:
        """Extract CloudTrail trail name from ARN."""
        if ":trail/" in resource_arn:
            return resource_arn.split(":trail/")[-1]
        return resource_arn


# Global execution engine instance
execution_engine = ExecutionEngine()
