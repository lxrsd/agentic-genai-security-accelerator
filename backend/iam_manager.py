"""IAM Role Manager — Centralized AWS identity and role session handling.

Provides:
- Caller identity verification via STS
- Read-only role assumption (if READ_ONLY_ROLE_ARN configured)
- Execution role assumption (if EXECUTION_ROLE_ARN configured, Phase 6+)
- Fallback to current credentials if no role specified
- Execution permission simulation via iam:SimulatePrincipalPolicy
"""

import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class IAMManager:
    """Manages AWS identity verification and session creation.

    Supports two role types:
    - Read_Only_Role: for investigation tools (List/Get/Describe/Lookup)
    - Execution_Role: for live remediation (Phase 6+, low-risk only)
    """

    def __init__(self, region: str = ""):
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._read_only_role_arn = os.environ.get("READ_ONLY_ROLE_ARN", "")
        self._execution_role_arn = os.environ.get("EXECUTION_ROLE_ARN", "")
        self._cached_session = None
        self._session_expiry: float = 0
        self._cached_execution_session = None
        self._execution_session_expiry: float = 0
        self._identity_cache: Optional[Dict[str, Any]] = None

    def get_caller_identity(self) -> Dict[str, Any]:
        """Get current AWS caller identity via STS.

        Returns:
            Dict with status, account_id, arn, user_id, region.
        """
        try:
            import boto3
            sts = boto3.client("sts", region_name=self._region)
            identity = sts.get_caller_identity()
            self._identity_cache = {
                "status": "connected",
                "account_id": identity.get("Account", ""),
                "arn": identity.get("Arn", ""),
                "user_id": identity.get("UserId", ""),
                "region": self._region,
            }
            return self._identity_cache
        except ImportError:
            return {"status": "error", "message": "boto3 not installed"}
        except Exception as e:
            return {"status": "not_connected", "message": str(e)}

    def get_read_only_session(self):
        """Get a boto3 session for read-only operations.

        If READ_ONLY_ROLE_ARN is configured, assumes that role.
        Otherwise falls back to current credentials.

        Returns:
            A boto3.Session instance or None if unavailable.
        """
        try:
            import boto3

            # If we have a cached session that hasn't expired, reuse it
            if self._cached_session and time.time() < self._session_expiry:
                return self._cached_session

            if self._read_only_role_arn:
                return self._assume_read_only_role()

            # Fallback: use current credentials
            session = boto3.Session(region_name=self._region)
            self._cached_session = session
            self._session_expiry = time.time() + 3500  # ~1 hour
            return session

        except ImportError:
            logger.error("boto3 not installed — cannot create AWS session")
            return None
        except Exception as e:
            logger.error("Failed to create read-only session: %s", e)
            return None

    def _assume_read_only_role(self):
        """Assume the configured READ_ONLY_ROLE_ARN."""
        import boto3

        sts = boto3.client("sts", region_name=self._region)
        response = sts.assume_role(
            RoleArn=self._read_only_role_arn,
            RoleSessionName="agentic-security-investigation",
            DurationSeconds=3600,
        )
        credentials = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=self._region,
        )
        self._cached_session = session
        self._session_expiry = time.time() + 3500
        logger.info("Assumed read-only role: %s", self._read_only_role_arn)
        return session

    def verify_read_only_access(self) -> Dict[str, Any]:
        """Verify that the current session has basic read access.

        Tests STS GetCallerIdentity as a minimal check.
        """
        session = self.get_read_only_session()
        if not session:
            return {"status": "not_connected", "message": "No AWS session available"}

        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return {
                "status": "connected",
                "account_id": identity.get("Account", ""),
                "arn": identity.get("Arn", ""),
                "role_arn": self._read_only_role_arn or "current credentials",
                "region": self._region,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_client(self, service_name: str):
        """Get a boto3 client for a specific service using read-only session.

        Args:
            service_name: AWS service (e.g., 'iam', 's3', 'cloudtrail')

        Returns:
            boto3 client or None if unavailable.
        """
        session = self.get_read_only_session()
        if not session:
            return None
        try:
            return session.client(service_name, region_name=self._region)
        except Exception as e:
            logger.error("Failed to create %s client: %s", service_name, e)
            return None

    @property
    def region(self) -> str:
        return self._region

    @property
    def read_only_role_arn(self) -> str:
        return self._read_only_role_arn

    def mask_access_key_id(self, key_id: str) -> str:
        """Mask access key ID, showing only last 4 characters."""
        if not key_id or len(key_id) < 4:
            return "****"
        return "****" + key_id[-4:]

    # ─── Execution Role (Phase 6+) ─────────────────────────────────

    def get_execution_session(self):
        """Get a boto3 session for execution operations.

        If EXECUTION_ROLE_ARN is configured, assumes that role.
        Otherwise falls back to current credentials (for local dev/demo).

        Returns:
            A boto3.Session instance or None if unavailable.
        """
        try:
            import boto3

            if self._cached_execution_session and time.time() < self._execution_session_expiry:
                return self._cached_execution_session

            if self._execution_role_arn:
                return self._assume_execution_role()

            # Fallback: use current credentials (local dev/demo mode)
            session = boto3.Session(region_name=self._region)
            self._cached_execution_session = session
            self._execution_session_expiry = time.time() + 3500
            logger.warning("Using current credentials for execution (no EXECUTION_ROLE_ARN configured)")
            return session

        except ImportError:
            logger.error("boto3 not installed")
            return None
        except Exception as e:
            logger.error("Failed to create execution session: %s", e)
            return None

    def _assume_execution_role(self):
        """Assume the configured EXECUTION_ROLE_ARN."""
        import boto3

        sts = boto3.client("sts", region_name=self._region)
        response = sts.assume_role(
            RoleArn=self._execution_role_arn,
            RoleSessionName="agentic-security-execution",
            DurationSeconds=3600,
        )
        credentials = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=self._region,
        )
        self._cached_execution_session = session
        self._execution_session_expiry = time.time() + 3500
        logger.info("Assumed execution role: %s", self._execution_role_arn)
        return session

    def get_execution_client(self, service_name: str):
        """Get a boto3 client for execution using the execution role.

        Args:
            service_name: AWS service (e.g., 's3', 'kms', 'guardduty')

        Returns:
            boto3 client or None.
        """
        session = self.get_execution_session()
        if not session:
            return None
        try:
            return session.client(service_name, region_name=self._region)
        except Exception as e:
            logger.error("Failed to create execution %s client: %s", service_name, e)
            return None

    def verify_execution_role(self) -> Dict[str, Any]:
        """Verify execution role is assumable."""
        session = self.get_execution_session()
        if not session:
            return {"status": "not_connected", "message": "Execution session not available"}
        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            return {
                "status": "connected",
                "account_id": identity.get("Account", ""),
                "arn": identity.get("Arn", ""),
                "role_arn": self._execution_role_arn or "current credentials",
                "region": self._region,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def simulate_execution_permission(self, action: str, resource_arn: str) -> Dict[str, Any]:
        """Simulate whether the execution role has permission for an action.

        Uses iam:SimulatePrincipalPolicy if possible, otherwise returns unknown.
        """
        try:
            import boto3
            iam = boto3.client("iam", region_name=self._region)
            # Determine the principal ARN
            principal_arn = self._execution_role_arn
            if not principal_arn:
                # Use current caller
                sts = boto3.client("sts", region_name=self._region)
                identity = sts.get_caller_identity()
                principal_arn = identity.get("Arn", "")

            response = iam.simulate_principal_policy(
                PolicySourceArn=principal_arn,
                ActionNames=[action],
                ResourceArns=[resource_arn] if resource_arn else [],
            )
            results = response.get("EvaluationResults", [])
            if results:
                decision = results[0].get("EvalDecision", "")
                return {
                    "status": "simulated",
                    "action": action,
                    "resource": resource_arn,
                    "decision": decision,
                    "allowed": decision == "allowed",
                }
            return {"status": "unknown", "message": "No simulation result"}
        except Exception as e:
            # Permission simulation may not be available — continue anyway
            return {"status": "unavailable", "message": f"Permission simulation failed: {e}"}

    @property
    def execution_role_arn(self) -> str:
        return self._execution_role_arn
