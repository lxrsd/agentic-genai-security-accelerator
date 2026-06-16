"""AWS API Action Allowlist and Blocklist.

Defines which AWS API actions are permitted for execution and which
are permanently blocked. Used by planning tools for safety validation
and by execution tools (future) for enforcement.

No code in this file makes AWS API calls.
"""

from typing import Dict, Set, Tuple


# Actions that ARE permitted for execution (Level 5, low-risk only for MVP)
ALLOWED_ACTIONS: Set[str] = {
    "s3:PutPublicAccessBlock",
    "s3:PutEncryptionConfiguration",
    "kms:EnableKeyRotation",
    "guardduty:CreateDetector",
    "securityhub:BatchEnableStandards",
    "cloudtrail:CreateTrail",
    "cloudtrail:StartLogging",
    "ec2:RevokeSecurityGroupIngress",
    "iam:UpdateAccessKey",
}

# Actions that are PERMANENTLY blocked regardless of flags or approval
BLOCKED_ACTIONS: Set[str] = {
    "iam:DeleteUser",
    "iam:DeleteRole",
    "iam:DeleteAccessKey",
    "s3:DeleteBucket",
    "cloudtrail:DeleteTrail",
    "guardduty:DeleteDetector",
    "kms:ScheduleKeyDeletion",
    "iam:AttachUserPolicy",       # Blocked when policy is Admin/PowerUser/*
    "iam:AttachRolePolicy",       # Blocked when policy is Admin/PowerUser/*
    "ec2:AuthorizeSecurityGroupIngress",  # Blocked when CIDR is 0.0.0.0/0 or ::/0
    "kms:PutKeyPolicy",           # Blocked in MVP
}

# Policy ARNs that must never be attached
BLOCKED_POLICY_ARNS: Set[str] = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}

# Risk classification per action
RISK_CLASSIFICATIONS: Dict[str, str] = {
    "s3:PutPublicAccessBlock": "low",
    "s3:PutEncryptionConfiguration": "low",
    "kms:EnableKeyRotation": "low",
    "guardduty:CreateDetector": "low",
    "securityhub:BatchEnableStandards": "low",
    "cloudtrail:CreateTrail": "low",
    "cloudtrail:StartLogging": "low",
    "ec2:RevokeSecurityGroupIngress": "medium",
    "iam:UpdateAccessKey": "medium",
}


def is_action_allowed(action: str, params: dict = None) -> Tuple[bool, str]:
    """Check if an action is on the allowlist.

    Returns:
        Tuple of (allowed: bool, reason: str).
    """
    if not action:
        return False, "No action specified"

    if action in ALLOWED_ACTIONS:
        return True, f"Action '{action}' is on the execution allowlist"

    return False, f"Action '{action}' is NOT on the execution allowlist"


def is_action_blocked(action: str, params: dict = None) -> Tuple[bool, str]:
    """Check if an action is on the permanent blocklist.

    Returns:
        Tuple of (blocked: bool, reason: str).
    """
    if not action:
        return False, "No action specified"

    if action in BLOCKED_ACTIONS:
        return True, f"Action '{action}' is on the permanent blocklist. This action cannot be executed."

    # Check parameter-based blocking
    params = params or {}
    if action in ("iam:AttachUserPolicy", "iam:AttachRolePolicy"):
        policy_arn = params.get("policy_arn", "")
        if policy_arn in BLOCKED_POLICY_ARNS:
            return True, f"Attaching policy '{policy_arn}' is permanently blocked (admin/power user access)"

    if action == "ec2:AuthorizeSecurityGroupIngress":
        cidr = params.get("cidr", "")
        if cidr in ("0.0.0.0/0", "::/0"):
            return True, f"Adding ingress rule with CIDR '{cidr}' is permanently blocked (open to internet)"

    return False, "Action is not on the blocklist"
