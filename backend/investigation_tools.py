"""Read-Only AWS Investigation Tools.

Provides live AWS read-only query tools for the Bedrock assistant.
All tools use only List/Get/Describe/Lookup APIs — never Create, Put,
Update, Delete, Attach, Detach, Enable, Disable, Start, Stop, Revoke,
Authorize, or Modify.

Safety limits:
- CloudTrail: default 24h lookback, max 90 days, max 50 events
- Security Hub: max 25 findings per request
- GuardDuty: max 25 findings per request
- Inspector: max 25 findings per request
- Access key IDs masked (last 4 chars only)
- Never displays secret keys, tokens, or passwords
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Hard limits
CLOUDTRAIL_DEFAULT_HOURS = 24
CLOUDTRAIL_MAX_DAYS = 90
CLOUDTRAIL_MAX_RESULTS = 50
SECURITYHUB_MAX_RESULTS = 25
GUARDDUTY_MAX_RESULTS = 25
INSPECTOR_MAX_RESULTS = 25


class InvestigationTools:
    """Read-only AWS investigation tools for the assistant.

    All methods use boto3 read-only APIs only. No mutations.
    """

    def __init__(self, iam_manager):
        """Initialize with IAM manager for session handling.

        Args:
            iam_manager: IAMManager instance for creating AWS clients.
        """
        self._iam_manager = iam_manager

    def _mask_key(self, key_id: str) -> str:
        """Mask access key ID, showing only last 4 chars."""
        return self._iam_manager.mask_access_key_id(key_id)

    # ─── IAM Tools ──────────────────────────────────────────────────

    def list_iam_users(self, params: Dict = None) -> Dict[str, Any]:
        """List IAM users with creation date, last activity, and policy count.

        Read-only: iam:ListUsers, iam:GetAccessKeyLastUsed, iam:ListAttachedUserPolicies
        """
        client = self._iam_manager.get_client("iam")
        if not client:
            return {"error": "IAM client not available. Check AWS credentials."}

        try:
            response = client.list_users()
            users = []
            for user in response.get("Users", [])[:25]:
                user_info = {
                    "username": user.get("UserName", ""),
                    "user_id": user.get("UserId", ""),
                    "arn": user.get("Arn", ""),
                    "created": user.get("CreateDate", "").isoformat() if user.get("CreateDate") else "",
                    "password_last_used": user.get("PasswordLastUsed", "").isoformat() if user.get("PasswordLastUsed") else "Never",
                    "path": user.get("Path", "/"),
                }
                # Get attached policy count
                try:
                    policies = client.list_attached_user_policies(UserName=user["UserName"])
                    user_info["attached_policy_count"] = len(policies.get("AttachedPolicies", []))
                except Exception:
                    user_info["attached_policy_count"] = "unknown"

                users.append(user_info)

            return {
                "users": users,
                "total_count": len(users),
                "response_source": "Live AWS Read-Only Query",
            }
        except Exception as e:
            return {"error": f"Failed to list IAM users: {e}"}

    def get_iam_user_details(self, params: Dict = None) -> Dict[str, Any]:
        """Get detailed info for a specific IAM user.

        Read-only: iam:GetUser, iam:ListAccessKeys, iam:ListMFADevices,
                   iam:ListGroupsForUser, iam:ListAttachedUserPolicies
        """
        params = params or {}
        username = params.get("username", "")
        if not username:
            return {"error": "username parameter is required"}

        client = self._iam_manager.get_client("iam")
        if not client:
            return {"error": "IAM client not available. Check AWS credentials."}

        try:
            user_resp = client.get_user(UserName=username)
            user = user_resp.get("User", {})

            # Access keys (masked)
            keys_resp = client.list_access_keys(UserName=username)
            access_keys = []
            for key in keys_resp.get("AccessKeyMetadata", []):
                key_id = key.get("AccessKeyId", "")
                # Get last used
                try:
                    last_used_resp = client.get_access_key_last_used(AccessKeyId=key_id)
                    last_used = last_used_resp.get("AccessKeyLastUsed", {})
                    last_used_date = last_used.get("LastUsedDate", "").isoformat() if last_used.get("LastUsedDate") else "Never"
                except Exception:
                    last_used_date = "Unknown"

                access_keys.append({
                    "access_key_id": self._mask_key(key_id),
                    "status": key.get("Status", ""),
                    "created": key.get("CreateDate", "").isoformat() if key.get("CreateDate") else "",
                    "last_used": last_used_date,
                })

            # MFA devices
            mfa_resp = client.list_mfa_devices(UserName=username)
            mfa_devices = [{"serial": d.get("SerialNumber", ""), "enabled": True} for d in mfa_resp.get("MFADevices", [])]

            # Groups
            groups_resp = client.list_groups_for_user(UserName=username)
            groups = [g.get("GroupName", "") for g in groups_resp.get("Groups", [])]

            # Attached policies
            policies_resp = client.list_attached_user_policies(UserName=username)
            policies = [{"name": p.get("PolicyName", ""), "arn": p.get("PolicyArn", "")} for p in policies_resp.get("AttachedPolicies", [])]

            return {
                "username": user.get("UserName", ""),
                "arn": user.get("Arn", ""),
                "created": user.get("CreateDate", "").isoformat() if user.get("CreateDate") else "",
                "password_last_used": user.get("PasswordLastUsed", "").isoformat() if user.get("PasswordLastUsed") else "Never",
                "mfa_enabled": len(mfa_devices) > 0,
                "mfa_devices": mfa_devices,
                "access_keys": access_keys,
                "groups": groups,
                "attached_policies": policies,
                "response_source": "Live AWS Read-Only Query",
            }
        except Exception as e:
            return {"error": f"Failed to get user details for '{username}': {e}"}

    def list_iam_roles(self, params: Dict = None) -> Dict[str, Any]:
        """List IAM roles with basic metadata.

        Read-only: iam:ListRoles
        """
        client = self._iam_manager.get_client("iam")
        if not client:
            return {"error": "IAM client not available."}

        try:
            response = client.list_roles()
            roles = []
            for role in response.get("Roles", [])[:25]:
                roles.append({
                    "role_name": role.get("RoleName", ""),
                    "arn": role.get("Arn", ""),
                    "created": role.get("CreateDate", "").isoformat() if role.get("CreateDate") else "",
                    "path": role.get("Path", "/"),
                    "description": role.get("Description", ""),
                })
            return {"roles": roles, "total_count": len(roles), "response_source": "Live AWS Read-Only Query"}
        except Exception as e:
            return {"error": f"Failed to list IAM roles: {e}"}

    # ─── S3 Tools ───────────────────────────────────────────────────

    def describe_s3_bucket(self, params: Dict = None) -> Dict[str, Any]:
        """Get S3 bucket security configuration.

        Read-only: s3:GetBucketEncryption, s3:GetPublicAccessBlock,
                   s3:GetBucketVersioning, s3:GetBucketLogging
        """
        params = params or {}
        bucket_name = params.get("bucket_name", "")
        if not bucket_name:
            return {"error": "bucket_name parameter is required"}

        client = self._iam_manager.get_client("s3")
        if not client:
            return {"error": "S3 client not available."}

        result = {"bucket_name": bucket_name, "response_source": "Live AWS Read-Only Query"}

        # Encryption
        try:
            enc = client.get_bucket_encryption(Bucket=bucket_name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            result["encryption"] = {"enabled": len(rules) > 0, "rules": [r.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "") for r in rules]}
        except client.exceptions.ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                result["encryption"] = {"enabled": False, "rules": []}
            else:
                result["encryption"] = {"error": str(e)}

        # Public access block
        try:
            pab = client.get_public_access_block(Bucket=bucket_name)
            config = pab.get("PublicAccessBlockConfiguration", {})
            result["public_access_block"] = {
                "block_public_acls": config.get("BlockPublicAcls", False),
                "ignore_public_acls": config.get("IgnorePublicAcls", False),
                "block_public_policy": config.get("BlockPublicPolicy", False),
                "restrict_public_buckets": config.get("RestrictPublicBuckets", False),
            }
        except client.exceptions.ClientError:
            result["public_access_block"] = {"enabled": False}

        # Versioning
        try:
            ver = client.get_bucket_versioning(Bucket=bucket_name)
            result["versioning"] = {"status": ver.get("Status", "Disabled")}
        except Exception:
            result["versioning"] = {"status": "Unknown"}

        # Logging
        try:
            log = client.get_bucket_logging(Bucket=bucket_name)
            result["logging"] = {"enabled": "LoggingEnabled" in log}
        except Exception:
            result["logging"] = {"enabled": False}

        return result

    def list_s3_buckets_security_summary(self, params: Dict = None) -> Dict[str, Any]:
        """List S3 buckets with security status summary.

        Read-only: s3:ListBuckets, s3:GetPublicAccessBlock, s3:GetBucketEncryption
        """
        client = self._iam_manager.get_client("s3")
        if not client:
            return {"error": "S3 client not available."}

        try:
            response = client.list_buckets()
            buckets = []
            for bucket in response.get("Buckets", [])[:20]:
                name = bucket.get("Name", "")
                info = {"name": name, "created": bucket.get("CreationDate", "").isoformat() if bucket.get("CreationDate") else ""}

                # Quick security check
                try:
                    client.get_public_access_block(Bucket=name)
                    info["public_access_blocked"] = True
                except Exception:
                    info["public_access_blocked"] = False

                try:
                    client.get_bucket_encryption(Bucket=name)
                    info["encryption_enabled"] = True
                except Exception:
                    info["encryption_enabled"] = False

                buckets.append(info)

            return {"buckets": buckets, "total_count": len(buckets), "response_source": "Live AWS Read-Only Query"}
        except Exception as e:
            return {"error": f"Failed to list S3 buckets: {e}"}

    # ─── EC2 / Network Tools ────────────────────────────────────────

    def describe_security_group(self, params: Dict = None) -> Dict[str, Any]:
        """Describe a security group's rules and associations.

        Read-only: ec2:DescribeSecurityGroups
        """
        params = params or {}
        group_id = params.get("group_id", "")

        client = self._iam_manager.get_client("ec2")
        if not client:
            return {"error": "EC2 client not available."}

        try:
            filters = []
            if group_id:
                response = client.describe_security_groups(GroupIds=[group_id])
            else:
                # List all security groups (limited)
                response = client.describe_security_groups(MaxResults=25)

            groups = []
            for sg in response.get("SecurityGroups", [])[:10]:
                inbound = []
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        inbound.append({
                            "protocol": rule.get("IpProtocol", ""),
                            "from_port": rule.get("FromPort", "all"),
                            "to_port": rule.get("ToPort", "all"),
                            "cidr": ip_range.get("CidrIp", ""),
                            "description": ip_range.get("Description", ""),
                        })

                outbound = []
                for rule in sg.get("IpPermissionsEgress", []):
                    for ip_range in rule.get("IpRanges", []):
                        outbound.append({
                            "protocol": rule.get("IpProtocol", ""),
                            "from_port": rule.get("FromPort", "all"),
                            "to_port": rule.get("ToPort", "all"),
                            "cidr": ip_range.get("CidrIp", ""),
                        })

                groups.append({
                    "group_id": sg.get("GroupId", ""),
                    "group_name": sg.get("GroupName", ""),
                    "description": sg.get("Description", ""),
                    "vpc_id": sg.get("VpcId", ""),
                    "inbound_rules": inbound,
                    "outbound_rules": outbound[:5],
                })

            return {"security_groups": groups, "response_source": "Live AWS Read-Only Query"}
        except Exception as e:
            return {"error": f"Failed to describe security groups: {e}"}

    # ─── CloudTrail Tools ───────────────────────────────────────────

    def lookup_cloudtrail_events(self, params: Dict = None) -> Dict[str, Any]:
        """Lookup recent CloudTrail events with filters.

        Read-only: cloudtrail:LookupEvents
        Limits: max 50 events, default 24h lookback, max 90 days
        """
        params = params or {}
        hours = min(params.get("hours", CLOUDTRAIL_DEFAULT_HOURS), CLOUDTRAIL_MAX_DAYS * 24)
        username = params.get("username", "")
        event_name = params.get("event_name", "")
        event_source = params.get("event_source", "")
        max_results = min(params.get("max_results", CLOUDTRAIL_MAX_RESULTS), CLOUDTRAIL_MAX_RESULTS)

        client = self._iam_manager.get_client("cloudtrail")
        if not client:
            return {"error": "CloudTrail client not available."}

        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)

            lookup_kwargs = {
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": max_results,
            }

            # Add lookup attributes (filters)
            attributes = []
            if username:
                attributes.append({"AttributeKey": "Username", "AttributeValue": username})
            if event_name:
                attributes.append({"AttributeKey": "EventName", "AttributeValue": event_name})
            if event_source:
                attributes.append({"AttributeKey": "EventSource", "AttributeValue": event_source})

            if attributes:
                lookup_kwargs["LookupAttributes"] = attributes[:1]  # CloudTrail supports 1 attribute at a time

            response = client.lookup_events(**lookup_kwargs)

            events = []
            for event in response.get("Events", [])[:max_results]:
                events.append({
                    "event_id": event.get("EventId", ""),
                    "event_name": event.get("EventName", ""),
                    "event_time": event.get("EventTime", "").isoformat() if event.get("EventTime") else "",
                    "event_source": event.get("EventSource", ""),
                    "username": event.get("Username", ""),
                    "source_ip": event.get("CloudTrailEvent", "{}"),  # Will be parsed below
                    "resources": [{"type": r.get("ResourceType", ""), "name": r.get("ResourceName", "")} for r in event.get("Resources", [])[:3]],
                })
                # Try to extract source IP from CloudTrailEvent JSON
                try:
                    import json
                    ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                    events[-1]["source_ip"] = ct_event.get("sourceIPAddress", "")
                    events[-1]["user_agent"] = ct_event.get("userAgent", "")[:80]
                    events[-1]["aws_region"] = ct_event.get("awsRegion", "")
                except Exception:
                    events[-1]["source_ip"] = ""

            return {
                "events": events,
                "total_returned": len(events),
                "time_range": f"Last {hours} hours",
                "filters": {"username": username, "event_name": event_name, "event_source": event_source},
                "response_source": "Live AWS Read-Only Query",
            }
        except Exception as e:
            return {"error": f"Failed to lookup CloudTrail events: {e}"}

    # ─── Security Hub Tools ─────────────────────────────────────────

    def get_security_hub_findings(self, params: Dict = None) -> Dict[str, Any]:
        """Get Security Hub findings with optional filters.

        Read-only: securityhub:GetFindings
        Limit: max 25 findings per request
        """
        params = params or {}
        severity = params.get("severity", "")
        resource_type = params.get("resource_type", "")
        max_results = min(params.get("max_results", SECURITYHUB_MAX_RESULTS), SECURITYHUB_MAX_RESULTS)

        client = self._iam_manager.get_client("securityhub")
        if not client:
            return {"error": "Security Hub client not available."}

        try:
            filters = {}
            if severity:
                filters["SeverityLabel"] = [{"Value": severity.upper(), "Comparison": "EQUALS"}]
            if resource_type:
                filters["ResourceType"] = [{"Value": resource_type, "Comparison": "EQUALS"}]
            # Only active findings
            filters["RecordState"] = [{"Value": "ACTIVE", "Comparison": "EQUALS"}]

            response = client.get_findings(Filters=filters, MaxResults=max_results)
            findings = []
            for f in response.get("Findings", []):
                findings.append({
                    "title": f.get("Title", ""),
                    "severity": f.get("Severity", {}).get("Label", ""),
                    "status": f.get("Compliance", {}).get("Status", ""),
                    "resource_type": f.get("Resources", [{}])[0].get("Type", "") if f.get("Resources") else "",
                    "resource_id": f.get("Resources", [{}])[0].get("Id", "") if f.get("Resources") else "",
                    "description": f.get("Description", "")[:200],
                    "created_at": f.get("CreatedAt", ""),
                    "updated_at": f.get("UpdatedAt", ""),
                    "product": f.get("ProductName", ""),
                })

            return {
                "findings": findings,
                "total_returned": len(findings),
                "filters": {"severity": severity, "resource_type": resource_type},
                "response_source": "Live AWS Read-Only Query",
            }
        except Exception as e:
            return {"error": f"Failed to get Security Hub findings: {e}"}

    # ─── GuardDuty Tools ────────────────────────────────────────────

    def get_guardduty_findings(self, params: Dict = None) -> Dict[str, Any]:
        """Get GuardDuty findings with optional filters.

        Read-only: guardduty:ListDetectors, guardduty:ListFindings, guardduty:GetFindings
        Limit: max 25 findings per request
        """
        params = params or {}
        severity = params.get("severity", "")
        max_results = min(params.get("max_results", GUARDDUTY_MAX_RESULTS), GUARDDUTY_MAX_RESULTS)

        client = self._iam_manager.get_client("guardduty")
        if not client:
            return {"error": "GuardDuty client not available."}

        try:
            # Get detector ID
            detectors = client.list_detectors()
            detector_ids = detectors.get("DetectorIds", [])
            if not detector_ids:
                return {"findings": [], "message": "No GuardDuty detector found. GuardDuty may not be enabled.", "response_source": "Live AWS Read-Only Query"}

            detector_id = detector_ids[0]

            # List findings
            criteria = {"criterion": {}}
            if severity:
                sev_map = {"low": {"Gte": 1, "Lt": 4}, "medium": {"Gte": 4, "Lt": 7}, "high": {"Gte": 7, "Lt": 10}}
                if severity.lower() in sev_map:
                    criteria["criterion"]["severity"] = sev_map[severity.lower()]

            list_resp = client.list_findings(
                DetectorId=detector_id,
                FindingCriteria=criteria,
                MaxResults=max_results,
            )
            finding_ids = list_resp.get("FindingIds", [])

            if not finding_ids:
                return {"findings": [], "total_returned": 0, "response_source": "Live AWS Read-Only Query"}

            # Get finding details
            get_resp = client.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:max_results])
            findings = []
            for f in get_resp.get("Findings", []):
                findings.append({
                    "id": f.get("Id", ""),
                    "type": f.get("Type", ""),
                    "severity": f.get("Severity", 0),
                    "title": f.get("Title", ""),
                    "description": f.get("Description", "")[:200],
                    "resource_type": f.get("Resource", {}).get("ResourceType", ""),
                    "created_at": f.get("CreatedAt", ""),
                    "updated_at": f.get("UpdatedAt", ""),
                })

            return {
                "findings": findings,
                "total_returned": len(findings),
                "detector_id": detector_id,
                "response_source": "Live AWS Read-Only Query",
            }
        except Exception as e:
            return {"error": f"Failed to get GuardDuty findings: {e}"}

    # ─── Inspector Tools ────────────────────────────────────────────

    def get_inspector_findings(self, params: Dict = None) -> Dict[str, Any]:
        """Get Inspector findings with optional filters.

        Read-only: inspector2:ListFindings
        Limit: max 25 findings per request
        """
        params = params or {}
        severity = params.get("severity", "")
        max_results = min(params.get("max_results", INSPECTOR_MAX_RESULTS), INSPECTOR_MAX_RESULTS)

        client = self._iam_manager.get_client("inspector2")
        if not client:
            return {"error": "Inspector client not available."}

        try:
            filter_criteria = {}
            if severity:
                filter_criteria["severity"] = [{"comparison": "EQUALS", "value": severity.upper()}]

            kwargs = {"maxResults": max_results}
            if filter_criteria:
                kwargs["filterCriteria"] = filter_criteria

            response = client.list_findings(**kwargs)
            findings = []
            for f in response.get("findings", []):
                findings.append({
                    "finding_arn": f.get("findingArn", ""),
                    "type": f.get("type", ""),
                    "severity": f.get("severity", ""),
                    "title": f.get("title", ""),
                    "description": f.get("description", "")[:200],
                    "resource_type": f.get("resources", [{}])[0].get("type", "") if f.get("resources") else "",
                    "resource_id": f.get("resources", [{}])[0].get("id", "") if f.get("resources") else "",
                    "status": f.get("status", ""),
                    "first_observed": f.get("firstObservedAt", ""),
                    "last_observed": f.get("lastObservedAt", ""),
                })

            return {
                "findings": findings,
                "total_returned": len(findings),
                "response_source": "Live AWS Read-Only Query",
            }
        except Exception as e:
            return {"error": f"Failed to get Inspector findings: {e}"}
