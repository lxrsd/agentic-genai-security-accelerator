"""Tool Registry — Conditional tool registration based on feature flags.

Manages which tools are available to the Bedrock Converse API based on
the current FeatureFlags configuration. Always registers posture tools.
Conditionally registers investigation, planning, and execution tools
when their respective flags are enabled.

Phase 1: Only posture tools are implemented. Investigation/planning/execution
tool definitions are placeholders that will be populated in later phases.
"""

import logging
from typing import Any, Dict, List

from backend.feature_flags import FeatureFlags

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Conditional tool registry for Bedrock Converse API.

    Registers tools based on active feature flags. Provides tool definitions
    for the Converse API and routes tool execution to appropriate handlers.
    """

    def __init__(self, feature_flags: FeatureFlags, posture_tools: object = None, investigation_tools: object = None, planning_tools: object = None):
        """Initialize with feature flags and tool handler references.

        Args:
            feature_flags: Current feature flag configuration.
            posture_tools: The MCPServer instance for posture data queries.
            investigation_tools: InvestigationTools instance for live AWS queries.
            planning_tools: PlanningTools instance for remediation planning.
        """
        self._flags = feature_flags
        self._posture_tools = posture_tools
        self._investigation_tools = investigation_tools
        self._planning_tools = planning_tools
        self._registered_tools: Dict[str, Dict[str, Any]] = {}
        self._register_tools()

    def _register_tools(self) -> None:
        """Register tools based on feature flags."""
        # Always register posture tools (Level 1 — existing)
        self._register_posture_tools()

        # Conditionally register investigation tools (Level 2-3)
        if self._flags.investigation_tools_enabled:
            self._register_investigation_tools()

        # Conditionally register planning tools (Level 4)
        if self._flags.remediation_planning_enabled:
            self._register_planning_tools()

        # Conditionally register execution tools (Level 5)
        if self._flags.remediation_execution_enabled:
            self._register_execution_tools()

        logger.info(
            "Tool registry initialized: %d tools registered (mode: %s)",
            len(self._registered_tools),
            self._flags.get_capability_mode(),
        )

    def _register_posture_tools(self) -> None:
        """Register the 5 existing posture data tools (always available)."""
        posture_tools = [
            {
                "name": "get_posture_score",
                "description": "Get the overall security posture score and area breakdown",
                "category": "posture",
                "inputSchema": {"json": {"type": "object", "properties": {}}},
            },
            {
                "name": "get_top_gaps",
                "description": "Get top security gaps sorted by severity",
                "category": "posture",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "limit": {"type": "integer", "description": "Max gaps to return", "default": 5}
                        },
                    }
                },
            },
            {
                "name": "get_remediation_plan",
                "description": "Get prioritized remediation actions (planning-only)",
                "category": "posture",
                "inputSchema": {"json": {"type": "object", "properties": {}}},
            },
            {
                "name": "simulate_improvement",
                "description": "Simulate what the score would be after fixing specific findings",
                "category": "posture",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_ids": {"type": "array", "items": {"type": "string"}, "description": "Finding IDs to remediate"}
                        },
                        "required": ["finding_ids"],
                    }
                },
            },
            {
                "name": "explain_area_score",
                "description": "Explain score for a specific security area",
                "category": "posture",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "area_name": {"type": "string", "description": "Security area name"}
                        },
                        "required": ["area_name"],
                    }
                },
            },
        ]
        for tool in posture_tools:
            self._registered_tools[tool["name"]] = tool

    def _register_investigation_tools(self) -> None:
        """Register investigation tools (Level 2-3) when INVESTIGATION_TOOLS_ENABLED=true."""
        investigation_tools = [
            {
                "name": "list_iam_users",
                "description": "List IAM users with creation date, last activity, and attached policy count",
                "category": "investigation",
                "inputSchema": {"json": {"type": "object", "properties": {}}},
            },
            {
                "name": "get_iam_user_details",
                "description": "Get detailed info for a specific IAM user including policies, access keys (masked), MFA status, and groups",
                "category": "investigation",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {"username": {"type": "string", "description": "IAM username to inspect"}},
                        "required": ["username"],
                    }
                },
            },
            {
                "name": "list_iam_roles",
                "description": "List IAM roles with basic metadata",
                "category": "investigation",
                "inputSchema": {"json": {"type": "object", "properties": {}}},
            },
            {
                "name": "describe_s3_bucket",
                "description": "Get S3 bucket security configuration (encryption, public access block, versioning, logging)",
                "category": "investigation",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {"bucket_name": {"type": "string", "description": "S3 bucket name"}},
                        "required": ["bucket_name"],
                    }
                },
            },
            {
                "name": "list_s3_buckets_security_summary",
                "description": "List S3 buckets with security status (encryption, public access block)",
                "category": "investigation",
                "inputSchema": {"json": {"type": "object", "properties": {}}},
            },
            {
                "name": "describe_security_group",
                "description": "Describe security group inbound/outbound rules and VPC",
                "category": "investigation",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {"group_id": {"type": "string", "description": "Security group ID (optional, lists all if empty)"}},
                    }
                },
            },
            {
                "name": "lookup_cloudtrail_events",
                "description": "Lookup recent CloudTrail events. Default last 24 hours, max 90 days, max 50 events. Supports username, event_name, event_source filters.",
                "category": "investigation",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "hours": {"type": "integer", "description": "Lookback hours (default 24, max 2160)", "default": 24},
                            "username": {"type": "string", "description": "Filter by IAM username"},
                            "event_name": {"type": "string", "description": "Filter by event name (e.g., CreateUser, PutBucketPolicy)"},
                            "event_source": {"type": "string", "description": "Filter by event source (e.g., iam.amazonaws.com)"},
                            "max_results": {"type": "integer", "description": "Max events to return (max 50)", "default": 20},
                        },
                    }
                },
            },
            {
                "name": "get_security_hub_findings",
                "description": "Get active Security Hub findings with optional severity and resource type filters. Max 25 per request.",
                "category": "investigation",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"},
                            "resource_type": {"type": "string", "description": "Filter by resource type (e.g., AwsS3Bucket, AwsEc2Instance)"},
                            "max_results": {"type": "integer", "description": "Max findings (max 25)", "default": 10},
                        },
                    }
                },
            },
            {
                "name": "get_guardduty_findings",
                "description": "Get GuardDuty threat detection findings with optional severity filter. Max 25 per request.",
                "category": "investigation",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string", "description": "Filter by severity: low, medium, high"},
                            "max_results": {"type": "integer", "description": "Max findings (max 25)", "default": 10},
                        },
                    }
                },
            },
            {
                "name": "get_inspector_findings",
                "description": "Get Inspector vulnerability findings with optional severity filter. Max 25 per request.",
                "category": "investigation",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "severity": {"type": "string", "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"},
                            "max_results": {"type": "integer", "description": "Max findings (max 25)", "default": 10},
                        },
                    }
                },
            },
        ]
        for tool in investigation_tools:
            self._registered_tools[tool["name"]] = tool

    def _register_planning_tools(self) -> None:
        """Register planning tools (Level 4) when REMEDIATION_PLANNING_ENABLED=true."""
        planning_tools = [
            {
                "name": "generate_remediation_plan",
                "description": "Generate a complete remediation plan for a finding including risk category, blast radius, implementation steps, prerequisites, rollback plan, and AWS documentation links",
                "category": "planning",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_title": {"type": "string", "description": "Title of the finding to remediate"},
                            "check_id": {"type": "string", "description": "Check/control ID (e.g., s3_bucket_public_access)"},
                            "resource_arn": {"type": "string", "description": "Affected resource ARN"},
                            "service": {"type": "string", "description": "AWS service (e.g., s3, iam, ec2)"},
                            "pillar": {"type": "string", "description": "Security area (e.g., Data Protection)"},
                        },
                        "required": ["finding_title"],
                    }
                },
            },
            {
                "name": "estimate_score_impact",
                "description": "Estimate posture score improvement from remediating specific findings",
                "category": "planning",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_ids": {"type": "array", "items": {"type": "string"}, "description": "Finding IDs to simulate remediation for"},
                        },
                        "required": ["finding_ids"],
                    }
                },
            },
            {
                "name": "generate_aws_cli_commands",
                "description": "Generate AWS CLI commands for a remediation action (for review only — NOT executed)",
                "category": "planning",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_title": {"type": "string", "description": "Title of the finding"},
                            "check_id": {"type": "string", "description": "Check/control ID"},
                            "resource_arn": {"type": "string", "description": "Affected resource ARN"},
                            "bucket_name": {"type": "string", "description": "S3 bucket name if applicable"},
                            "group_id": {"type": "string", "description": "Security group ID if applicable"},
                        },
                        "required": ["finding_title"],
                    }
                },
            },
            {
                "name": "generate_terraform_patch",
                "description": "Generate Terraform HCL configuration patch for a remediation",
                "category": "planning",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_title": {"type": "string", "description": "Title of the finding"},
                            "check_id": {"type": "string", "description": "Check/control ID"},
                            "resource_name": {"type": "string", "description": "Terraform resource name", "default": "example"},
                        },
                        "required": ["finding_title"],
                    }
                },
            },
            {
                "name": "generate_cloudformation_patch",
                "description": "Generate CloudFormation YAML patch for a remediation",
                "category": "planning",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_title": {"type": "string", "description": "Title of the finding"},
                            "check_id": {"type": "string", "description": "Check/control ID"},
                            "resource_name": {"type": "string", "description": "CloudFormation resource name", "default": "ExampleResource"},
                        },
                        "required": ["finding_title"],
                    }
                },
            },
            {
                "name": "generate_rollback_plan",
                "description": "Generate a rollback plan with specific CLI commands to revert a remediation",
                "category": "planning",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_title": {"type": "string", "description": "Title of the finding"},
                            "check_id": {"type": "string", "description": "Check/control ID"},
                        },
                        "required": ["finding_title"],
                    }
                },
            },
            {
                "name": "validate_remediation_safety",
                "description": "Validate whether a remediation is safe to execute. Returns risk category, blast radius, allowlist status, and safety verdict (SAFE/CAUTION/BLOCKED)",
                "category": "planning",
                "inputSchema": {
                    "json": {
                        "type": "object",
                        "properties": {
                            "finding_title": {"type": "string", "description": "Title of the finding"},
                            "check_id": {"type": "string", "description": "Check/control ID"},
                            "action": {"type": "string", "description": "AWS API action (e.g., s3:PutPublicAccessBlock)"},
                        },
                        "required": ["finding_title"],
                    }
                },
            },
        ]
        for tool in planning_tools:
            self._registered_tools[tool["name"]] = tool

    def _register_execution_tools(self) -> None:
        """Register execution tools (Phase 5/6 — placeholder for now)."""
        # Phase 5/6 will populate these with real tool definitions
        # Execution tools are NEVER registered unless REMEDIATION_EXECUTION_ENABLED=true
        pass

    def get_converse_tool_definitions(self) -> List[Dict[str, Any]]:
        """Build Converse API toolConfig list from registered tools.

        Returns:
            List of tool definitions in Bedrock Converse API format.
        """
        tools = []
        for tool in self._registered_tools.values():
            tools.append({
                "toolSpec": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "inputSchema": tool["inputSchema"],
                }
            })
        return tools

    def get_registered_tool_names(self) -> List[str]:
        """Return names of all currently registered tools."""
        return list(self._registered_tools.keys())

    def get_registered_tool_count(self) -> int:
        """Return count of registered tools."""
        return len(self._registered_tools)

    def get_tools_by_category(self) -> Dict[str, List[str]]:
        """Return tool names grouped by category."""
        categories: Dict[str, List[str]] = {}
        for tool in self._registered_tools.values():
            cat = tool.get("category", "unknown")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tool["name"])
        return categories

    def is_tool_registered(self, tool_name: str) -> bool:
        """Check if a specific tool is registered."""
        return tool_name in self._registered_tools

    def execute_tool(self, tool_name: str, tool_input: Dict) -> Any:
        """Route tool execution to appropriate handler.

        Args:
            tool_name: Name of the tool to execute.
            tool_input: Input parameters for the tool.

        Returns:
            Tool execution result (dict or error).
        """
        if not self.is_tool_registered(tool_name):
            return {"error": f"Tool '{tool_name}' is not registered in current capability mode."}

        tool = self._registered_tools[tool_name]
        category = tool.get("category", "unknown")

        if category == "posture":
            return self._execute_posture_tool(tool_name, tool_input)
        elif category == "investigation":
            return self._execute_investigation_tool(tool_name, tool_input)
        elif category == "planning":
            return self._execute_planning_tool(tool_name, tool_input)
        elif category == "execution":
            return {"error": "Execution tools not yet implemented (Phase 5/6)."}
        else:
            return {"error": f"Unknown tool category: {category}"}

    def _execute_posture_tool(self, tool_name: str, tool_input: Dict) -> Any:
        """Execute a posture data tool against local posture data."""
        if self._posture_tools is None:
            return {"error": "Posture tools not available."}

        try:
            if tool_name == "get_posture_score":
                return self._posture_tools.get_overall_posture_score()
            elif tool_name == "get_top_gaps":
                limit = tool_input.get("limit", 5)
                gaps = self._posture_tools.get_top_security_gaps(limit=limit)
                return {"gaps": gaps}
            elif tool_name == "get_remediation_plan":
                plan = self._posture_tools.get_remediation_plan()
                return {"actions": plan}
            elif tool_name == "simulate_improvement":
                finding_ids = tool_input.get("finding_ids", [])
                return self._posture_tools.simulate_score_improvement(finding_ids)
            elif tool_name == "explain_area_score":
                area_name = tool_input.get("area_name", "")
                return self._posture_tools.explain_score(pillar=area_name)
            else:
                return {"error": f"Unknown posture tool: {tool_name}"}
        except Exception as e:
            return {"error": str(e)}

    def _execute_investigation_tool(self, tool_name: str, tool_input: Dict) -> Any:
        """Execute a read-only investigation tool against live AWS."""
        if self._investigation_tools is None:
            return {"error": "Investigation tools not available. Check AWS credentials and INVESTIGATION_TOOLS_ENABLED flag."}

        # Route to the appropriate method on InvestigationTools
        method_map = {
            "list_iam_users": self._investigation_tools.list_iam_users,
            "get_iam_user_details": self._investigation_tools.get_iam_user_details,
            "list_iam_roles": self._investigation_tools.list_iam_roles,
            "describe_s3_bucket": self._investigation_tools.describe_s3_bucket,
            "list_s3_buckets_security_summary": self._investigation_tools.list_s3_buckets_security_summary,
            "describe_security_group": self._investigation_tools.describe_security_group,
            "lookup_cloudtrail_events": self._investigation_tools.lookup_cloudtrail_events,
            "get_security_hub_findings": self._investigation_tools.get_security_hub_findings,
            "get_guardduty_findings": self._investigation_tools.get_guardduty_findings,
            "get_inspector_findings": self._investigation_tools.get_inspector_findings,
        }

        handler = method_map.get(tool_name)
        if not handler:
            return {"error": f"Unknown investigation tool: {tool_name}"}

        try:
            return handler(tool_input)
        except Exception as e:
            return {"error": f"Investigation tool '{tool_name}' failed: {e}"}

    def _execute_planning_tool(self, tool_name: str, tool_input: Dict) -> Any:
        """Execute a planning tool (generates guidance, no AWS mutations)."""
        if self._planning_tools is None:
            return {"error": "Planning tools not available. Check REMEDIATION_PLANNING_ENABLED flag."}

        method_map = {
            "generate_remediation_plan": self._planning_tools.generate_remediation_plan,
            "estimate_score_impact": self._planning_tools.estimate_score_impact,
            "generate_aws_cli_commands": self._planning_tools.generate_aws_cli_commands,
            "generate_terraform_patch": self._planning_tools.generate_terraform_patch,
            "generate_cloudformation_patch": self._planning_tools.generate_cloudformation_patch,
            "generate_rollback_plan": self._planning_tools.generate_rollback_plan,
            "validate_remediation_safety": self._planning_tools.validate_remediation_safety,
        }

        handler = method_map.get(tool_name)
        if not handler:
            return {"error": f"Unknown planning tool: {tool_name}"}

        try:
            return handler(tool_input)
        except Exception as e:
            return {"error": f"Planning tool '{tool_name}' failed: {e}"}
