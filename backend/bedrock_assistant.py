"""Amazon Bedrock Assistant — real integration using boto3 Converse API.

Uses local posture data via tool use / function calling for finding context.
Uses external AWS MCP clients for AWS best-practice guidance.
Shows "Not connected" when Bedrock is not configured — never fakes answers.
"""

import json
import os
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BedrockAssistant:
    """Real Amazon Bedrock assistant using Converse API with tool use.

    When BEDROCK_ENABLED=true and AWS credentials are available:
      - Uses boto3 bedrock-runtime client
      - Sends user questions with posture data context
      - Defines tools for accessing local posture data
      - Returns AI-generated answers grounded in real findings

    When not configured:
      - Returns "Not connected" status
      - Does NOT generate fake answers
    """

    def __init__(
        self,
        posture_tools: object,
        mcp_connection_manager: object = None,
        model_id: str = None,
        region: str = None,
    ):
        """Initialize Bedrock assistant with model discovery and fallback.

        Args:
            posture_tools: Object with posture data methods (get scores, gaps, etc.)
            mcp_connection_manager: MCPConnectionManager for AWS MCP status
            model_id: Bedrock model ID (default from env BEDROCK_MODEL_ID)
            region: AWS region (default from env AWS_REGION)
        """
        self._posture_tools = posture_tools
        self._mcp_manager = mcp_connection_manager

        self._enabled = os.environ.get("BEDROCK_ENABLED", "false").lower() == "true"
        self._configured_model_id = model_id or os.environ.get("BEDROCK_MODEL_ID", "")
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._model_id = self._configured_model_id  # Will be updated by discovery
        self._active_model_id: Optional[str] = None
        self._discovery_result: Dict[str, Any] = {}

        self._client = None
        if self._enabled:
            self._init_client_with_discovery()

    def _init_client_with_discovery(self):
        """Initialize Bedrock client with model discovery and fallback."""
        try:
            import boto3
            from backend.bedrock_model_discovery import select_best_available_model

            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self._region,
            )

            # Discover a working model
            active_model, result = select_best_available_model(
                preferred_model_id=self._configured_model_id,
                region=self._region,
            )

            self._discovery_result = result
            self._active_model_id = active_model

            if active_model:
                self._model_id = active_model
                logger.info(
                    "Bedrock ready (model: %s, region: %s)%s",
                    active_model,
                    self._region,
                    " [fallback]" if result.get("is_fallback") else "",
                )
            else:
                logger.warning(
                    "Bedrock model discovery failed: %s",
                    result.get("message", "No model available"),
                )
                self._client = None  # Mark as not connected
        except ImportError:
            logger.warning("boto3 not installed — Bedrock unavailable")
            self._client = None
            self._discovery_result = {"status": "misconfigured", "message": "boto3 not installed"}
        except Exception as e:
            logger.warning("Failed to initialize Bedrock: %s", e)
            self._client = None
            self._discovery_result = {"status": "not_connected", "message": str(e)}

    @property
    def is_connected(self) -> bool:
        """Check if Bedrock is configured and client is available."""
        return self._enabled and self._client is not None

    def get_status(self) -> Dict[str, str]:
        """Get connection status with model discovery details."""
        if not self._enabled:
            return {
                "status": "not_connected",
                "message": "Bedrock not configured. Set BEDROCK_ENABLED=true and configure AWS credentials.",
            }
        if self._client is None or self._active_model_id is None:
            dr = self._discovery_result
            return {
                "status": dr.get("status", "not_connected"),
                "message": dr.get("message", "Bedrock model discovery failed"),
                "fix": dr.get("fix", ""),
                "configured_model_id": self._configured_model_id,
                "region": self._region,
            }
        return {
            "status": "connected",
            "message": f"Bedrock connected (model: {self._active_model_id}, region: {self._region})",
            "active_model_id": self._active_model_id,
            "configured_model_id": self._configured_model_id,
            "is_fallback": self._discovery_result.get("is_fallback", False),
            "region": self._region,
        }

    def respond(self, user_message: str) -> str:
        """Generate a response using Bedrock Converse API.

        If not connected: returns "Not connected" message.
        If connected: sends the question to Bedrock with posture context.
        """
        if not self.is_connected:
            status = self.get_status()
            return f"[Bedrock Not Connected] {status['message']}"

        try:
            return self._converse(user_message)
        except Exception as e:
            logger.error("Bedrock Converse API error: %s", e)
            return f"[Bedrock Error] An error occurred while processing your question: {e}"

    def _converse(self, user_message: str) -> str:
        """Send a message to Bedrock using the Converse API with tool use."""
        # Build posture context
        posture_context = self._build_posture_context()

        # Build system prompt
        system_prompt = self._build_system_prompt()

        # Build tool definitions for Bedrock
        tools = self._build_tool_definitions()

        # Initial user message with posture context
        messages = [
            {
                "role": "user",
                "content": [
                    {
                        "text": (
                            f"Context about the customer's current security posture:\n"
                            f"{posture_context}\n\n"
                            f"Customer question: {user_message}"
                        )
                    }
                ],
            }
        ]

        # Call Converse API
        converse_kwargs = {
            "modelId": self._model_id,
            "system": [{"text": system_prompt}],
            "messages": messages,
        }
        if tools:
            converse_kwargs["toolConfig"] = {"tools": tools}

        response = self._client.converse(**converse_kwargs)

        # Handle response — may include tool use
        return self._process_response(response, messages)

    def _build_system_prompt(self) -> str:
        """Build the system prompt for Bedrock."""
        mcp_status = ""
        if self._mcp_manager:
            try:
                # Only check external AWS MCP servers — not internal services
                aws_mcp_services = ["aws_knowledge_mcp", "aws_api_mcp", "iam_mcp"]
                all_status = self._mcp_manager.get_all_status()
                connected_mcps = [
                    k
                    for k in aws_mcp_services
                    if k in all_status
                    and isinstance(all_status[k], dict)
                    and all_status[k].get("status") == "connected"
                ]
                if connected_mcps:
                    mcp_status = (
                        f"Connected AWS MCP servers: {', '.join(connected_mcps)}. "
                        "Use these for AWS best-practice guidance."
                    )
                else:
                    mcp_status = (
                        "No AWS MCP servers are connected. Answer based on posture data only. "
                        "Note that AWS best-practice guidance requires AWS MCP configuration."
                    )
            except Exception:
                mcp_status = "Unable to determine AWS MCP connection status."

        return (
            "You are a security posture assistant for the Agentic GenAI Security Accelerator. "
            "You help customers understand their AWS security posture score, explain findings, "
            "recommend remediation actions, and simulate score improvements.\n\n"
            "IMPORTANT RULES:\n"
            "- All remediation recommendations are PLANNING-ONLY. No AWS changes are executed.\n"
            "- Never invent findings or scores. Use only the provided posture data.\n"
            "- Never claim remediation was executed.\n"
            "- If asked about AWS best practices, use AWS MCP guidance when available.\n"
            f"- {mcp_status}\n"
            "- Be concise and actionable in your responses.\n"
            "- Reference specific finding IDs when discussing gaps.\n"
        )

    def _build_posture_context(self) -> str:
        """Build a concise posture data context string."""
        try:
            score_data = self._posture_tools.get_overall_posture_score()
            areas_data = self._posture_tools.get_domain_scores()
            gaps_data = self._posture_tools.get_top_security_gaps(limit=5)

            lines = [
                f"Overall Score: {score_data['overall_score']}/5.0 ({score_data['score_label']})",
                f"Total Findings: {score_data['total_findings']} ({score_data['total_passed']} passed, {score_data['total_failed']} failed)",
                f"Evaluated Areas: {score_data.get('evaluated_area_count', 5)}/5",
                "",
                "Area Scores:",
            ]

            for area in areas_data.get("pillars", []):
                if area.get("is_evaluated", True):
                    lines.append(f"  - {area['name']}: {area['score']}/5.0")
                else:
                    lines.append(f"  - {area['name']}: Not Evaluated")

            lines.append("")
            lines.append("Top Gaps:")
            for gap in gaps_data[:5]:
                lines.append(
                    f"  - [{gap['severity']}] {gap['title']} ({gap['pillar']})"
                )

            return "\n".join(lines)
        except Exception as e:
            return f"Error loading posture context: {e}"

    def _build_tool_definitions(self) -> List[Dict[str, Any]]:
        """Build tool definitions for the Converse API.

        These allow Bedrock to call back into our posture data.
        """
        return [
            {
                "toolSpec": {
                    "name": "get_posture_score",
                    "description": "Get the overall security posture score and area breakdown",
                    "inputSchema": {"json": {"type": "object", "properties": {}}},
                }
            },
            {
                "toolSpec": {
                    "name": "get_top_gaps",
                    "description": "Get top security gaps sorted by severity",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "limit": {
                                    "type": "integer",
                                    "description": "Max gaps to return",
                                    "default": 5,
                                }
                            },
                        }
                    },
                }
            },
            {
                "toolSpec": {
                    "name": "get_remediation_plan",
                    "description": "Get prioritized remediation actions (planning-only)",
                    "inputSchema": {"json": {"type": "object", "properties": {}}},
                }
            },
            {
                "toolSpec": {
                    "name": "simulate_improvement",
                    "description": "Simulate what the score would be after fixing specific findings",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "finding_ids": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                    "description": "Finding IDs to remediate",
                                }
                            },
                            "required": ["finding_ids"],
                        }
                    },
                }
            },
            {
                "toolSpec": {
                    "name": "explain_area_score",
                    "description": "Explain score for a specific security area",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {
                                "area_name": {
                                    "type": "string",
                                    "description": "Security area name",
                                }
                            },
                            "required": ["area_name"],
                        }
                    },
                }
            },
        ]

    def _process_response(self, response: Dict, messages: List) -> str:
        """Process the Converse API response, handling tool use if needed."""
        output = response.get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])

        # Check for tool use
        tool_uses = [b for b in content_blocks if "toolUse" in b]

        if tool_uses:
            # Handle tool calls
            messages.append(message)
            tool_results = []

            for block in tool_uses:
                tool_use = block["toolUse"]
                tool_name = tool_use["name"]
                tool_input = tool_use.get("input", {})
                tool_id = tool_use["toolUseId"]

                result = self._execute_tool(tool_name, tool_input)
                tool_results.append(
                    {
                        "toolResult": {
                            "toolUseId": tool_id,
                            "content": [{"json": result}],
                        }
                    }
                )

            # Send tool results back to Bedrock
            messages.append({"role": "user", "content": tool_results})

            follow_up = self._client.converse(
                modelId=self._model_id,
                system=[{"text": self._build_system_prompt()}],
                messages=messages,
                toolConfig={"tools": self._build_tool_definitions()},
            )

            return self._extract_text(follow_up)

        # No tool use — return text directly
        return self._extract_text(response)

    def _execute_tool(self, tool_name: str, tool_input: Dict) -> Any:
        """Execute a tool call against local posture data.
        
        Returns a dict (Bedrock Converse API requires tool results to be JSON objects).
        """
        try:
            if tool_name == "get_posture_score":
                return self._posture_tools.get_overall_posture_score()
            elif tool_name == "get_top_gaps":
                limit = tool_input.get("limit", 5)
                gaps = self._posture_tools.get_top_security_gaps(limit=limit)
                return {"gaps": gaps}  # Wrap list in object for Bedrock
            elif tool_name == "get_remediation_plan":
                plan = self._posture_tools.get_remediation_plan()
                return {"actions": plan}  # Wrap list in object for Bedrock
            elif tool_name == "simulate_improvement":
                finding_ids = tool_input.get("finding_ids", [])
                return self._posture_tools.simulate_score_improvement(finding_ids)
            elif tool_name == "explain_area_score":
                area_name = tool_input.get("area_name", "")
                return self._posture_tools.explain_score(pillar=area_name)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            return {"error": str(e)}

    def _extract_text(self, response: Dict) -> str:
        """Extract text content from a Converse API response."""
        output = response.get("output", {})
        message = output.get("message", {})
        content_blocks = message.get("content", [])

        text_parts = []
        for block in content_blocks:
            if "text" in block:
                text_parts.append(block["text"])

        return "\n".join(text_parts) if text_parts else "No response generated."
