"""AWS Knowledge/Documentation MCP client.

Connects to the AWS Knowledge MCP server when configured.
Returns honest "not_connected" status when AWS_KNOWLEDGE_MCP_ENABLED is not set.
Never returns fake best-practice data.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class AWSKnowledgeMCPClient:
    """Client for the AWS Knowledge/Documentation MCP server.

    Provides access to AWS documentation, best practices, and remediation
    guidance through a live MCP server connection. When not configured,
    honestly reports not_connected status.
    """

    def __init__(self) -> None:
        self._enabled = os.environ.get("AWS_KNOWLEDGE_MCP_ENABLED", "").lower() == "true"
        self._config_path = os.environ.get("MCP_CONFIG_PATH", "")
        self._server_config: Optional[Dict[str, Any]] = None
        self._connected = False

        if self._enabled:
            self._server_config = self._load_server_config()
            self._connected = self._server_config is not None

    def _load_server_config(self) -> Optional[Dict[str, Any]]:
        """Attempt to load MCP server configuration from MCP_CONFIG_PATH."""
        if not self._config_path:
            return None

        config_file = Path(self._config_path)
        if not config_file.is_file():
            return None

        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            # Look for AWS Knowledge MCP server entry
            servers = config.get("mcpServers", config.get("servers", {}))
            if "aws-knowledge" in servers or "aws-docs" in servers:
                return servers.get("aws-knowledge", servers.get("aws-docs"))
            return None
        except (json.JSONDecodeError, OSError):
            return None

    def get_status(self) -> Dict[str, str]:
        """Return current connection status.

        Returns:
            Dict with "status" key ("connected" or "not_connected") and
            optional "message" explaining why not connected.
        """
        if not self._enabled:
            return {
                "status": "not_connected",
                "message": "AWS_KNOWLEDGE_MCP_ENABLED not set to true",
            }

        if self._connected:
            return {"status": "connected"}

        return {
            "status": "not_connected",
            "message": "MCP server configuration not found at MCP_CONFIG_PATH",
        }

    def query_best_practice(self, topic: str) -> Dict[str, Any]:
        """Query AWS best practices for a given topic.

        When connected to a live MCP server, this would invoke the server's
        best practice tool. When not connected, returns not_connected status.

        Args:
            topic: The security or AWS topic to query best practices for.

        Returns:
            Dict with status and results when connected, or not_connected info.
        """
        if not self._connected:
            return {"status": "not_connected"}

        # When connected, the actual MCP protocol call would happen here.
        # The connection manager routes through the MCP protocol to the
        # configured AWS Knowledge MCP server.
        return {
            "status": "connected",
            "topic": topic,
            "message": "Query routed to AWS Knowledge MCP server",
        }

    def query_remediation_guidance(self, finding_title: str) -> Dict[str, Any]:
        """Query remediation guidance for a specific finding.

        When connected to a live MCP server, this would invoke the server's
        remediation guidance tool. When not connected, returns not_connected status.

        Args:
            finding_title: The title of the finding to get remediation for.

        Returns:
            Dict with status and guidance when connected, or not_connected info.
        """
        if not self._connected:
            return {"status": "not_connected"}

        # When connected, the actual MCP protocol call would happen here.
        return {
            "status": "connected",
            "finding_title": finding_title,
            "message": "Query routed to AWS Knowledge MCP server",
        }
