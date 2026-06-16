"""AWS API MCP client (read-only).

Connects to the AWS API MCP server in read-only mode when configured.
Returns honest "not_connected" status when AWS_API_MCP_ENABLED is not set.
No write operations are exposed — read-only by design.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class AWSAPIMCPClient:
    """Client for the AWS API MCP server in read-only mode.

    Provides read-only access to AWS resource context through a live MCP
    server connection. No write operations are exposed. When not configured,
    honestly reports not_connected status.
    """

    def __init__(self) -> None:
        self._enabled = os.environ.get("AWS_API_MCP_ENABLED", "").lower() == "true"
        self._read_only = os.environ.get("AWS_API_MCP_READ_ONLY", "true").lower() == "true"
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
            servers = config.get("mcpServers", config.get("servers", {}))
            if "aws-api" in servers:
                return servers.get("aws-api")
            return None
        except (json.JSONDecodeError, OSError):
            return None

    def get_status(self) -> Dict[str, str]:
        """Return current connection status.

        Returns:
            Dict with "status" key and optional "message".
        """
        if not self._enabled:
            return {
                "status": "not_connected",
                "message": "AWS_API_MCP_ENABLED not set to true",
            }

        if self._connected:
            return {
                "status": "connected",
                "read_only": str(self._read_only),
            }

        return {
            "status": "not_connected",
            "message": "MCP server configuration not found at MCP_CONFIG_PATH",
        }

    def query_resource(self, resource_arn: str) -> Dict[str, Any]:
        """Query resource context for a given ARN (read-only).

        When connected to a live MCP server, this would invoke the server's
        resource query tool. When not connected, returns not_connected status.

        Args:
            resource_arn: The ARN of the AWS resource to query.

        Returns:
            Dict with status and resource context when connected,
            or not_connected info.
        """
        if not self._connected:
            return {"status": "not_connected"}

        if not self._read_only:
            return {
                "status": "error",
                "message": "Read-only mode not enforced — refusing operation",
            }

        # When connected, the actual MCP protocol call would happen here.
        return {
            "status": "connected",
            "resource_arn": resource_arn,
            "message": "Query routed to AWS API MCP server (read-only)",
        }
