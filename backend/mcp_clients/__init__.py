"""MCP client connections for external AWS MCP servers.

This module manages connections to live AWS MCP servers (Knowledge, API, IAM).
When not configured, each client honestly reports "not_connected" status.
No fake data. No mocked responses.
"""

from backend.mcp_clients.connection_manager import MCPConnectionManager
from backend.mcp_clients.aws_knowledge_mcp_client import AWSKnowledgeMCPClient
from backend.mcp_clients.aws_api_mcp_client import AWSAPIMCPClient
from backend.mcp_clients.iam_mcp_client import IAMMCPClient

__all__ = [
    "MCPConnectionManager",
    "AWSKnowledgeMCPClient",
    "AWSAPIMCPClient",
    "IAMMCPClient",
]
