"""MCP Connection Manager — single source of truth for all connection states.

Reads configuration from environment variables AND from the MCP config file
(MCP_CONFIG_PATH). Determines real connection status by verifying that server
binaries are available on the system, not just checking env var flags.

On startup, if AWS Knowledge MCP is enabled and the command is available,
attempts to start it as a subprocess and perform a basic health check.
"""

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.mcp_clients.aws_knowledge_mcp_client import AWSKnowledgeMCPClient
from backend.mcp_clients.aws_api_mcp_client import AWSAPIMCPClient
from backend.mcp_clients.iam_mcp_client import IAMMCPClient

logger = logging.getLogger(__name__)


# Mapping from config server keys to env var names and display names
SERVER_REGISTRY = {
    "aws-knowledge": {
        "env_enabled": "AWS_KNOWLEDGE_MCP_ENABLED",
        "display_name": "AWS Knowledge MCP",
    },
    "aws-api": {
        "env_enabled": "AWS_API_MCP_ENABLED",
        "env_read_only": "AWS_API_MCP_READ_ONLY",
        "display_name": "AWS API MCP",
    },
    "iam": {
        "env_enabled": "IAM_MCP_ENABLED",
        "env_read_only": "IAM_MCP_READ_ONLY",
        "display_name": "IAM MCP",
    },
    "cloudtrail": {
        "env_enabled": "CLOUDTRAIL_MCP_ENABLED",
        "display_name": "CloudTrail MCP",
    },
    "securityhub": {
        "env_enabled": "SECURITYHUB_MCP_ENABLED",
        "display_name": "Security Hub MCP",
    },
}


class MCPConnectionManager:
    """Central manager for all MCP and service connection states.

    This is the single source of truth for connection status across:
    - Prowler data (loaded sample or custom)
    - Posture Data MCP (built-in, always available when findings loaded)
    - Amazon Bedrock (requires BEDROCK_ENABLED=true)
    - AWS MCP servers (configured via mcp_config.json + env vars)

    Status values:
    - "disabled" — enabled=false in config or env var not set
    - "misconfigured" — enabled but config is invalid/missing required fields
    - "not_connected" — enabled and configured but server not reachable
    - "connected" — enabled, configured, and server binary is available
    - "error" — connection attempt failed with specific error message
    """

    def __init__(self, findings_count: int = 0, data_source: str = "sample-data") -> None:
        """Initialize the connection manager.

        Args:
            findings_count: Number of Prowler findings currently loaded.
            data_source: Source description (e.g., "sample-data" or custom path).
        """
        self._findings_count = findings_count
        self._data_source = data_source

        # Environment-driven config
        self._aws_mcp_enabled = os.environ.get("AWS_MCP_ENABLED", "").lower() == "true"
        self._bedrock_enabled = os.environ.get("BEDROCK_ENABLED", "").lower() == "true"
        self._bedrock_model_id = os.environ.get("BEDROCK_MODEL_ID", "")
        self._aws_region = os.environ.get("AWS_REGION", "")

        # Load MCP config file
        self._config_path = os.environ.get("MCP_CONFIG_PATH", "mcp_config.json")
        self._server_configs: Dict[str, Dict[str, Any]] = {}
        self._config_load_error: Optional[str] = None
        self._load_config()

        # Instantiate individual clients (for backward compatibility)
        self._aws_knowledge_client = AWSKnowledgeMCPClient()
        self._aws_api_client = AWSAPIMCPClient()
        self._iam_client = IAMMCPClient()

        # Auto-start health check results
        self._health_check_results: Dict[str, str] = {}
        self._attempt_auto_start()

        # Runtime auto-enable state for account MCPs
        self._auto_enable = os.environ.get("AUTO_ENABLE_ACCOUNT_MCPS_ON_AWS_CONNECT", "true").lower() == "true"
        self._runtime_enabled_mcps: Dict[str, Dict[str, Any]] = {}
        self._aws_identity_connected = False

    def _load_config(self) -> None:
        """Load and parse the MCP configuration file."""
        config_file = Path(self._config_path)
        if not config_file.is_file():
            self._config_load_error = f"Config file not found: {self._config_path}"
            return

        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            self._server_configs = config.get("mcpServers", config.get("servers", {}))
        except json.JSONDecodeError as e:
            self._config_load_error = f"Invalid JSON in {self._config_path}: {e}"
        except OSError as e:
            self._config_load_error = f"Cannot read {self._config_path}: {e}"

    def _attempt_auto_start(self) -> None:
        """Attempt to auto-start MCP servers that are enabled and available.

        For each enabled server, spawns the process briefly to verify it
        doesn't crash immediately (basic health check). Only marks as
        'connected' after successful health check.

        Status states:
        - connected: enabled, configured, and server process starts successfully
        - disabled: not enabled in config or env
        - not_connected: enabled but server binary not available
        - misconfigured: enabled but config is invalid
        - error: connection attempt failed
        """
        for server_key, registry_entry in SERVER_REGISTRY.items():
            env_enabled = registry_entry["env_enabled"]
            server_env_enabled = os.environ.get(env_enabled, "").lower() == "true"

            if not self._aws_mcp_enabled or not server_env_enabled:
                continue

            server_config = self._server_configs.get(server_key, {})
            if not server_config.get("enabled", False):
                continue

            command = server_config.get("command", "")
            if not command or shutil.which(command) is None:
                continue

            # Attempt health check: spawn process, wait briefly, check it didn't crash
            args = server_config.get("args", [])
            full_cmd = [command] + args
            env = os.environ.copy()
            server_env = server_config.get("env", {})
            env.update(server_env)

            try:
                proc = subprocess.Popen(
                    full_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                # Wait briefly to see if it crashes immediately
                time.sleep(0.5)
                exit_code = proc.poll()

                if exit_code is None:
                    # Process is still running — health check passed
                    self._health_check_results[server_key] = "connected"
                    # Terminate the test process (we don't keep it running here)
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    logger.info(
                        "Health check passed for %s (%s)",
                        registry_entry["display_name"],
                        command,
                    )
                else:
                    # Process exited immediately — health check failed
                    self._health_check_results[server_key] = "error"
                    logger.warning(
                        "Health check failed for %s: process exited with code %d",
                        registry_entry["display_name"],
                        exit_code,
                    )
            except (OSError, subprocess.SubprocessError) as e:
                self._health_check_results[server_key] = "error"
                logger.warning(
                    "Failed to start %s for health check: %s",
                    registry_entry["display_name"],
                    e,
                )

    @property
    def aws_knowledge_client(self) -> AWSKnowledgeMCPClient:
        """Access the AWS Knowledge MCP client."""
        return self._aws_knowledge_client

    def connect_account_mcps_after_aws_identity(self, identity: Dict[str, Any] = None) -> Dict[str, Dict[str, Any]]:
        """Runtime auto-enable and connect account-aware MCPs after AWS identity verification.
        
        Called when AWS identity STS check succeeds. Attempts to connect:
        - AWS API MCP (read-only)
        - IAM MCP (read-only)
        - CloudTrail MCP
        - Security Hub MCP
        
        Does NOT modify .env. This is runtime-only for the current session.
        
        Args:
            identity: The verified AWS identity dict (account_id, arn, etc.)
            
        Returns:
            Dict mapping server keys to their connection status.
        """
        if not self._auto_enable:
            return {}
        
        self._aws_identity_connected = True
        account_mcps = ["aws-api", "iam", "cloudtrail", "securityhub"]
        results: Dict[str, Dict[str, Any]] = {}
        
        for server_key in account_mcps:
            registry_entry = SERVER_REGISTRY.get(server_key, {})
            display_name = registry_entry.get("display_name", server_key)
            env_read_only = registry_entry.get("env_read_only")
            
            # Check config file for this server
            server_config = self._server_configs.get(server_key, {})
            if not server_config:
                results[server_key] = {
                    "status": "misconfigured",
                    "enabled_source": "runtime_auto_enable",
                    "message": f"Server '{server_key}' not in mcp_config.json",
                    "fix": f"Add '{server_key}' to mcp_config.json",
                    "display_name": display_name,
                }
                self._runtime_enabled_mcps[server_key] = results[server_key]
                continue
            
            command = server_config.get("command", "")
            if not command:
                results[server_key] = {
                    "status": "misconfigured",
                    "enabled_source": "runtime_auto_enable",
                    "message": "No command specified in config",
                    "fix": f"Set command for {server_key} in mcp_config.json",
                    "display_name": display_name,
                }
                self._runtime_enabled_mcps[server_key] = results[server_key]
                continue
            
            if not shutil.which(command):
                results[server_key] = {
                    "status": "misconfigured",
                    "enabled_source": "runtime_auto_enable",
                    "message": f"Command '{command}' not found",
                    "fix": f"Install {command} (e.g., brew install uv)",
                    "display_name": display_name,
                }
                self._runtime_enabled_mcps[server_key] = results[server_key]
                continue
            
            # Attempt real health check
            args = server_config.get("args", [])
            full_cmd = [command] + args
            env = os.environ.copy()
            server_env = server_config.get("env", {})
            env.update(server_env)
            
            read_only = True
            if env_read_only:
                read_only = os.environ.get(env_read_only, "true").lower() == "true"
            
            try:
                proc = subprocess.Popen(
                    full_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
                time.sleep(1.0)
                exit_code = proc.poll()
                
                if exit_code is None:
                    # Process running — health check passed
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    
                    results[server_key] = {
                        "status": "connected",
                        "enabled_source": "runtime_auto_enable",
                        "read_only": read_only,
                        "message": f"Connected after AWS identity verification ({command})",
                        "display_name": display_name,
                    }
                    self._health_check_results[server_key] = "connected"
                else:
                    _, stderr = proc.communicate(timeout=2)
                    err_msg = stderr.decode()[:150] if stderr else f"Exit code {exit_code}"
                    results[server_key] = {
                        "status": "not_connected",
                        "enabled_source": "runtime_auto_enable",
                        "message": f"Server failed to start: {err_msg}",
                        "fix": f"Check {server_key} config and dependencies",
                        "display_name": display_name,
                    }
            except Exception as e:
                results[server_key] = {
                    "status": "not_connected",
                    "enabled_source": "runtime_auto_enable",
                    "message": f"Failed to start: {e}",
                    "fix": "Check server config",
                    "display_name": display_name,
                }
            
            self._runtime_enabled_mcps[server_key] = results[server_key]
        
        return results

    def get_scoring_context_mode(self) -> str:
        """Return the scoring context mode based on connected MCPs.
        
        Returns one of:
        - 'local_fallback'
        - 'aws_knowledge_mcp_enriched'
        - 'account_mcp_enriched'
        """
        knowledge_connected = self._health_check_results.get("aws-knowledge") == "connected"
        account_connected = any(
            self._runtime_enabled_mcps.get(k, {}).get("status") == "connected"
            for k in ["aws-api", "iam", "cloudtrail", "securityhub"]
        )
        
        if knowledge_connected and account_connected:
            return "account_mcp_enriched"
        elif knowledge_connected:
            return "aws_knowledge_mcp_enriched"
        return "local_fallback"

    @property
    def aws_api_client(self) -> AWSAPIMCPClient:
        """Access the AWS API MCP client."""
        return self._aws_api_client

    @property
    def iam_client(self) -> IAMMCPClient:
        """Access the IAM MCP client."""
        return self._iam_client

    def check_connection(self, server_key: str) -> Dict[str, Any]:
        """Check connection status for a specific MCP server.

        Determines status based on config, env vars, AND runtime auto-enable state.

        Args:
            server_key: The server key (e.g., "aws-knowledge", "aws-api", "iam").

        Returns:
            Dict with "status", "message", and optional metadata.
        """
        registry_entry = SERVER_REGISTRY.get(server_key)
        if registry_entry is None:
            return {"status": "error", "message": f"Unknown server: {server_key}"}

        display_name = registry_entry["display_name"]
        env_enabled = registry_entry["env_enabled"]
        env_read_only = registry_entry.get("env_read_only")

        # Check if this server was runtime auto-enabled
        if server_key in self._runtime_enabled_mcps:
            result = self._runtime_enabled_mcps[server_key].copy()
            result["display_name"] = display_name
            return result

        # Check master switch
        if not self._aws_mcp_enabled:
            # If auto-enable is on and identity is connected, account MCPs should attempt
            account_mcps = {"aws-api", "iam", "cloudtrail", "securityhub"}
            if self._auto_enable and self._aws_identity_connected and server_key in account_mcps:
                return {
                    "status": "not_connected",
                    "enabled_source": "runtime_auto_enable",
                    "message": "AWS_MCP_ENABLED not set but auto-enable active. Set AWS_MCP_ENABLED=true.",
                    "display_name": display_name,
                }
            return {
                "status": "disabled",
                "message": "AWS_MCP_ENABLED not set to true",
                "display_name": display_name,
            }

        # Check per-server env var
        server_env_enabled = os.environ.get(env_enabled, "").lower() == "true"

        # Check config file entry
        server_config = self._server_configs.get(server_key, {})
        config_enabled = server_config.get("enabled", False)

        # Account MCPs: if auto-enable is on and identity connected, don't show as disabled
        account_mcps = {"aws-api", "iam", "cloudtrail", "securityhub"}
        if not server_env_enabled and not config_enabled:
            if self._auto_enable and self._aws_identity_connected and server_key in account_mcps:
                return {
                    "status": "not_connected",
                    "enabled_source": "runtime_auto_enable",
                    "message": "Runtime auto-enable active but server not yet connected. Click Reconnect Account MCPs.",
                    "fix": "Ensure mcp_config.json has this server configured",
                    "display_name": display_name,
                }
            return {
                "status": "disabled",
                "message": f"Disabled by configuration. Set {env_enabled}=true in .env",
                "fix": f"Set {env_enabled}=true in .env and restart",
                "display_name": display_name,
            }

        # If config says disabled but env says enabled, use config as authority
        if not config_enabled:
            return {
                "status": "disabled",
                "message": "enabled=false in config",
                "display_name": display_name,
            }

        # If env says disabled but config says enabled, still disabled
        if not server_env_enabled:
            return {
                "status": "disabled",
                "message": f"{env_enabled} not set to true",
                "display_name": display_name,
            }

        # Server is enabled — validate config
        validation = self._validate_server_config(server_config)
        if validation is not None:
            return {
                "status": "misconfigured",
                "message": validation,
                "display_name": display_name,
            }

        # Config is valid — check if server binary is available
        availability = self._check_server_available(server_config)
        availability["display_name"] = display_name

        # Add read-only info if applicable
        if env_read_only:
            read_only = os.environ.get(env_read_only, "true").lower() == "true"
            config_read_only = server_config.get("readOnly", True)
            availability["read_only"] = read_only or config_read_only

        return availability

    def check_all_connections(self) -> Dict[str, Dict[str, Any]]:
        """Check connection status for all configured MCP servers.

        Returns:
            Dict mapping server keys to their status dicts.
        """
        results: Dict[str, Dict[str, Any]] = {}

        for server_key in SERVER_REGISTRY:
            results[server_key] = self.check_connection(server_key)

        return results

    def _validate_server_config(self, server_config: Dict[str, Any]) -> Optional[str]:
        """Validate that a server config has all required fields.

        Returns:
            None if valid, or an error message string if invalid.
        """
        if not server_config:
            return "Server configuration is empty"

        command = server_config.get("command")
        if not command:
            return "No command specified in server config"

        args = server_config.get("args")
        if args is None:
            return "No args specified in server config"

        transport = server_config.get("transport")
        if not transport:
            return "No transport specified in server config"

        return None

    def _check_server_available(self, server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Check if the MCP server command is available and runnable.

        For stdio transport: checks if the command binary exists on PATH.
        Also considers health check results from auto-start attempt.

        Args:
            server_config: The server configuration dict.

        Returns:
            Dict with "status" and "message" keys.
        """
        command = server_config.get("command", "")
        if not command:
            return {"status": "misconfigured", "message": "No command specified"}

        # Check if command exists on PATH
        if shutil.which(command) is None:
            return {
                "status": "not_connected",
                "message": f"Command '{command}' not found. Install it or check PATH.",
            }

        # Check health check results if available
        for server_key, cfg in self._server_configs.items():
            if cfg is server_config or cfg == server_config:
                hc_result = self._health_check_results.get(server_key)
                if hc_result == "connected":
                    return {"status": "connected", "message": f"Server available ({command})"}
                elif hc_result == "error":
                    return {
                        "status": "not_connected",
                        "message": f"Server failed health check ({command})",
                    }
                break

        # Command exists — mark as connected (available)
        return {"status": "connected", "message": f"Server available ({command})"}

    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Return status for all services including MCP servers.

        Returns:
            Dict mapping service name to status dict.
        """
        # Core services
        status: Dict[str, Dict[str, Any]] = {
            "prowler_data": self.get_prowler_data_status(),
            "posture_data_mcp": self.get_posture_data_mcp_status(),
            "bedrock": self.get_bedrock_status(),
        }

        # MCP server connections (real checks)
        mcp_status = self.check_all_connections()
        for server_key, server_status in mcp_status.items():
            # Normalize key for API (aws-knowledge -> aws_knowledge_mcp)
            api_key = server_key.replace("-", "_") + "_mcp"
            status[api_key] = server_status

        return status

    def get_service_status(self, service_name: str) -> Dict[str, Any]:
        """Get status for a specific service by name.

        Args:
            service_name: One of: prowler_data, posture_data_mcp, bedrock,
                         or an MCP server key.

        Returns:
            Dict with at least "status" key.
        """
        # Check core services first
        if service_name == "prowler_data":
            return self.get_prowler_data_status()
        elif service_name == "posture_data_mcp":
            return self.get_posture_data_mcp_status()
        elif service_name == "bedrock":
            return self.get_bedrock_status()

        # Check MCP servers by normalized name or config key
        # Support both formats: "aws_knowledge_mcp" and "aws-knowledge"
        config_key = service_name.replace("_mcp", "").replace("_", "-")
        if config_key in SERVER_REGISTRY:
            return self.check_connection(config_key)

        return {"status": "error", "message": f"Unknown service: {service_name}"}

    def is_service_connected(self, service_name: str) -> bool:
        """Check if a specific service is connected.

        Args:
            service_name: The service to check.

        Returns:
            True if the service status is "connected".
        """
        status = self.get_service_status(service_name)
        return status.get("status") == "connected"

    def get_prowler_data_status(self) -> Dict[str, Any]:
        """Return Prowler data connection status."""
        if self._findings_count > 0:
            return {
                "status": "connected",
                "source": self._data_source,
                "findings_count": self._findings_count,
            }
        return {
            "status": "not_connected",
            "message": "No Prowler findings loaded",
        }

    def get_posture_data_mcp_status(self) -> Dict[str, Any]:
        """Return Posture Data MCP status."""
        if self._findings_count > 0:
            return {"status": "connected"}
        return {
            "status": "not_connected",
            "message": "No posture data available (no findings loaded)",
        }

    def get_bedrock_status(self) -> Dict[str, Any]:
        """Return Amazon Bedrock connection status."""
        if not self._bedrock_enabled:
            return {
                "status": "not_connected",
                "message": "BEDROCK_ENABLED not set to true",
            }

        result: Dict[str, Any] = {"status": "connected"}
        if self._bedrock_model_id:
            result["model_id"] = self._bedrock_model_id
        if self._aws_region:
            result["region"] = self._aws_region
        return result

    def update_findings_count(self, count: int, source: str = "sample-data") -> None:
        """Update the loaded findings count and data source.

        Args:
            count: Number of findings currently loaded.
            source: Data source description.
        """
        self._findings_count = count
        self._data_source = source

    def print_connection_report(self) -> None:
        """Print a formatted connection status report to stdout."""
        print()
        print("Connection Status Report")
        print("=" * 40)

        # Bedrock
        bedrock = self.get_bedrock_status()
        _print_status_line("Bedrock", bedrock)

        # MCP servers
        mcp_status = self.check_all_connections()
        for server_key, server_status in mcp_status.items():
            display_name = server_status.get("display_name", server_key)
            _print_status_line(display_name, server_status)

        print()


def _print_status_line(name: str, status: Dict[str, Any]) -> None:
    """Print a single status line with icon."""
    s = status.get("status", "error")
    message = status.get("message", "")
    read_only = status.get("read_only", False)

    # Choose icon
    if s == "connected":
        icon = "✅"
    elif s == "disabled":
        icon = "⚪"
    elif s == "not_connected":
        icon = "❌"
    elif s == "misconfigured":
        icon = "⚠️"
    else:
        icon = "❌"

    # Build suffix
    suffix = ""
    if message:
        suffix = f" ({message})"
    elif s == "connected" and read_only:
        suffix = " (read-only)"

    # Pad name for alignment
    padded_name = f"{name} ".ljust(22, ".")
    status_label = {
        "connected": "Connected",
        "disabled": "Disabled",
        "not_connected": "Not Connected",
        "misconfigured": "Misconfigured",
        "error": "Error",
    }.get(s, s.title())

    print(f"  {icon} {padded_name} {status_label}{suffix}")
