# AWS MCP Integration

## Why External AWS MCP Servers

The Agentic GenAI Security Accelerator connects to real, external AWS MCP (Model Context Protocol) servers for best-practice guidance. These are not simulated, mocked, or faked. When an AWS MCP server is not configured, the system honestly reports "Not connected" — it never falls back to fabricated data.

This approach ensures that all AWS guidance shown to customers comes from official AWS sources, not from cached or invented responses.

## Architecture

```
Amazon Bedrock Assistant
    ├── Local Posture Data (findings, scores, gaps via function calling)
    └── External AWS MCP Servers (documentation, best practices, read-only context)
```

Bedrock calls internal posture data functions to understand your security state, then queries connected AWS MCP servers for official AWS documentation and best-practice context to construct grounded answers.

## AWS MCP Servers

| Server | Role | Mode | Required |
|--------|------|------|----------|
| AWS Knowledge / Documentation MCP | AWS documentation, best practices, remediation references | Read | Yes |
| AWS API MCP | Read-only account context and service state | Read-only | Yes |
| IAM MCP | Read-only IAM policy and role context | Read-only | Yes |
| CloudTrail MCP | Trail analysis and audit investigation context | Read-only | Optional |
| Security Hub MCP | Consolidated findings from multiple sources | Read-only | Optional |

## Setup Steps

1. Copy the example config:

```bash
cp mcp_config.example.json mcp_config.json
```

2. Edit `mcp_config.json` — enable/disable servers as needed

3. Set the config path:

```bash
export MCP_CONFIG_PATH=./mcp_config.json
```

4. Set the master switch:

```bash
export AWS_MCP_ENABLED=true
```

5. Enable individual servers:

```bash
export AWS_KNOWLEDGE_MCP_ENABLED=true
export AWS_API_MCP_ENABLED=true
export IAM_MCP_ENABLED=true
```

6. Verify read-only is enforced:

```bash
export AWS_API_MCP_READ_ONLY=true
export IAM_MCP_READ_ONLY=true
```

7. Check connections:

```bash
python -m backend.main --check-connections
```

8. Start the dashboard:

```bash
python -m backend.main
```

## Configuration

### Master Switch

| Variable | Purpose | Default |
|----------|---------|---------|
| `AWS_MCP_ENABLED` | Master switch — must be `true` for any MCP connection | `false` |

### Per-Server Configuration

| Variable | Purpose | Default |
|----------|---------|---------|
| `AWS_KNOWLEDGE_MCP_ENABLED` | Enable AWS Knowledge/Documentation MCP | `false` |
| `AWS_API_MCP_ENABLED` | Enable AWS API MCP | `false` |
| `IAM_MCP_ENABLED` | Enable IAM MCP | `false` |
| `CLOUDTRAIL_MCP_ENABLED` | Enable CloudTrail MCP | `false` |
| `SECURITYHUB_MCP_ENABLED` | Enable Security Hub MCP | `false` |

### Read-Only Enforcement

| Variable | Purpose | Default |
|----------|---------|---------|
| `AWS_API_MCP_READ_ONLY` | Enforce read-only on AWS API MCP | `true` |
| `IAM_MCP_READ_ONLY` | Enforce read-only on IAM MCP | `true` |

### MCP Server Configuration File

| Variable | Purpose | Default |
|----------|---------|---------|
| `MCP_CONFIG_PATH` | Path to MCP server connection config | `mcp_config.json` |

## MCP Config File Format

The `mcp_config.json` file defines all MCP server connections:

```json
{
  "mcpServers": {
    "aws-knowledge": {
      "name": "AWS Knowledge / Documentation MCP",
      "command": "uvx",
      "args": ["awslabs.aws-documentation-mcp-server@latest"],
      "transport": "stdio",
      "enabled": true,
      "env": { "FASTMCP_LOG_LEVEL": "ERROR" },
      "description": "AWS documentation and best practices"
    }
  }
}
```

Each server requires:
- `command` — the binary to execute (e.g., `uvx`)
- `args` — command arguments
- `transport` — protocol transport type (`stdio`)
- `enabled` — whether the server is active in config

## Connection Status Values

Each MCP server reports one of five states:

| Status | Meaning |
|--------|---------|
| `connected` | Server command is available on PATH, config is valid, enabled |
| `disabled` | Server is explicitly disabled (enabled=false or env var not set) |
| `not_connected` | Server is enabled and configured but command binary not found |
| `misconfigured` | Server is enabled but config is invalid/missing required fields |
| `error` | Connection attempt failed with specific error |

The dashboard displays these states in connection status cards. The `/api/status` endpoint returns the current state of all services with detailed messages.

**Important:** "Connected" means the server binary/command is available AND the config is valid — not just that an env var is set.

## Enabling a Server

1. Set `AWS_MCP_ENABLED=true` (master switch)
2. Set the per-server enable flag (e.g., `AWS_KNOWLEDGE_MCP_ENABLED=true`)
3. Ensure the config file has `enabled: true` for the server
4. Ensure the command binary is installed (e.g., `uvx`)
5. Ensure AWS credentials are configured for the region
6. Restart the accelerator

Example:

```bash
export AWS_MCP_ENABLED=true
export AWS_KNOWLEDGE_MCP_ENABLED=true
export AWS_API_MCP_ENABLED=true
export IAM_MCP_ENABLED=true
export AWS_REGION=us-east-1
python -m backend.main
```

## Read-Only Enforcement

AWS API MCP and IAM MCP operate in strictly read-only mode:

- `AWS_API_MCP_READ_ONLY=true` (default) prevents any write operations through the API MCP
- `IAM_MCP_READ_ONLY=true` (default) prevents any IAM modifications through the IAM MCP
- These defaults should never be changed in production
- The system does not execute any AWS write operations

## Behavior When Not Connected

When AWS MCP servers are not connected:

- The assistant answers using local posture data only (findings, scores, gaps)
- Answers include a note: "AWS MCP not connected for best-practice guidance"
- No fabricated AWS documentation or best practices are shown
- The dashboard shows "Not Connected" status cards for each unconfigured server

## Future Service MCPs

Additional AWS MCP servers may be added in the future:

- AWS Config MCP — for compliance rule context
- AWS WAF MCP — for web application firewall context
- AWS Network Firewall MCP — for network security context
- Amazon Macie MCP — for data classification context

Each will follow the same pattern: real connection, read-only mode, "Not connected" when unconfigured.
