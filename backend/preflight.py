"""Preflight Readiness Check for the Agentic GenAI Security Accelerator.

Validates all dependencies, connections, and configuration.
Can be run standalone: python -m backend.preflight
Or via API: GET /api/preflight
"""

import json
import os
import shutil
import sys
from pathlib import Path


def run_preflight() -> dict:
    """Run all preflight checks and return structured results."""
    checks = {}
    
    # === Core Runtime ===
    checks["python"] = _check_python()
    checks["virtualenv"] = _check_virtualenv()
    checks["dependencies"] = _check_dependencies()
    checks["boto3"] = _check_boto3()
    checks["botocore"] = _check_botocore()
    
    # === AWS Identity ===
    checks["aws_cli"] = _check_aws_cli()
    checks["aws_credentials"] = _check_aws_credentials()
    
    # === Prowler ===
    checks["prowler"] = _check_prowler()
    checks["prowler_findings"] = _check_prowler_findings()
    
    # === MCP Runtime ===
    checks["mcp_config"] = _check_mcp_config()
    checks["mcp_runtime"] = _check_mcp_runtime()
    checks["aws_knowledge_mcp"] = _check_mcp_server("aws-knowledge", "AWS_KNOWLEDGE_MCP_ENABLED", "AWS Knowledge MCP")
    checks["aws_api_mcp"] = _check_mcp_server("aws-api", "AWS_API_MCP_ENABLED", "AWS API MCP")
    checks["iam_mcp"] = _check_mcp_server("iam", "IAM_MCP_ENABLED", "IAM MCP")
    checks["cloudtrail_mcp"] = _check_mcp_server("cloudtrail", "CLOUDTRAIL_MCP_ENABLED", "CloudTrail MCP")
    checks["securityhub_mcp"] = _check_mcp_server("securityhub", "SECURITYHUB_MCP_ENABLED", "Security Hub MCP")
    
    # === Bedrock ===
    checks["bedrock"] = _check_bedrock()
    
    # === Scoring ===
    checks["scoring_engine"] = _check_scoring_engine()
    
    # === Readiness Summary ===
    summary = _compute_readiness(checks)
    
    return {"summary": summary, "checks": checks}


def _check_python():
    v = sys.version_info
    return {"status": "ok", "message": f"{v.major}.{v.minor}.{v.micro}"}


def _check_virtualenv():
    in_venv = sys.prefix != sys.base_prefix
    return {"status": "ok" if in_venv else "warning", "message": ".venv active" if in_venv else "Not in a virtual environment"}


def _check_dependencies():
    try:
        import boto3, botocore
        return {"status": "ok", "message": "Installed"}
    except ImportError as e:
        return {"status": "missing", "message": str(e), "fix": "pip install -r requirements.txt"}


def _check_boto3():
    try:
        import boto3
        return {"status": "installed", "message": f"boto3 {boto3.__version__}"}
    except ImportError:
        return {"status": "missing", "message": "boto3 not installed", "fix": "pip install boto3 botocore"}


def _check_botocore():
    try:
        import botocore
        return {"status": "installed", "message": f"botocore {botocore.__version__}"}
    except ImportError:
        return {"status": "missing", "message": "botocore not installed", "fix": "pip install botocore"}


def _check_aws_cli():
    if shutil.which("aws"):
        return {"status": "ok", "message": "AWS CLI found"}
    return {"status": "missing", "message": "AWS CLI not found", "fix": "Install AWS CLI v2: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"}


def _check_aws_credentials():
    try:
        import boto3
        region = os.environ.get("AWS_REGION", "us-east-1")
        sts = boto3.client("sts", region_name=region)
        identity = sts.get_caller_identity()
        return {
            "status": "connected",
            "account_id": identity.get("Account"),
            "arn": identity.get("Arn"),
            "profile": os.environ.get("AWS_PROFILE", "default"),
            "region": region,
            "message": f"Authenticated as {identity.get('Arn')}",
        }
    except ImportError:
        return {"status": "missing", "message": "boto3 not installed", "fix": "pip install boto3"}
    except Exception as e:
        msg = str(e)
        if "NoCredentialsError" in msg or "Unable to locate credentials" in msg:
            return {"status": "not_connected", "message": "No AWS credentials found", "fix": "aws configure sso && aws sso login --profile <profile>"}
        elif "ExpiredToken" in msg or "token has expired" in msg.lower():
            return {"status": "not_connected", "message": "Credentials expired", "fix": "aws sso login --profile <profile>"}
        return {"status": "not_connected", "message": msg, "fix": "Configure AWS credentials"}


def _check_prowler():
    # Check .prowler-venv first (dedicated Python 3.12 venv for Prowler)
    project_root = Path(__file__).parent.parent
    prowler_venv = project_root / ".prowler-venv" / "bin" / "prowler"
    if prowler_venv.is_file():
        return {"status": "installed", "message": f"Prowler in .prowler-venv (Python 3.12)", "path": str(prowler_venv)}
    if shutil.which("prowler"):
        return {"status": "installed", "message": "Prowler CLI found on PATH"}
    return {"status": "missing", "message": "Prowler not installed", "fix": "python3.12 -m venv .prowler-venv && .prowler-venv/bin/pip install prowler"}


def _check_prowler_findings():
    data_dir = Path(os.environ.get("PROWLER_OUTPUT_DIR", "sample-data/prowler-output"))
    if not data_dir.exists():
        return {"status": "missing", "type": "none", "finding_count": 0, "message": "No findings directory", "fix": "Run Prowler scan via Connect AWS"}
    json_files = list(data_dir.glob("*.json"))
    if not json_files:
        return {"status": "missing", "type": "none", "finding_count": 0, "message": "No JSON findings", "fix": "Run Prowler scan"}
    # Check if it's demo data
    is_demo = "sample-data" in str(data_dir)
    return {"status": "loaded", "type": "demo" if is_demo else "imported", "finding_count": len(json_files), "message": f"{'Demo' if is_demo else 'Imported'} findings loaded"}


def _check_mcp_config():
    config_path = os.environ.get("MCP_CONFIG_PATH", "mcp_config.json")
    if Path(config_path).is_file():
        return {"status": "found", "path": config_path}
    return {"status": "missing", "path": config_path, "fix": "cp mcp_config.example.json mcp_config.json"}


def _check_mcp_runtime():
    if shutil.which("uvx"):
        return {"status": "ready", "message": "uvx available"}
    if shutil.which("uv"):
        return {"status": "ready", "message": "uv available"}
    return {"status": "missing", "message": "uvx/uv not found", "fix": "brew install uv  OR  curl -LsSf https://astral.sh/uv/install.sh | sh"}


def _check_mcp_server(config_key: str, env_var: str, display_name: str):
    """Check MCP server with real process start and health validation."""
    import subprocess
    import time

    master = os.environ.get("AWS_MCP_ENABLED", "").lower() == "true"
    enabled = os.environ.get(env_var, "").lower() == "true"
    
    if not master or not enabled:
        return {"status": "disabled", "message": f"Disabled by configuration. Set {env_var}=true in .env", "fix": f"Set {env_var}=true in .env and restart"}
    
    # Check if AWS identity is needed for account-specific MCPs
    account_mcps = {"aws-api", "iam", "cloudtrail", "securityhub"}
    if config_key in account_mcps:
        # These need AWS identity first
        try:
            import boto3
            boto3.client("sts").get_caller_identity()
        except Exception:
            return {"status": "not_connected", "message": "AWS identity required before this MCP can connect", "fix": "Run aws configure sso && aws sso login"}
    
    # Check if config exists and has this server
    config_path = os.environ.get("MCP_CONFIG_PATH", "mcp_config.json")
    if not Path(config_path).is_file():
        return {"status": "misconfigured", "message": "mcp_config.json not found", "fix": "cp mcp_config.example.json mcp_config.json"}
    
    try:
        with open(config_path) as f:
            config = json.load(f)
        servers = config.get("mcpServers", {})
        server_config = servers.get(config_key, {})
        
        if not server_config:
            return {"status": "misconfigured", "message": f"Server '{config_key}' not in mcp_config.json", "fix": f"Add '{config_key}' to mcp_config.json"}
        
        if not server_config.get("enabled", False):
            return {"status": "disabled", "message": "enabled=false in config"}
        
        command = server_config.get("command", "")
        if not command:
            return {"status": "misconfigured", "message": "No command in config", "fix": f"Set command for {config_key} in mcp_config.json"}
        
        if not shutil.which(command):
            return {"status": "misconfigured", "message": f"Command '{command}' not found", "fix": f"Install {command} (e.g., brew install uv)"}
        
        # Real health check: start the process and verify it doesn't crash immediately
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
            # Wait briefly to see if it crashes
            time.sleep(1.0)
            exit_code = proc.poll()
            
            if exit_code is None:
                # Process is still running — health check passed
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                return {"status": "connected", "message": f"Server started successfully ({command})"}
            else:
                # Process exited immediately — get stderr
                _, stderr = proc.communicate(timeout=2)
                err_msg = stderr.decode()[:200] if stderr else f"Process exited with code {exit_code}"
                return {"status": "not_connected", "message": f"Server failed to start: {err_msg}", "fix": f"Check {config_key} config and dependencies"}
        except FileNotFoundError:
            return {"status": "misconfigured", "message": f"Command '{command}' not found at runtime", "fix": f"Install {command}"}
        except Exception as e:
            return {"status": "not_connected", "message": f"Failed to start server: {e}", "fix": "Check server config and dependencies"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _check_bedrock():
    """Check Bedrock with model discovery and fallback."""
    enabled = os.environ.get("BEDROCK_ENABLED", "").lower() == "true"
    if not enabled:
        return {"status": "disabled", "message": "BEDROCK_ENABLED not set to true", "fix": "Set BEDROCK_ENABLED=true in .env"}
    
    try:
        import boto3
    except ImportError:
        return {"status": "misconfigured", "message": "boto3 not installed", "fix": "pip install boto3"}
    
    region = os.environ.get("AWS_REGION", "us-east-1")
    configured_model = os.environ.get("BEDROCK_MODEL_ID", "")
    
    try:
        from backend.bedrock_model_discovery import select_best_available_model
        
        active_model, result = select_best_available_model(
            preferred_model_id=configured_model,
            region=region,
        )
        
        if active_model:
            msg = f"Bedrock connected (model: {active_model}, region: {region})"
            if result.get("is_fallback"):
                msg += f" [fallback — configured '{configured_model}' unavailable]"
            return {"status": "connected", "model_id": active_model, "message": msg, "is_fallback": result.get("is_fallback", False)}
        else:
            return {
                "status": result.get("status", "not_connected"),
                "model_id": configured_model,
                "message": result.get("message", "No model available"),
                "fix": result.get("fix", "Enable a Bedrock model in the console"),
                "tried": result.get("tried", []),
            }
    except Exception as e:
        return {"status": "not_connected", "message": f"Bedrock check failed: {str(e)[:200]}", "fix": f"Verify model access and IAM permissions in {region}"}


def _check_scoring_engine():
    try:
        from backend.aws_scoring_engine import AWSBestPracticeScoringEngine
        from backend.aws_best_practice_catalog import AWSBestPracticeCatalog
        catalog = AWSBestPracticeCatalog()
        return {"status": "ok", "engine": "AWS Best-Practice Scoring Engine", "mode": catalog.get_scoring_mode(), "message": catalog.get_scoring_mode_display()}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _compute_readiness(checks: dict) -> dict:
    """Compute readiness levels for each mode."""
    missing = []
    
    # Demo Mode: needs Python, deps, findings
    demo_ok = (
        checks["python"]["status"] == "ok" and
        checks["dependencies"]["status"] == "ok" and
        checks["prowler_findings"]["status"] == "loaded"
    )
    
    # Connected AWS: needs demo + AWS identity + imported findings
    aws_identity_ok = checks["aws_credentials"]["status"] == "connected"
    prowler_ok = checks["prowler"]["status"] == "installed"
    
    connected_ok = demo_ok and aws_identity_ok and prowler_ok
    
    # Fully Operational: connected + MCP + Bedrock
    mcp_ok = checks["aws_knowledge_mcp"]["status"] == "connected"
    bedrock_ok = checks["bedrock"]["status"] == "connected"
    
    fully_ok = connected_ok and mcp_ok and bedrock_ok
    
    # Build missing items
    if checks["boto3"]["status"] == "missing":
        missing.append({"item": "boto3", "fix": "pip install -r requirements.txt"})
    if not aws_identity_ok:
        missing.append({"item": "AWS credentials", "fix": "aws configure sso && aws sso login"})
    if checks["prowler"]["status"] == "missing":
        missing.append({"item": "Prowler CLI", "fix": "pip install prowler"})
    if checks["mcp_runtime"]["status"] == "missing":
        missing.append({"item": "MCP runtime (uvx)", "fix": "brew install uv"})
    if checks["aws_knowledge_mcp"]["status"] not in ("connected", "disabled"):
        missing.append({"item": "AWS Knowledge MCP", "fix": checks["aws_knowledge_mcp"].get("fix", "Check MCP config")})
    if checks["bedrock"]["status"] not in ("connected", "disabled"):
        missing.append({"item": "Bedrock", "fix": checks["bedrock"].get("fix", "Set BEDROCK_ENABLED=true and BEDROCK_MODEL_ID")})
    
    return {
        "demo_mode": "ready" if demo_ok else "not_ready",
        "connected_aws_mode": "ready" if connected_ok else ("partial" if demo_ok and aws_identity_ok else "not_ready"),
        "fully_operational_mode": "ready" if fully_ok else ("partial" if connected_ok else "not_ready"),
        "missing": missing,
    }


def print_preflight():
    """Print formatted preflight check results to stdout."""
    # Load .env if python-dotenv available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    
    results = run_preflight()
    checks = results["checks"]
    summary = results["summary"]
    
    def icon(status):
        return {"ok": "✅", "installed": "✅", "connected": "✅", "loaded": "✅", "found": "✅", "ready": "✅",
                "disabled": "⚪", "warning": "⚠️", "misconfigured": "⚠️", "missing": "❌",
                "not_connected": "❌", "access_denied": "🚫", "error": "❌", "not_ready": "❌",
                "partial": "🟡"}.get(status, "❓")
    
    def pad(label, width=25):
        dots = "." * max(1, width - len(label))
        return f"{label} {dots}"
    
    print()
    print("=" * 60)
    print("  Agentic GenAI Security Accelerator — Preflight Check")
    print("=" * 60)
    
    print("\nCore Runtime")
    print(f"  {icon(checks['python']['status'])} {pad('Python')} {checks['python']['message']}")
    print(f"  {icon(checks['virtualenv']['status'])} {pad('Virtualenv')} {checks['virtualenv']['message']}")
    print(f"  {icon(checks['dependencies']['status'])} {pad('Dependencies')} {checks['dependencies']['message']}")
    print(f"  {icon(checks['boto3']['status'])} {pad('boto3')} {checks['boto3']['message']}")
    print(f"  {icon(checks['botocore']['status'])} {pad('botocore')} {checks['botocore']['message']}")
    
    print("\nAWS Identity")
    print(f"  {icon(checks['aws_cli']['status'])} {pad('AWS CLI')} {checks['aws_cli']['message']}")
    creds = checks['aws_credentials']
    creds_msg = creds.get('message', '')
    print(f"  {icon(creds['status'])} {pad('AWS Credentials')} {creds_msg}")
    if creds['status'] == 'connected':
        print(f"     Account: {creds.get('account_id', '')}")
        print(f"     ARN: {creds.get('arn', '')}")
        print(f"     Region: {creds.get('region', '')}")
    
    print("\nProwler")
    print(f"  {icon(checks['prowler']['status'])} {pad('Prowler CLI')} {checks['prowler']['message']}")
    pf = checks['prowler_findings']
    print(f"  {icon(pf['status'])} {pad('Prowler Findings')} {pf['message']}")
    
    print("\nMCP Runtime")
    print(f"  {icon(checks['mcp_config']['status'])} {pad('mcp_config.json')} {checks['mcp_config'].get('path', '')}")
    print(f"  {icon(checks['mcp_runtime']['status'])} {pad('MCP Runtime (uvx)')} {checks['mcp_runtime']['message']}")
    for key in ['aws_knowledge_mcp', 'aws_api_mcp', 'iam_mcp', 'cloudtrail_mcp', 'securityhub_mcp']:
        c = checks[key]
        print(f"  {icon(c['status'])} {pad(key.replace('_', ' ').title())} {c['message']}")
    
    print("\nBedrock")
    br = checks['bedrock']
    print(f"  {icon(br['status'])} {pad('Bedrock')} {br['message']}")
    
    print("\nScoring")
    se = checks['scoring_engine']
    print(f"  {icon(se['status'])} {pad('Scoring Engine')} {se.get('engine', '')} ({se.get('message', '')})")
    
    print(f"\n{'=' * 60}")
    print("  Readiness Summary")
    print(f"{'=' * 60}")
    print(f"  {icon(summary['demo_mode'])} Demo Mode ................. {summary['demo_mode'].upper()}")
    print(f"  {icon(summary['connected_aws_mode'])} Connected AWS Mode ........ {summary['connected_aws_mode'].upper()}")
    print(f"  {icon(summary['fully_operational_mode'])} Fully Operational Mode .... {summary['fully_operational_mode'].upper()}")
    
    if summary['missing']:
        print(f"\n  Missing items:")
        for item in summary['missing']:
            print(f"    • {item['item']}: {item['fix']}")
    
    print()


if __name__ == "__main__":
    print_preflight()
