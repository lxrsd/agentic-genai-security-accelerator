"""REST API server for the Agentic Security Posture Accelerator."""

import json
import logging
import os
import re
import shutil
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from backend.mcp_server import MCPServer

logger = logging.getLogger(__name__)


# Prowler scan safety: allowed regions and output formats
ALLOWED_PROWLER_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
    "ap-south-1", "sa-east-1", "ca-central-1",
]
ALLOWED_OUTPUT_FORMATS = ["json", "csv", "html"]


class PostureAPIHandler(BaseHTTPRequestHandler):
    """HTTP handler serving posture data as JSON endpoints and static files."""

    mcp_server: MCPServer = None  # type: ignore[assignment]
    connection_manager = None
    assistant = None
    scoring_mode: str = "local_fallback"
    scoring_mode_display: str = "Local AWS best-practice metadata fallback"
    prowler_scan_status: str = "not_started"
    data_mode: str = "demo"  # "demo" or "connected_aws"
    dashboard_dir: Path = Path("dashboard")
    aws_identity_cache: dict = {}  # Cached identity result from last check

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(200)
        self._add_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Handle GET requests for API endpoints and static files."""
        parsed = urlparse(self.path)
        path = parsed.path

        # API routes
        if path == "/api/score":
            self._handle_score()
        elif path == "/api/pillars":
            self._handle_pillars()
        elif path == "/api/gaps":
            self._handle_gaps()
        elif path == "/api/remediation":
            self._handle_remediation()
        elif path == "/api/simulate":
            self._handle_simulate(parsed.query)
        elif path == "/api/summary":
            self._handle_summary()
        elif path == "/api/status":
            self._handle_status()
        elif path == "/api/preflight":
            self._handle_preflight()
        elif path == "/api/runtime":
            self._handle_runtime()
        elif path == "/api/bedrock/models":
            self._handle_bedrock_models()
        elif path == "/api/reports/latest":
            self._handle_reports_latest()
        elif path == "/api/debug/storage":
            self._handle_debug_storage()
        elif path == "/api/capability-mode":
            self._handle_capability_mode()
        elif path == "/api/remediation/queue":
            self._handle_remediation_queue_get()
        elif path == "/api/audit/log":
            self._handle_audit_log_get()
        elif path.startswith("/api/scan-status/"):
            scan_id = path.split("/api/scan-status/")[1].split("/")[0]
            self._handle_scan_status_get(scan_id)
        else:
            # Serve static files
            self._serve_static(path)

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/chat":
            self._handle_chat()
        elif path == "/api/check-connections":
            self._handle_check_connections()
        elif path == "/api/aws-sso-login":
            self._handle_aws_sso_login()
        elif path == "/api/run-prowler-scan":
            self._handle_run_prowler_scan()
        elif path == "/api/refresh-findings":
            self._handle_refresh_findings()
        elif path == "/api/bedrock/validate-model":
            self._handle_bedrock_validate_model()
        elif path == "/api/bedrock/select-model":
            self._handle_bedrock_select_model()
        elif path == "/api/mcp/reconnect-account-mcps":
            self._handle_reconnect_account_mcps()
        elif path == "/api/remediation/queue":
            self._handle_remediation_queue_post()
        elif path == "/api/remediation/approve":
            self._handle_remediation_approve()
        elif path == "/api/remediation/reject":
            self._handle_remediation_reject()
        elif path == "/api/remediation/skip":
            self._handle_remediation_skip()
        elif path == "/api/remediation/dry-run-execute":
            self._handle_remediation_dry_run()
        elif path == "/api/remediation/live-execute":
            self._handle_remediation_live_execute()
        elif path == "/api/reports/s3/validate-bucket":
            self._handle_s3_validate_bucket()
        elif path == "/api/reports/s3/create-bucket":
            self._handle_s3_create_bucket()
        elif path.startswith("/api/scan-status/"):
            scan_id = path.split("/api/scan-status/")[1].split("/")[0]
            if path.endswith("/cancel"):
                self._handle_scan_cancel(scan_id)
            else:
                self._handle_scan_status_get(scan_id)
        else:
            self._send_json_response({"error": "Not found"}, 404)

    # ------------------------------------------------------------------
    # API Handlers
    # ------------------------------------------------------------------

    def _handle_score(self):
        """GET /api/score - Return overall posture score data."""
        data = self.mcp_server.get_overall_posture_score()
        # Add scoring mode info
        data["scoring_mode"] = PostureAPIHandler.scoring_mode
        data["scoring_mode_display"] = PostureAPIHandler.scoring_mode_display
        data["score_source"] = "Prowler findings + AWS Best-Practice Scoring Engine"
        self._send_json_response(data)

    def _handle_pillars(self):
        """GET /api/pillars - Return all 5 area scores with details."""
        data = self.mcp_server.get_domain_scores()
        self._send_json_response(data)

    def _handle_gaps(self):
        """GET /api/gaps - Return top security gaps."""
        data = self.mcp_server.get_top_security_gaps(limit=5)
        self._send_json_response({"gaps": data})

    def _handle_remediation(self):
        """GET /api/remediation - Return remediation plan."""
        data = self.mcp_server.get_remediation_plan()
        self._send_json_response({"actions": data})

    def _handle_simulate(self, query_string: str):
        """GET /api/simulate?ids=id1,id2 - Return simulated improvement."""
        params = parse_qs(query_string)
        ids_param = params.get("ids", [""])[0]
        ids = [id.strip() for id in ids_param.split(",") if id.strip()]

        if not ids:
            self._send_json_response({
                "current_score": self.mcp_server._posture.overall_score,
                "simulated_score": self.mcp_server._posture.overall_score,
                "improvement": 0.0,
                "pillar_changes": [],
            })
            return

        data = self.mcp_server.simulate_score_improvement(ids)
        # Map from internal format to API format
        pillar_changes = []
        for item in data.get("pillar_improvements", []):
            pillar_changes.append({
                "pillar": item["pillar"],
                "current": item["current_score"],
                "simulated": item["simulated_score"],
            })
        self._send_json_response({
            "current_score": data["current_score"],
            "simulated_score": data["simulated_score"],
            "improvement": data["improvement"],
            "pillar_changes": pillar_changes,
        })

    def _handle_summary(self):
        """GET /api/summary - Return executive summary text."""
        summary = self.mcp_server.generate_executive_summary()
        self._send_json_response({"summary": summary})

    def _handle_status(self):
        """GET /api/status - Return enriched connection status."""
        connection_manager = PostureAPIHandler.connection_manager
        score_data = self.mcp_server.get_overall_posture_score()

        # Build data_source section
        findings_count = score_data.get("total_findings", 0)
        data_mode = PostureAPIHandler.data_mode
        is_static = data_mode == "demo"

        if findings_count > 0:
            data_source = {
                "status": "connected",
                "type": "sample_prowler" if is_static else "live_prowler",
                "finding_count": findings_count,
                "message": "Demo findings loaded" if is_static else "Live findings imported",
                "is_static": is_static,
            }
        else:
            data_source = {
                "status": "not_connected",
                "type": None,
                "finding_count": 0,
                "message": "No findings loaded",
                "is_static": False,
            }

        # Build aws_identity section (use cached result if available)
        aws_identity = PostureAPIHandler.aws_identity_cache if PostureAPIHandler.aws_identity_cache else {
            "status": "not_connected",
            "account_id": None,
            "arn": None,
            "profile": None,
            "region": os.environ.get("AWS_REGION", "us-east-1"),
            "message": "Click 'Connect AWS' to detect credentials.",
        }

        # Build scoring section
        scoring = {
            "status": "connected",
            "engine": "AWS Best-Practice Scoring Engine",
            "mode": PostureAPIHandler.scoring_mode,
            "mode_display": PostureAPIHandler.scoring_mode_display,
            "message": "",
        }

        # Build connections section from connection manager
        connections = {}
        if connection_manager:
            all_status = connection_manager.get_all_status()
            # Map to expected keys with friendly messages
            connection_messages = {
                "aws_knowledge_mcp": "Provides AWS best-practice control context.",
                "bedrock": "Bedrock powers live AI chat. Scoring works without Bedrock.",
                "aws_api_mcp": "Enable for live read-only AWS account context.",
                "iam_mcp": "Enable for read-only IAM context.",
                "cloudtrail_mcp": "Enable for investigation questions.",
                "securityhub_mcp": "Enable for Security Hub findings context.",
            }

            for key in ["aws_knowledge_mcp", "bedrock", "aws_api_mcp", "iam_mcp", "cloudtrail_mcp", "securityhub_mcp"]:
                svc_data = all_status.get(key, {})
                status = svc_data.get("status", "disabled")
                msg = svc_data.get("message", "")
                # Use friendly fallback message for disabled services
                if status == "disabled" and not msg:
                    msg = connection_messages.get(key, "")
                elif status == "disabled":
                    msg = connection_messages.get(key, msg)
                connections[key] = {"status": status, "message": msg}
        else:
            # No connection manager — mark all as disabled
            connections = {
                "aws_knowledge_mcp": {"status": "disabled", "message": "Connection manager not initialized."},
                "bedrock": {"status": "disabled", "message": "Bedrock powers live AI chat. Scoring works without Bedrock."},
                "aws_api_mcp": {"status": "disabled", "message": "Enable for live read-only AWS account context."},
                "iam_mcp": {"status": "disabled", "message": "Enable for read-only IAM context."},
                "cloudtrail_mcp": {"status": "disabled", "message": "Enable for investigation questions."},
                "securityhub_mcp": {"status": "disabled", "message": "Enable for Security Hub findings context."},
            }

        # Prowler scan section
        prowler_scan = {
            "status": PostureAPIHandler.prowler_scan_status,
            "message": "",
            "last_run": None,
            "output_directory": os.environ.get("PROWLER_DATA_DIR", "sample-data/prowler-output"),
        }

        response = {
            "mode": data_mode,
            "data_source": data_source,
            "aws_identity": aws_identity,
            "scoring": scoring,
            "connections": connections,
            "prowler_scan": prowler_scan,
        }

        self._send_json_response(response)

    def _handle_preflight(self):
        """GET /api/preflight — Full readiness check."""
        from backend.preflight import run_preflight
        result = run_preflight()
        self._send_json_response(result)

    def _handle_runtime(self):
        """GET /api/runtime — Return runtime environment info."""
        import sys
        import time
        
        boto3_version = ""
        boto3_installed = False
        botocore_version = ""
        botocore_installed = False
        
        try:
            import boto3
            boto3_installed = True
            boto3_version = boto3.__version__
        except ImportError:
            pass
        
        try:
            import botocore
            botocore_installed = True
            botocore_version = botocore.__version__
        except ImportError:
            pass
        
        self._send_json_response({
            "python_executable": sys.executable,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "boto3_installed": boto3_installed,
            "boto3_version": boto3_version,
            "botocore_installed": botocore_installed,
            "botocore_version": botocore_version,
            "repo_root": str(Path(__file__).parent.parent),
            "env_path": os.environ.get("ENV_FILE", ".env"),
            "pid": os.getpid(),
            "in_venv": sys.prefix != sys.base_prefix,
            "venv_path": sys.prefix if sys.prefix != sys.base_prefix else None,
        })

    def _handle_bedrock_models(self):
        """GET /api/bedrock/models — List available Bedrock models."""
        from backend.bedrock_model_discovery import get_fallback_model_ids

        region = os.environ.get("AWS_REGION", "us-east-1")
        configured = os.environ.get("BEDROCK_MODEL_ID", "")

        # Get active model from assistant
        active = ""
        assistant = PostureAPIHandler.assistant
        if assistant and hasattr(assistant, '_active_model_id'):
            active = assistant._active_model_id or ""

        # Try to list foundation models from Bedrock
        available_models = []
        try:
            import boto3
            client = boto3.client("bedrock", region_name=region)
            response = client.list_foundation_models(byOutputModality="TEXT")
            for m in response.get("modelSummaries", []):
                mid = m.get("modelId", "")
                # Only include models that support on-demand and chat-like use
                if any(p in mid for p in ["claude", "nova", "titan", "llama", "mistral"]):
                    available_models.append({
                        "model_id": mid,
                        "provider": m.get("providerName", ""),
                        "model_name": m.get("modelName", ""),
                        "status": "available",
                    })
        except Exception:
            pass  # Discovery failed — fallback list will be shown

        # Get Bedrock status
        bedrock_status = "disabled"
        bedrock_message = ""
        if assistant and hasattr(assistant, 'get_status'):
            st = assistant.get_status()
            bedrock_status = st.get("status", "disabled")
            bedrock_message = st.get("message", "")

        self._send_json_response({
            "region": region,
            "configured_model_id": configured,
            "active_model_id": active,
            "available_models": available_models[:20],  # Cap at 20
            "fallback_models": get_fallback_model_ids(),
            "status": bedrock_status,
            "message": bedrock_message,
        })

    def _handle_bedrock_validate_model(self):
        """POST /api/bedrock/validate-model — Validate a specific model."""
        from backend.bedrock_model_discovery import validate_model_access

        body = self._read_json_body()
        if body is None:
            return

        model_id = body.get("model_id", "")
        region = os.environ.get("AWS_REGION", "us-east-1")
        result = validate_model_access(model_id, region)
        self._send_json_response(result)

    def _handle_bedrock_select_model(self):
        """POST /api/bedrock/select-model — Select and activate a model."""
        from backend.bedrock_model_discovery import validate_model_access

        body = self._read_json_body()
        if body is None:
            return

        model_id = body.get("model_id", "")
        region = os.environ.get("AWS_REGION", "us-east-1")

        # Validate
        result = validate_model_access(model_id, region)

        if result["status"] == "connected":
            # Update the active assistant's model
            assistant = PostureAPIHandler.assistant
            if assistant and hasattr(assistant, '_model_id'):
                assistant._model_id = model_id
                assistant._active_model_id = model_id

            self._send_json_response({
                "status": "connected",
                "active_model_id": model_id,
                "message": f"Model selected and validated: {model_id}",
            })
        else:
            self._send_json_response(result)

    def _handle_reconnect_account_mcps(self):
        """POST /api/mcp/reconnect-account-mcps — Reconnect account-aware MCPs.
        
        Requires AWS identity to be connected. Attempts to connect
        AWS API, IAM, CloudTrail, and Security Hub MCPs.
        """
        # Check identity first
        identity = self._check_aws_identity()
        if identity.get("status") != "connected":
            self._send_json_response({
                "status": "not_connected",
                "message": "AWS identity required before connecting account MCPs.",
                "fix": "Click Connect AWS to verify identity first.",
            })
            return
        
        # Attempt account MCP connections
        cm = PostureAPIHandler.connection_manager
        if not cm:
            self._send_json_response({"status": "error", "message": "Connection manager not available"})
            return
        
        results = cm.connect_account_mcps_after_aws_identity(identity)
        self._send_json_response({
            "status": "success",
            "account_mcps": results,
            "message": f"Attempted {len(results)} account MCP connections.",
        })

    def _handle_s3_validate_bucket(self):
        """POST /api/reports/s3/validate-bucket"""
        from backend.s3_report_storage import S3ReportStorage

        identity = PostureAPIHandler.aws_identity_cache
        account_id = identity.get("account_id", "") if identity else ""
        storage = S3ReportStorage(account_id=account_id)
        result = storage.validate_bucket()
        self._send_json_response(result)

    def _handle_s3_create_bucket(self):
        """POST /api/reports/s3/create-bucket"""
        from backend.s3_report_storage import S3ReportStorage

        body = self._read_json_body()
        if body is None:
            return
        confirm = body.get("confirm", False)
        identity = PostureAPIHandler.aws_identity_cache
        account_id = identity.get("account_id", "") if identity else ""
        storage = S3ReportStorage(account_id=account_id)
        result = storage.create_bucket(confirm=confirm)
        self._send_json_response(result)

    def _handle_reports_latest(self):
        """GET /api/reports/latest"""
        from backend.s3_report_storage import S3ReportStorage

        identity = PostureAPIHandler.aws_identity_cache
        account_id = identity.get("account_id", "") if identity else ""
        storage = S3ReportStorage(account_id=account_id)
        result = storage.get_latest_scan()
        self._send_json_response(result)

    def _handle_debug_storage(self):
        """GET /api/debug/storage"""
        identity = PostureAPIHandler.aws_identity_cache
        account_id = identity.get("account_id", "") if identity else ""
        mode = os.environ.get("REPORT_STORAGE_MODE", "local")

        bucket_name = ""
        if os.environ.get("REPORT_BUCKET_NAME", ""):
            bucket_name = os.environ.get("REPORT_BUCKET_NAME", "")
        elif account_id:
            bucket_name = f"agentic-security-posture-{account_id}-{os.environ.get('AWS_REGION', 'us-east-1')}"

        active_finding_count = 0
        if PostureAPIHandler.mcp_server:
            try:
                score_data = PostureAPIHandler.mcp_server.get_overall_posture_score()
                active_finding_count = score_data.get("total_findings", 0)
            except Exception:
                pass

        self._send_json_response({
            "storage_mode": mode,
            "bucket_name": bucket_name,
            "prefix": os.environ.get("REPORT_BUCKET_PREFIX", "agentic-security-posture"),
            "account_id": account_id,
            "region": os.environ.get("AWS_REGION", "us-east-1"),
            "demo_path": "sample-data/prowler-output",
            "active_finding_count": active_finding_count,
        })

    def _handle_capability_mode(self):
        """GET /api/capability-mode — Return current agent capability mode and badges."""
        from backend.feature_flags import FeatureFlags
        from backend.tool_registry import ToolRegistry
        from backend.iam_manager import IAMManager

        flags = FeatureFlags.from_env()

        # Build investigation tools reference if enabled
        investigation_tools = None
        if flags.investigation_tools_enabled:
            from backend.investigation_tools import InvestigationTools
            iam_mgr = IAMManager()
            investigation_tools = InvestigationTools(iam_mgr)

        registry = ToolRegistry(flags, PostureAPIHandler.mcp_server, investigation_tools)
        data_source = PostureAPIHandler.data_mode or "demo"

        # AWS identity status
        aws_identity = PostureAPIHandler.aws_identity_cache or {}
        aws_status = "Connected" if aws_identity.get("status") == "connected" else "Not Connected"

        self._send_json_response({
            "capability_mode": flags.get_capability_mode(),
            "remediation_mode": flags.get_remediation_mode(),
            "guardrails": flags.get_guardrail_status(),
            "feature_flags": flags.to_dict(),
            "registered_tool_count": registry.get_registered_tool_count(),
            "registered_tool_names": registry.get_registered_tool_names(),
            "tools_by_category": registry.get_tools_by_category(),
            "data_source": data_source,
            "aws_identity_status": aws_status,
            "live_aws_read_only": flags.investigation_tools_enabled,
        })

    def _handle_remediation_queue_get(self):
        """GET /api/remediation/queue — List queued remediation actions."""
        from backend.remediation_queue import remediation_queue
        actions = remediation_queue.get_all()
        self._send_json_response({
            "actions": [a.to_dict() for a in actions],
            "summary": remediation_queue.get_summary(),
        })

    def _handle_remediation_queue_post(self):
        """POST /api/remediation/queue — Add a planned action to the queue."""
        from backend.remediation_queue import remediation_queue
        from backend.audit_logger import audit_logger

        body = self._read_json_body()
        if body is None:
            return
        action = remediation_queue.add(body)
        audit_logger.log_event(
            action_type="queued",
            remediation_action_id=action.action_id,
            finding_id=action.finding_id,
            target_resource=action.target_resource,
            proposed_action=action.proposed_action,
            risk_category=action.risk_category,
            status="pending",
            session_id=action.session_id,
        )
        self._send_json_response({"status": "queued", "action": action.to_dict()})

    def _handle_remediation_approve(self):
        """POST /api/remediation/approve — Approve a specific action (does NOT execute)."""
        from backend.approval_engine import approval_engine
        body = self._read_json_body()
        if body is None:
            return
        action_id = body.get("action_id", "")
        if not action_id:
            self._send_json_response({"status": "error", "message": "action_id is required"}, 400)
            return
        result = approval_engine.approve(action_id)
        status_code = 200 if result.get("status") != "error" else 400
        self._send_json_response(result, status_code)

    def _handle_remediation_reject(self):
        """POST /api/remediation/reject — Reject a specific action."""
        from backend.approval_engine import approval_engine
        body = self._read_json_body()
        if body is None:
            return
        action_id = body.get("action_id", "")
        if not action_id:
            self._send_json_response({"status": "error", "message": "action_id is required"}, 400)
            return
        result = approval_engine.reject(action_id)
        status_code = 200 if result.get("status") != "error" else 400
        self._send_json_response(result, status_code)

    def _handle_remediation_skip(self):
        """POST /api/remediation/skip — Skip a specific action."""
        from backend.approval_engine import approval_engine
        body = self._read_json_body()
        if body is None:
            return
        action_id = body.get("action_id", "")
        if not action_id:
            self._send_json_response({"status": "error", "message": "action_id is required"}, 400)
            return
        result = approval_engine.skip(action_id)
        status_code = 200 if result.get("status") != "error" else 400
        self._send_json_response(result, status_code)

    def _handle_remediation_dry_run(self):
        """POST /api/remediation/dry-run-execute — Dry-run execute an approved action."""
        from backend.execution_tools import execution_engine
        body = self._read_json_body()
        if body is None:
            return
        action_id = body.get("action_id", "")
        if not action_id:
            self._send_json_response({"status": "error", "message": "action_id is required"}, 400)
            return
        result = execution_engine.dry_run_execute(action_id)
        status_code = 200 if result.get("status") != "error" else 400
        self._send_json_response(result, status_code)

    def _handle_remediation_live_execute(self):
        """POST /api/remediation/live-execute — Live execute an approved low-risk action."""
        from backend.execution_tools import execution_engine
        from backend.iam_manager import IAMManager

        body = self._read_json_body()
        if body is None:
            return
        action_id = body.get("action_id", "")
        if not action_id:
            self._send_json_response({"status": "error", "message": "action_id is required"}, 400)
            return

        iam_mgr = IAMManager()
        result = execution_engine.live_execute(action_id, iam_manager=iam_mgr)
        status_code = 200 if result.get("status") not in ("error", "failed") else 400
        self._send_json_response(result, status_code)

    def _handle_audit_log_get(self):
        """GET /api/audit/log — Query audit log entries with optional filters."""
        from backend.audit_logger import audit_logger
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        entries = audit_logger.get_entries(
            action_type=params.get("action_type", [""])[0],
            status=params.get("status", [""])[0],
            risk_category=params.get("risk_category", [""])[0],
            resource=params.get("resource", [""])[0],
            remediation_action_id=params.get("action_id", [""])[0],
        )
        self._send_json_response({"entries": entries, "total": len(entries)})

    def _handle_check_connections(self):
        """POST /api/check-connections — Auto-detect AWS credentials and check identity.
        
        Accepts optional body: {"profile": "my-profile"}
        If no profile provided, uses the standard boto3 credential chain:
        - AWS_PROFILE env var
        - Default AWS CLI profile  
        - AWS SSO cached session
        - Environment credentials
        """
        body = self._read_json_body()
        if body is None:
            body = {}
        
        profile = body.get("profile", "")
        
        # Validate profile if provided
        if profile and not re.match(r'^[a-zA-Z0-9_-]+$', profile):
            self._send_json_response({"aws_identity": {
                "status": "not_connected",
                "message": "Invalid profile name. Use letters, numbers, dashes, and underscores only."
            }})
            return
        
        identity = self._check_aws_identity(profile=profile)
        
        # Store identity result on the handler for /api/status
        PostureAPIHandler.aws_identity_cache = identity
        
        # If identity connected, auto-enable account MCPs
        account_mcp_results = {}
        if identity.get("status") == "connected" and PostureAPIHandler.connection_manager:
            account_mcp_results = PostureAPIHandler.connection_manager.connect_account_mcps_after_aws_identity(identity)
        
        result = {
            "aws_identity": identity,
            "account_mcps": account_mcp_results,
            "connections": PostureAPIHandler.connection_manager.get_all_status() if PostureAPIHandler.connection_manager else {},
        }
        self._send_json_response(result)

    def _check_aws_identity(self, profile: str = "") -> dict:
        """Check AWS identity using boto3 STS with optional profile.
        
        Tries the standard boto3 credential chain. If a profile is specified,
        creates a session with that profile.
        
        Returns "misconfigured" if boto3 is not installed (app setup issue).
        Returns "not_connected" if credentials are missing (user setup issue).
        """
        try:
            import boto3
        except ImportError:
            return {
                "status": "misconfigured",
                "message": "boto3 is not installed. Run ./scripts/setup_demo.sh or pip install -r requirements.txt.",
            }
        
        try:
            region = os.environ.get("AWS_REGION", "us-east-1")
            
            if profile:
                session = boto3.Session(profile_name=profile, region_name=region)
                sts = session.client("sts")
            else:
                sts = boto3.client("sts", region_name=region)
            
            identity = sts.get_caller_identity()
            
            # Detect which profile was used
            detected_profile = profile or os.environ.get("AWS_PROFILE", "default")
            
            return {
                "status": "connected",
                "account_id": identity.get("Account"),
                "arn": identity.get("Arn"),
                "user_id": identity.get("UserId"),
                "profile": detected_profile,
                "region": region,
                "message": f"Authenticated as {identity.get('Arn')}",
            }
        except Exception as e:
            error_msg = str(e)
            # Provide helpful messages for common errors
            if "NoCredentialsError" in error_msg or "Unable to locate credentials" in error_msg:
                return {
                    "status": "not_connected",
                    "message": "No AWS credentials found. Use AWS SSO or configure an AWS CLI profile.",
                    "setup_required": True,
                }
            elif "ExpiredToken" in error_msg or "token has expired" in error_msg.lower():
                return {
                    "status": "not_connected",
                    "message": "AWS credentials have expired. Run: aws sso login --profile <profile>",
                    "expired": True,
                }
            elif "InvalidClientTokenId" in error_msg:
                return {
                    "status": "not_connected",
                    "message": "Invalid AWS credentials. Check your access key configuration.",
                }
            else:
                return {
                    "status": "not_connected",
                    "message": f"AWS identity check failed: {error_msg}",
                }

    def _handle_aws_sso_login(self):
        """POST /api/aws-sso-login — Trigger AWS SSO login for a profile.
        
        Request: {"profile": "my-profile"}
        Runs: aws sso login --profile <profile>
        This opens the browser for SSO authentication.
        """
        body = self._read_json_body()
        if body is None:
            return
        
        profile = body.get("profile", "")
        
        if not profile:
            self._send_json_response({
                "status": "failed",
                "message": "Profile name is required for SSO login."
            }, 400)
            return
        
        # Validate profile name strictly
        if not re.match(r'^[a-zA-Z0-9_-]+$', profile):
            self._send_json_response({
                "status": "failed",
                "message": "Invalid profile name. Use letters, numbers, dashes, and underscores only."
            }, 400)
            return
        
        # Check if aws CLI is available
        if not shutil.which("aws"):
            self._send_json_response({
                "status": "failed",
                "message": "AWS CLI not found. Install the AWS CLI first."
            }, 400)
            return
        
        # Run aws sso login --profile <profile> safely
        cmd = ["aws", "sso", "login", "--profile", profile]
        
        try:
            # Start the process but don't wait for it to complete
            # SSO login opens a browser and waits for user interaction
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            self._send_json_response({
                "status": "started",
                "message": f"AWS SSO login started for profile '{profile}'. Complete the login in your browser, then click 'Check Identity' again.",
                "profile": profile,
            })
        except Exception as e:
            self._send_json_response({
                "status": "failed",
                "message": f"Failed to start SSO login: {e}"
            })

    def _handle_run_prowler_scan(self):
        """POST /api/run-prowler-scan — Start a Prowler scan as background job.
        
        Accepts: {"scan_mode": "quick|full", "profile": "", "region": ""}
        Returns scan_id immediately for polling.
        """
        from backend.scan_manager import scan_manager

        if scan_manager.is_running:
            job = scan_manager.get_current_job()
            self._send_json_response({"status": "already_running", "scan_id": job.scan_id, "message": "A scan is already in progress.", **job.to_dict()})
            return

        body = self._read_json_body()
        if body is None:
            body = {}

        scan_mode = body.get("scan_mode", "quick")
        profile = body.get("profile", "")
        region = body.get("region", os.environ.get("AWS_REGION", "us-east-1"))

        # Validate profile
        if profile and not re.match(r'^[a-zA-Z0-9_-]+$', profile):
            self._send_json_response({"status": "failed", "message": "Invalid profile name"}, 400)
            return

        # Start background scan
        job = scan_manager.start_scan(scan_mode=scan_mode, region=region, profile=profile)
        PostureAPIHandler.prowler_scan_status = "running"

        self._send_json_response({
            "status": "started",
            "scan_id": job.scan_id,
            "message": f"Prowler AWS {scan_mode.title()} Scan started...",
            **job.to_dict(),
        })

    def _save_scan_error_log(self, cmd, return_code, stdout, stderr):
        """Save full scan error details to a log file."""
        from datetime import datetime, timezone
        log_dir = Path("data/logs/prowler")
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
        log_path = log_dir / f"{timestamp}-scan-error.log"
        with open(log_path, "w") as f:
            f.write(f"Scan Error Log — {timestamp}\n")
            f.write(f"{'=' * 60}\n\n")
            f.write(f"Command: {' '.join(cmd) if cmd else 'N/A'}\n")
            f.write(f"Return code: {return_code}\n")
            f.write(f"Python: {os.sys.executable}\n")
            f.write(f"Working dir: {os.getcwd()}\n\n")
            f.write(f"--- STDOUT ---\n{stdout or '(empty)'}\n\n")
            f.write(f"--- STDERR ---\n{stderr or '(empty)'}\n")
        return str(log_path)

    def _handle_scan_status_get(self, scan_id: str):
        """GET /api/scan-status/<scan_id> — Get current scan status."""
        from backend.scan_manager import scan_manager
        job = scan_manager.get_job(scan_id)
        if not job:
            # Check if there's a current job
            current = scan_manager.get_current_job()
            if current:
                self._send_json_response(current.to_dict())
            else:
                self._send_json_response({"status": "not_found", "message": f"No scan with ID {scan_id}"}, 404)
            return
        self._send_json_response(job.to_dict())

    def _handle_scan_cancel(self, scan_id: str):
        """POST /api/scan-status/<scan_id>/cancel — Cancel a running scan."""
        from backend.scan_manager import scan_manager
        success = scan_manager.cancel_scan(scan_id)
        if success:
            PostureAPIHandler.prowler_scan_status = "cancelled"
            self._send_json_response({"status": "cancelled", "message": "Scan cancelled."})
        else:
            self._send_json_response({"status": "not_found", "message": "No running scan to cancel."}, 404)

    def _handle_refresh_findings(self):
        """POST /api/refresh-findings — Reload findings and recalculate."""
        try:
            self._refresh_findings_internal()
            score_data = PostureAPIHandler.mcp_server.get_overall_posture_score()
            self._send_json_response({
                "status": "success",
                "finding_count": score_data["total_findings"],
                "overall_score": score_data["overall_score"],
                "message": (
                    f"Findings refreshed. {score_data['total_findings']} findings loaded. "
                    f"Score: {score_data['overall_score']}/5.0"
                ),
            })
        except Exception as e:
            self._send_json_response({"status": "failed", "message": str(e)}, 500)

    def _refresh_findings_internal(self):
        """Internal method to reload findings pipeline."""
        from backend.importer import ProwlerImporter
        from backend.normalizer import Normalizer
        from backend.pillar_mapper import SecurityAreaMapper
        from backend.aws_best_practice_catalog import AWSBestPracticeCatalog
        from backend.aws_scoring_engine import AWSBestPracticeScoringEngine

        data_dir = Path(os.environ.get("PROWLER_DATA_DIR", "sample-data/prowler-output"))
        importer = ProwlerImporter(data_dir)
        raw = importer.load_findings()
        normalizer = Normalizer()
        normalized = normalizer.normalize_batch(raw)
        mapper = SecurityAreaMapper()
        area_findings = mapper.map_batch(normalized)

        # Build catalog
        aws_knowledge_client = None
        if PostureAPIHandler.connection_manager:
            aws_knowledge_client = PostureAPIHandler.connection_manager.aws_knowledge_client

        catalog = AWSBestPracticeCatalog(aws_knowledge_client=aws_knowledge_client)
        catalog.enrich_from_mcp()
        engine = AWSBestPracticeScoringEngine(catalog)
        posture = engine.calculate_posture(area_findings)

        # Update the shared MCP server instance
        new_mcp = MCPServer(engine, posture)
        PostureAPIHandler.mcp_server = new_mcp

        # Update scoring mode
        PostureAPIHandler.scoring_mode = engine.scoring_mode
        PostureAPIHandler.scoring_mode_display = engine.scoring_mode_display

        # Update connection manager findings count
        if PostureAPIHandler.connection_manager:
            PostureAPIHandler.connection_manager.update_findings_count(len(normalized), str(data_dir))

    def _handle_chat(self):
        """POST /api/chat - Handle assistant interaction."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            request_data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json_response({"error": "Invalid JSON"}, 400)
            return

        message = request_data.get("message", "")

        # Check if an assistant is attached
        assistant = PostureAPIHandler.assistant
        if assistant and hasattr(assistant, "respond"):
            response_text = assistant.respond(message)
        else:
            response_text = (
                "Assistant not yet connected. Configure BEDROCK_ENABLED=true to enable AI chat."
            )

        self._send_json_response({"response": response_text})

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _read_json_body(self) -> Optional[Dict]:
        """Read and parse JSON body from the request."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            return json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json_response({"error": "Invalid JSON"}, 400)
            return None

    def _serve_static(self, path: str):
        """Serve static files from the dashboard directory."""
        # Map / and /index.html to dashboard/index.html
        if path == "/" or path == "/index.html":
            file_path = self.dashboard_dir / "index.html"
        elif path.startswith("/static/"):
            # Serve static files from dashboard directory
            relative_path = path[len("/static/"):]
            file_path = self.dashboard_dir / relative_path
        else:
            # Strip leading slash and serve from dashboard dir
            relative_path = path.lstrip("/")
            file_path = self.dashboard_dir / relative_path

        # Security: prevent directory traversal
        try:
            file_path = file_path.resolve()
            dashboard_resolved = self.dashboard_dir.resolve()
            if not str(file_path).startswith(str(dashboard_resolved)):
                self._send_json_response({"error": "Forbidden"}, 403)
                return
        except (ValueError, OSError):
            self._send_json_response({"error": "Forbidden"}, 403)
            return

        if not file_path.is_file():
            self._send_json_response({"error": "Not found"}, 404)
            return

        # Detect content type
        content_type = self._get_content_type(file_path)

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self._add_cors_headers()
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except OSError:
            self._send_json_response({"error": "Internal server error"}, 500)

    def _send_json_response(self, data: Any, status: int = 200):
        """Send a JSON response with CORS headers."""
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._add_cors_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _add_cors_headers(self):
        """Add CORS headers to the response."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    @staticmethod
    def _get_content_type(file_path: Path) -> str:
        """Determine content type based on file extension."""
        extension_map = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".ico": "image/x-icon",
            ".woff": "font/woff",
            ".woff2": "font/woff2",
            ".ttf": "font/ttf",
        }
        ext = file_path.suffix.lower()
        return extension_map.get(ext, "application/octet-stream")

    def log_message(self, format, *args):
        """Override to suppress default request logging."""
        pass


def start_server(
    mcp_server: MCPServer,
    host: str = "127.0.0.1",
    port: int = 8080,
    dashboard_dir: Optional[Path] = None,
):
    """Start the HTTP server.

    Args:
        mcp_server: The MCP server instance with posture data.
        host: Host address to bind to (default 127.0.0.1).
        port: Port to bind to (default 8080).
        dashboard_dir: Path to the dashboard static files directory.
    """
    if dashboard_dir is None:
        # Default to dashboard/ in project root
        project_root = Path(__file__).parent.parent
        dashboard_dir = project_root / "dashboard"

    # Set class-level attributes for the handler
    PostureAPIHandler.mcp_server = mcp_server
    PostureAPIHandler.dashboard_dir = dashboard_dir

    server = HTTPServer((host, port), PostureAPIHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()
