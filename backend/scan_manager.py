"""Scan Manager — runs Prowler scans as background jobs with progress tracking.

Supports Quick Scan (targeted services, 20 min timeout) and 
Full Scan (all services, 60 min timeout).
"""

import json
import logging
import os
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Quick scan services — targeted at the 5 dashboard security areas
QUICK_SCAN_SERVICES = [
    "iam",          # Identity & Access
    "s3",           # Data Protection
    "kms",          # Data Protection
    "ec2",          # Network Security
    "vpc",          # Network Security
    "guardduty",    # Incident Readiness
    "cloudtrail",   # Incident Readiness
    "securityhub",  # Incident Readiness
    "config",       # Incident Readiness
    "inspector2",   # Vulnerability Management
    "ssm",          # Vulnerability Management
]

# Ultra Micro scan — single check for fastest pipeline validation
ULTRA_MICRO_SCAN_CHECKS = [
    "securityhub_enabled",
]

# Smoke scan — minimal curated checks for fast end-to-end validation
SMOKE_SCAN_CHECKS = [
    # Identity & Access (4 checks)
    "iam_root_mfa_enabled",
    "iam_root_hardware_mfa_enabled",
    "iam_user_mfa_enabled_console_access",
    "iam_root_credentials_management_enabled",
    # Data Protection (3 checks)
    "s3_bucket_public_access",
    "s3_bucket_public_write_acl",
    "s3_bucket_public_list_acl",
    # Network Security (3 checks)
    "ec2_securitygroup_allow_ingress_from_internet_to_all_ports",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389",
    # Incident Readiness (3 checks)
    "cloudtrail_multi_region_enabled",
    "guardduty_is_enabled",
    "securityhub_enabled",
]

# Smoke scan services (fallback if check IDs not supported)
SMOKE_SCAN_SERVICES = [
    "iam",
    "s3",
    "ec2",
    "cloudtrail",
    "guardduty",
    "securityhub",
]

# Quick Report services — core checks across all 5 security areas
QUICK_REPORT_SERVICES = [
    "iam",          # Identity & Access
    "s3",           # Data Protection
    "kms",          # Data Protection
    "ec2",          # Network Security
    "vpc",          # Network Security
    "guardduty",    # Incident Readiness
    "cloudtrail",   # Incident Readiness
    "securityhub",  # Incident Readiness
    "config",       # Incident Readiness
    "inspector2",   # Vulnerability Management
    "ssm",          # Vulnerability Management
]


class ScanJob:
    """Represents a running or completed Prowler scan job."""

    def __init__(self, scan_id: str, scan_mode: str, region: str, profile: str = ""):
        self.scan_id = scan_id
        self.scan_mode = scan_mode  # "quick" or "full"
        self.region = region
        self.profile = profile
        self.status = "queued"  # queued, running, completed, failed, timed_out, cancelled
        self.stage = "queued"
        self.message = "Preparing connected scan..."
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.started_at
        self.completed_at: Optional[str] = None
        self.elapsed_seconds = 0
        self.timeout_seconds = int(os.environ.get(
            {
                "ultra_micro": "PROWLER_ULTRA_MICRO_SCAN_TIMEOUT_SECONDS",
                "smoke": "PROWLER_SMOKE_SCAN_TIMEOUT_SECONDS",
                "quick_report": "PROWLER_QUICK_REPORT_TIMEOUT_SECONDS",
                "full_report": "PROWLER_FULL_REPORT_TIMEOUT_SECONDS",
            }.get(scan_mode, "PROWLER_ULTRA_MICRO_SCAN_TIMEOUT_SECONDS"),
            {"ultra_micro": "120", "smoke": "600", "quick_report": "1500", "full_report": "5400"}.get(scan_mode, "120")
        ))
        self.log_path: Optional[str] = None
        self.error: Optional[str] = None
        self.command: Optional[str] = None
        self.output_dir: Optional[str] = None
        self._process: Optional[subprocess.Popen] = None
        self._cancelled = False
        self.s3_log_uri: Optional[str] = None
        self.s3_status_uri: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "stage": self.stage,
            "message": self.message,
            "scan_mode": self.scan_mode,
            "region": self.region,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "elapsed_seconds": self.elapsed_seconds,
            "timeout_seconds": self.timeout_seconds,
            "log_path": self.log_path,
            "s3_log_uri": self.s3_log_uri,
            "s3_status_uri": self.s3_status_uri,
            "error": self.error,
        }

    def update(self, stage: str, message: str, status: str = "running"):
        self.stage = stage
        self.message = message
        self.status = status
        self.updated_at = datetime.now(timezone.utc).isoformat()
        start = datetime.fromisoformat(self.started_at)
        self.elapsed_seconds = int((datetime.now(timezone.utc) - start).total_seconds())

    def cancel(self):
        self._cancelled = True
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self.status = "cancelled"
        self.stage = "cancelled"
        self.message = "Scan cancelled by user."
        self.completed_at = datetime.now(timezone.utc).isoformat()


class ScanManager:
    """Manages Prowler scan jobs with background execution."""

    def __init__(self):
        self._jobs: Dict[str, ScanJob] = {}
        self._current_job: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self._current_job is not None and self._jobs.get(self._current_job, ScanJob("", "", "")).status == "running"

    def get_job(self, scan_id: str) -> Optional[ScanJob]:
        return self._jobs.get(scan_id)

    def get_current_job(self) -> Optional[ScanJob]:
        if self._current_job:
            return self._jobs.get(self._current_job)
        return None

    def start_scan(self, scan_mode: str = "quick", region: str = "", profile: str = "", on_complete=None) -> ScanJob:
        """Start a new scan job in the background."""
        if self.is_running:
            job = self._jobs[self._current_job]
            return job  # Return existing running job

        region = region or os.environ.get("AWS_REGION", "us-east-1")
        scan_id = str(uuid.uuid4())[:8]
        job = ScanJob(scan_id, scan_mode, region, profile)
        self._jobs[scan_id] = job
        self._current_job = scan_id

        # Start background thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(job, on_complete),
            daemon=True,
        )
        thread.start()

        return job

    def cancel_scan(self, scan_id: str) -> bool:
        job = self._jobs.get(scan_id)
        if job and job.status == "running":
            job.cancel()
            self._current_job = None
            return True
        return False

    def _run_scan(self, job: ScanJob, on_complete=None):
        """Execute the scan in a background thread."""
        project_root = Path(__file__).parent.parent
        
        try:
            # Create log file immediately so it exists even if scan fails
            self._create_initial_log(job)
            
            # Stage 1: Find Prowler
            job.update("validating_prowler", "Locating Prowler executable...")
            prowler_path = project_root / ".prowler-venv" / "bin" / "prowler"
            if not prowler_path.is_file():
                import shutil
                if shutil.which("prowler"):
                    prowler_path = Path(shutil.which("prowler"))
                else:
                    job.status = "failed"
                    job.error = "Prowler not found"
                    job.message = "Prowler CLI not found. Install with: python3.12 -m venv .prowler-venv && .prowler-venv/bin/pip install prowler"
                    return

            # Stage 2: Prepare output dir
            job.update("preparing", "Creating scan output directory...")
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            output_dir = project_root / "data" / "tmp" / "prowler-runs" / job.scan_id / timestamp
            output_dir.mkdir(parents=True, exist_ok=True)
            job.output_dir = str(output_dir)

            # Stage 3: Build command
            # Ultra Micro uses json-ocsf only (minimal output), others include csv/html
            if job.scan_mode == "ultra_micro":
                cmd = [str(prowler_path), "aws", "--output-formats", "json-ocsf", "--output-directory", str(output_dir), "--no-banner", "--ignore-exit-code-3"]
                cmd.extend(["--checks"] + ULTRA_MICRO_SCAN_CHECKS)
            elif job.scan_mode == "smoke":
                cmd = [str(prowler_path), "aws", "--output-formats", "json-ocsf", "csv", "html", "--output-directory", str(output_dir), "--no-banner", "--ignore-exit-code-3"]
                cmd.extend(["--checks"] + SMOKE_SCAN_CHECKS)
            elif job.scan_mode == "quick":
                cmd = [str(prowler_path), "aws", "--output-formats", "json-ocsf", "csv", "html", "--output-directory", str(output_dir), "--no-banner", "--ignore-exit-code-3"]
                cmd.extend(["--services"] + QUICK_SCAN_SERVICES)
            elif job.scan_mode == "quick_report":
                cmd = [str(prowler_path), "aws", "--output-formats", "json-ocsf", "csv", "html", "--output-directory", str(output_dir), "--no-banner", "--ignore-exit-code-3"]
                cmd.extend(["--services"] + QUICK_REPORT_SERVICES)
            else:
                # Full scan / full_report — no service/check filters
                cmd = [str(prowler_path), "aws", "--output-formats", "json-ocsf", "csv", "html", "--output-directory", str(output_dir), "--no-banner", "--ignore-exit-code-3"]
            
            if job.region:
                cmd.extend(["--region", job.region])
            
            if job.profile:
                cmd.extend(["--profile", job.profile])

            job.command = " ".join(cmd)

            # Stage 4: Run Prowler
            mode_label = "Quick" if job.scan_mode == "quick" else "Full"
            job.update("running_prowler", f"Running Prowler AWS {mode_label} Scan... (timeout: {job.timeout_seconds // 60} min)")

            scan_env = os.environ.copy()
            if job.profile:
                scan_env["AWS_PROFILE"] = job.profile
            if job.region:
                scan_env["AWS_REGION"] = job.region
                scan_env["AWS_DEFAULT_REGION"] = job.region

            start_time = time.time()
            job._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=scan_env,
                cwd=str(project_root),
            )

            # Wait with timeout check
            while job._process.poll() is None:
                if job._cancelled:
                    return
                elapsed = time.time() - start_time
                job.elapsed_seconds = int(elapsed)
                if elapsed > job.timeout_seconds:
                    job._process.terminate()
                    try:
                        job._process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        job._process.kill()
                    job.status = "timed_out"
                    job.stage = "timed_out"
                    job.message = f"Prowler scan exceeded timeout ({job.timeout_seconds // 60} min). Use Quick Scan or increase timeout."
                    job.error = f"Timed out after {int(elapsed)} seconds"
                    self._save_log(job, "", f"TIMEOUT after {int(elapsed)}s")
                    self._upload_log_to_s3(job)
                    self._current_job = None
                    return
                time.sleep(2)
                job.update("running_prowler", f"Running Prowler AWS {mode_label} Scan... ({int(elapsed)}s elapsed)")

            stdout, stderr = job._process.communicate()
            job.elapsed_seconds = int(time.time() - start_time)

            if job._process.returncode != 0:
                job.status = "failed"
                job.stage = "failed"
                short_err = stderr.decode()[:200].split('\n')[0] if stderr else f"Exit code {job._process.returncode}"
                job.message = f"Prowler scan failed: {short_err}"
                job.error = stderr.decode()[:500] if stderr else ""
                self._save_log(job, stdout.decode() if stdout else "", stderr.decode() if stderr else "")
                self._upload_log_to_s3(job)
                self._current_job = None
                return

            # Stage 5: Upload to S3
            job.update("uploading_to_s3", "Uploading report to private S3 bucket...")
            storage_mode = os.environ.get("REPORT_STORAGE_MODE", "local")
            if storage_mode == "s3":
                try:
                    from backend.s3_report_storage import S3ReportStorage
                    from backend.api import PostureAPIHandler
                    identity = PostureAPIHandler.aws_identity_cache or {}
                    account_id = identity.get("account_id", "")
                    if account_id:
                        storage = S3ReportStorage(account_id=account_id)
                        storage.upload_scan_report(output_dir, scan_mode=job.scan_mode)
                except Exception as e:
                    logger.warning("S3 upload failed: %s", e)

            # Stage 6: Import findings
            job.update("importing_findings", "Importing findings...")
            try:
                from backend.api import PostureAPIHandler
                handler_class = PostureAPIHandler
                # Trigger refresh from the new output
                os.environ["PROWLER_DATA_DIR"] = str(output_dir)
                from backend.importer import ProwlerImporter
                from backend.normalizer import Normalizer
                from backend.pillar_mapper import SecurityAreaMapper
                from backend.aws_best_practice_catalog import AWSBestPracticeCatalog
                from backend.aws_scoring_engine import AWSBestPracticeScoringEngine
                from backend.mcp_server import MCPServer

                importer = ProwlerImporter(output_dir)
                raw = importer.load_findings()
                normalizer = Normalizer()
                normalized = normalizer.normalize_batch(raw)
                mapper = SecurityAreaMapper()
                area_findings = mapper.map_batch(normalized)

                catalog = AWSBestPracticeCatalog()
                catalog.enrich_from_mcp()
                engine = AWSBestPracticeScoringEngine(catalog)
                posture = engine.calculate_posture(area_findings)

                new_mcp = MCPServer(engine, posture)
                handler_class.mcp_server = new_mcp
                handler_class.scoring_mode = engine.scoring_mode
                handler_class.scoring_mode_display = engine.scoring_mode_display
                handler_class.data_mode = "connected_aws"
                handler_class.prowler_scan_status = "completed"

                if handler_class.connection_manager:
                    handler_class.connection_manager.update_findings_count(len(normalized), str(output_dir))

                job.update("completed", f"Scan completed. {len(normalized)} controls evaluated ({posture.total_passed} passed, {posture.total_failed} failed). Score: {posture.overall_score}/5.0 ({posture.evaluated_area_count}/5 areas evaluated)", "completed")
                job.completed_at = datetime.now(timezone.utc).isoformat()
            except Exception as e:
                job.status = "failed"
                job.stage = "failed"
                job.message = f"Finding import failed: {str(e)[:150]}"
                job.error = str(e)

            self._save_log(job, stdout.decode() if stdout else "", stderr.decode() if stderr else "")
            self._upload_log_to_s3(job)
            self._current_job = None

            if on_complete:
                on_complete(job)

        except Exception as e:
            job.status = "failed"
            job.stage = "failed"
            job.message = f"Scan error: {str(e)[:150]}"
            job.error = str(e)
            self._current_job = None

    def _save_log(self, job: ScanJob, stdout: str, stderr: str):
        """Save/update scan log file. Appends to existing log if it exists."""
        project_root = Path(__file__).parent.parent
        log_dir = project_root / "data" / "logs" / "prowler"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Use existing log path if already created, otherwise create new
        if job.log_path and Path(job.log_path).exists():
            log_path = Path(job.log_path)
        else:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
            log_path = log_dir / f"{timestamp}-{job.scan_id}-scan.log"
            job.log_path = str(log_path)
        
        # Overwrite with full details
        with open(log_path, "w") as f:
            f.write(f"Prowler Scan Log\n")
            f.write(f"{'=' * 60}\n\n")
            f.write(f"Scan ID: {job.scan_id}\n")
            f.write(f"Scan Mode: {job.scan_mode}\n")
            f.write(f"Status: {job.status}\n")
            f.write(f"Command: {job.command or 'N/A'}\n")
            f.write(f"Region: {job.region}\n")
            f.write(f"Profile: {job.profile or 'default'}\n")
            f.write(f"Timeout: {job.timeout_seconds}s\n")
            f.write(f"Elapsed: {job.elapsed_seconds}s\n")
            f.write(f"Output Dir: {job.output_dir or 'N/A'}\n")
            f.write(f"Project Root: {project_root}\n\n")
            f.write(f"--- STDOUT ---\n{stdout or '(empty)'}\n\n")
            f.write(f"--- STDERR ---\n{stderr or '(empty)'}\n")
            if job.error:
                f.write(f"\n--- ERROR ---\n{job.error}\n")

    def _create_initial_log(self, job: ScanJob) -> str:
        """Create the log file immediately when scan starts (before Prowler runs)."""
        project_root = Path(__file__).parent.parent
        log_dir = project_root / "data" / "logs" / "prowler"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
        log_path = log_dir / f"{timestamp}-{job.scan_id}-scan.log"
        
        with open(log_path, "w") as f:
            f.write(f"Prowler Scan Log — {timestamp}\n")
            f.write(f"{'=' * 60}\n\n")
            f.write(f"Scan ID: {job.scan_id}\n")
            f.write(f"Scan Mode: {job.scan_mode}\n")
            f.write(f"Status: started\n")
            f.write(f"Region: {job.region}\n")
            f.write(f"Profile: {job.profile or 'default'}\n")
            f.write(f"Timeout: {job.timeout_seconds}s\n")
            f.write(f"Started at: {job.started_at}\n\n")
            f.write(f"--- SCAN IN PROGRESS ---\n")
            f.write(f"(This file will be updated when the scan completes or fails)\n")
        
        job.log_path = str(log_path)
        return str(log_path)

    def _upload_log_to_s3(self, job: ScanJob):
        """Upload the scan log and status to S3 if the report bucket is available."""
        try:
            from backend.s3_report_storage import S3ReportStorage
            from backend.api import PostureAPIHandler
            
            identity = PostureAPIHandler.aws_identity_cache or {}
            account_id = identity.get("account_id", "")
            if not account_id:
                return  # No identity — can't determine bucket
            
            storage = S3ReportStorage(account_id=account_id)
            validation = storage.validate_bucket()
            if validation.get("status") != "ready":
                return  # Bucket not safe or not available
            
            bucket = storage.bucket_name
            prefix = os.environ.get("REPORT_BUCKET_PREFIX", "agentic-security-posture")
            scan_time = datetime.fromisoformat(job.started_at).strftime("%Y-%m-%dT%H%M%SZ")
            s3_prefix = f"{prefix}/scans/{account_id}/{scan_time}"
            
            # Upload log file
            if job.log_path and Path(job.log_path).exists():
                log_key = f"{s3_prefix}/logs/prowler-scan.log"
                storage._client.upload_file(job.log_path, bucket, log_key)
                job.s3_log_uri = f"s3://{bucket}/{log_key}"
                logger.info("Uploaded scan log to %s", job.s3_log_uri)
            
            # Upload scan-status.json
            status_data = {
                "scan_id": job.scan_id,
                "status": job.status,
                "scan_mode": job.scan_mode,
                "stage": job.stage,
                "message": job.message,
                "timeout_seconds": job.timeout_seconds,
                "elapsed_seconds": job.elapsed_seconds,
                "local_log_path": job.log_path,
                "s3_log_uri": getattr(job, 's3_log_uri', ''),
                "error": job.error,
                "region": job.region,
                "started_at": job.started_at,
                "completed_at": job.completed_at,
            }
            status_key = f"{s3_prefix}/scan-status.json"
            storage._client.put_object(
                Bucket=bucket,
                Key=status_key,
                Body=json.dumps(status_data, indent=2),
                ContentType="application/json",
            )
            job.s3_status_uri = f"s3://{bucket}/{status_key}"
            
            # Write attempt manifest (for all outcomes)
            attempt_key = f"{prefix}/scan-attempts/{job.scan_id}/attempt.json"
            storage._client.put_object(
                Bucket=bucket,
                Key=attempt_key,
                Body=json.dumps(status_data, indent=2),
                ContentType="application/json",
            )
            
        except Exception as e:
            logger.warning("Failed to upload scan log to S3: %s", e)


# Global scan manager instance
scan_manager = ScanManager()
