"""S3 Report Storage — manages the private S3 bucket for Prowler reports.

The S3 report bucket is the source of truth for Connected AWS Mode.
Flow: Prowler scan → local temp → S3 upload → import from S3 → score

Security: The bucket must always be private with Block Public Access enabled.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class S3ReportStorage:
    """Manages the private S3 bucket for Prowler scan reports."""

    def __init__(self, region: str = None, account_id: str = None):
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._account_id = account_id
        self._bucket_name = os.environ.get("REPORT_BUCKET_NAME", "")
        self._prefix = os.environ.get("REPORT_BUCKET_PREFIX", "agentic-security-posture")
        self._auto_create = os.environ.get("AUTO_CREATE_REPORT_BUCKET", "false").lower() == "true"
        self._versioning = os.environ.get("S3_BUCKET_VERSIONING", "true").lower() == "true"
        self._client = None
        self._init_client()

    def _init_client(self):
        try:
            import boto3
            self._client = boto3.client("s3", region_name=self._region)
        except Exception as e:
            logger.warning("Failed to init S3 client: %s", e)

    @property
    def bucket_name(self) -> str:
        """Get or generate the bucket name."""
        if self._bucket_name:
            return self._bucket_name
        if self._account_id:
            return f"agentic-security-posture-{self._account_id}-{self._region}"
        return ""

    def validate_bucket(self) -> Dict[str, Any]:
        """Validate that the report bucket exists and is secure."""
        if not self._client:
            return {"status": "error", "message": "S3 client not available"}

        bucket = self.bucket_name
        if not bucket:
            return {
                "status": "not_configured",
                "message": "No bucket name. Set REPORT_BUCKET_NAME or connect AWS to auto-generate.",
                "suggested_name": f"agentic-security-posture-{self._account_id or '<ACCOUNT_ID>'}-{self._region}",
            }

        try:
            self._client.head_bucket(Bucket=bucket)
        except Exception as e:
            msg = str(e)
            if "404" in msg or "NoSuchBucket" in msg:
                return {
                    "status": "not_found",
                    "bucket": bucket,
                    "message": f"Bucket '{bucket}' does not exist.",
                    "fix": "Create it with POST /api/reports/s3/create-bucket",
                }
            elif "403" in msg:
                return {
                    "status": "access_denied",
                    "bucket": bucket,
                    "message": "Access denied to bucket.",
                    "fix": "Check IAM permissions for s3:HeadBucket, s3:PutObject, s3:GetObject",
                }
            return {"status": "error", "bucket": bucket, "message": str(e)}

        # Check Block Public Access
        try:
            pab = self._client.get_public_access_block(Bucket=bucket)
            config = pab.get("PublicAccessBlockConfiguration", {})
            all_blocked = (
                config.get("BlockPublicAcls", False)
                and config.get("IgnorePublicAcls", False)
                and config.get("BlockPublicPolicy", False)
                and config.get("RestrictPublicBuckets", False)
            )
            if not all_blocked:
                return {
                    "status": "unsafe",
                    "bucket": bucket,
                    "message": "Block Public Access is not fully enabled.",
                    "fix": "Enable all Block Public Access settings.",
                }
        except Exception:
            return {
                "status": "unsafe",
                "bucket": bucket,
                "message": "Cannot verify Block Public Access.",
                "fix": "Enable Block Public Access on the bucket.",
            }

        return {"status": "ready", "bucket": bucket, "message": "Bucket exists and is secure."}

    def create_bucket(self, confirm: bool = False) -> Dict[str, Any]:
        """Create the report bucket with security controls."""
        if not confirm:
            return {
                "status": "requires_confirmation",
                "message": "Bucket creation requires explicit confirmation.",
                "bucket": self.bucket_name,
            }

        if not self._client:
            return {"status": "error", "message": "S3 client not available"}

        bucket = self.bucket_name
        if not bucket:
            return {"status": "error", "message": "Cannot determine bucket name. Connect AWS first."}

        try:
            # Create bucket
            create_args = {"Bucket": bucket}
            if self._region != "us-east-1":
                create_args["CreateBucketConfiguration"] = {"LocationConstraint": self._region}
            self._client.create_bucket(**create_args)

            # Enable Block Public Access
            self._client.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

            # Enable encryption
            self._client.put_bucket_encryption(
                Bucket=bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                },
            )

            # Enable versioning if configured
            if self._versioning:
                self._client.put_bucket_versioning(
                    Bucket=bucket,
                    VersioningConfiguration={"Status": "Enabled"},
                )

            return {
                "status": "created",
                "bucket": bucket,
                "message": f"Bucket '{bucket}' created with security controls.",
            }
        except Exception as e:
            return {"status": "error", "bucket": bucket, "message": str(e)}

    def upload_scan_report(self, local_dir: Path, scan_time: str = None, scan_mode: str = "ultra_micro") -> Dict[str, Any]:
        """Upload Prowler scan report files to S3."""
        if not self._client:
            return {"status": "error", "message": "S3 client not available"}

        bucket = self.bucket_name
        if not bucket:
            return {"status": "error", "message": "No bucket configured"}

        # Validate bucket is safe before upload
        validation = self.validate_bucket()
        if validation["status"] not in ("ready",):
            return {"status": "unsafe", "message": f"Bucket not safe for upload: {validation['message']}"}

        scan_time = scan_time or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
        prefix = f"{self._prefix}/scans/{self._account_id}/{scan_time}-{scan_mode}"

        uploaded_files = []
        try:
            for f in local_dir.iterdir():
                if f.is_file():
                    key = f"{prefix}/{f.name}"
                    self._client.upload_file(str(f), bucket, key)
                    uploaded_files.append(key)
                    logger.info("Uploaded %s to s3://%s/%s", f.name, bucket, key)
        except Exception as e:
            return {"status": "error", "message": f"Upload failed: {e}", "uploaded": uploaded_files}

        # Write manifest
        manifest = {
            "account_id": self._account_id,
            "region": self._region,
            "scan_time": scan_time,
            "storage_mode": "s3",
            "bucket": bucket,
            "prefix": prefix,
            "prowler_files": [f.name for f in local_dir.iterdir() if f.is_file()],
            "finding_count": 0,  # Updated after import
            "score_source": "Prowler findings from S3",
            "scoring_engine": "AWS Best-Practice Scoring Engine",
        }

        manifest_key = f"{prefix}/manifest.json"
        self._client.put_object(
            Bucket=bucket,
            Key=manifest_key,
            Body=json.dumps(manifest, indent=2),
            ContentType="application/json",
        )

        # Update mode-specific latest pointer
        latest = {"latest_prefix": prefix, "scan_time": scan_time, "manifest_key": manifest_key}
        mode_latest_key = f"{self._prefix}/latest-{scan_mode.replace('_', '-')}.json"
        self._client.put_object(
            Bucket=bucket,
            Key=mode_latest_key,
            Body=json.dumps(latest, indent=2),
            ContentType="application/json",
        )

        # Update global latest-scan.json (always points to most recent successful scan)
        latest_key = f"{self._prefix}/latest-scan.json"
        self._client.put_object(
            Bucket=bucket,
            Key=latest_key,
            Body=json.dumps(latest, indent=2),
            ContentType="application/json",
        )

        return {
            "status": "uploaded",
            "bucket": bucket,
            "prefix": prefix,
            "files": uploaded_files,
            "manifest_key": manifest_key,
        }

    def get_latest_scan(self) -> Dict[str, Any]:
        """Get the latest scan manifest from S3."""
        if not self._client:
            return {"status": "error", "message": "S3 client not available"}

        bucket = self.bucket_name
        if not bucket:
            return {"status": "not_configured", "message": "No bucket configured"}

        try:
            latest_key = f"{self._prefix}/latest-scan.json"
            obj = self._client.get_object(Bucket=bucket, Key=latest_key)
            latest = json.loads(obj["Body"].read())

            # Load manifest
            manifest_key = latest.get("manifest_key", "")
            if manifest_key:
                mobj = self._client.get_object(Bucket=bucket, Key=manifest_key)
                manifest = json.loads(mobj["Body"].read())
                return {"status": "found", "latest": latest, "manifest": manifest}
            return {"status": "found", "latest": latest}
        except self._client.exceptions.NoSuchKey:
            return {"status": "no_scans", "message": "No scans found in S3. Run a Prowler scan first."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def download_findings_json(self, prefix: str) -> Optional[str]:
        """Download the Prowler JSON findings from a scan prefix."""
        if not self._client:
            return None

        bucket = self.bucket_name
        try:
            # List objects in the prefix to find JSON file
            response = self._client.list_objects_v2(Bucket=bucket, Prefix=prefix)
            for obj in response.get("Contents", []):
                key = obj["Key"]
                if key.endswith(".json") and "manifest" not in key and "latest" not in key:
                    result = self._client.get_object(Bucket=bucket, Key=key)
                    return result["Body"].read().decode("utf-8")
        except Exception as e:
            logger.error("Failed to download findings from S3: %s", e)
        return None
