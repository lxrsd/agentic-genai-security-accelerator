"""Prowler Importer - loads and validates Prowler JSON findings from disk."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class ProwlerImporter:
    """Loads raw Prowler JSON output files and returns validated finding dicts."""

    def __init__(self, data_dir: Path):
        """Initialize with path to prowler-output directory.

        Args:
            data_dir: Path to the directory containing Prowler JSON output files.
        """
        self.data_dir = Path(data_dir)

    def load_findings(self) -> List[Dict[str, Any]]:
        """Load all Prowler JSON files and return raw finding dicts.

        Reads all .json files from the configured directory, parses them,
        validates each finding, and returns the list of valid findings.
        Malformed JSON files are logged and skipped. Invalid findings
        (missing required fields) are logged and skipped.

        Returns:
            A list of validated raw finding dictionaries.
        """
        validated_findings: List[Dict[str, Any]] = []

        json_files = sorted(self.data_dir.glob("*.json"))
        
        # Also search subdirectories (Prowler 5.x nests output in subfolders)
        if not json_files:
            json_files = sorted(self.data_dir.rglob("*.json"))

        if not json_files:
            logger.warning("No JSON files found in %s", self.data_dir)
            return validated_findings

        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(
                    "Skipping malformed JSON file %s: %s", json_file.name, e
                )
                continue

            # Handle both single findings and arrays of findings
            if isinstance(data, list):
                findings = data
            elif isinstance(data, dict):
                findings = [data]
            else:
                logger.warning(
                    "Skipping %s: unexpected JSON structure (expected object or array)",
                    json_file.name,
                )
                continue

            for finding in findings:
                if self.validate_format(finding):
                    validated_findings.append(finding)
                else:
                    finding_id = self._extract_finding_id(finding)
                    logger.warning(
                        "Skipping finding %s in %s: missing required fields",
                        finding_id or "<unknown>",
                        json_file.name,
                    )

        return validated_findings

    def validate_format(self, raw_finding: Dict[str, Any]) -> bool:
        """Check if a raw finding has the minimum required fields.

        Supports both Prowler 3.x format and Prowler 5.x OCSF format.

        Args:
            raw_finding: A dictionary representing a single Prowler finding.

        Returns:
            True if all required fields are present, False otherwise.
        """
        if not isinstance(raw_finding, dict):
            return False

        # Try Prowler 5.x OCSF format first
        if "status_code" in raw_finding and "metadata" in raw_finding:
            metadata = raw_finding.get("metadata", {})
            if metadata.get("event_code"):
                return True
            finding_info = raw_finding.get("finding_info", {})
            if finding_info.get("uid"):
                return True

        # Prowler 3.x format
        for field in ("StatusCode", "Severity", "ServiceName"):
            if field not in raw_finding:
                return False

        # Check nested FindingInfo.FindingId
        finding_info = raw_finding.get("FindingInfo")
        if not isinstance(finding_info, dict):
            return False

        if "FindingId" not in finding_info:
            return False

        return True

    @staticmethod
    def _extract_finding_id(finding: Dict[str, Any]) -> str | None:
        """Try to extract FindingId for logging purposes."""
        finding_info = finding.get("FindingInfo")
        if isinstance(finding_info, dict):
            return finding_info.get("FindingId")
        return None
