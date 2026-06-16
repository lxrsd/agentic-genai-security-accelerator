"""AWS Best-Practice Scoring Engine.

Replaces the generic ScoringEngine with AWS-aligned scoring using
best-practice control metadata from the AWSBestPracticeCatalog.

Scoring is deterministic. Bedrock does not influence numeric scores.
MCP enriches control metadata and remediation context, not the calculation itself.
"""

from typing import Dict, List

from backend.aws_best_practice_catalog import AWSBestPracticeCatalog
from backend.control_metadata import ControlMetadata
from backend.models import FindingStatus, NormalizedFinding, Severity
from backend.pillar_mapper import SecurityArea
from backend.scoring import AreaScore, PostureScore, ScoringEngine


class AWSBestPracticeScoringEngine:
    """AWS-aligned scoring engine using best-practice control metadata.

    Uses the AWSBestPracticeCatalog to map findings to controls with
    impact weights and severity weights, producing weighted scores that
    reflect AWS best-practice criticality.

    Scoring is deterministic. MCP enriches metadata context only.
    """

    def __init__(self, catalog: AWSBestPracticeCatalog) -> None:
        """Initialize with an AWS best-practice catalog.

        Args:
            catalog: The catalog providing control metadata for scoring.
        """
        self._catalog = catalog
        # Keep a ScoringEngine internally for simulate_improvement compatibility
        self._base_engine = ScoringEngine()

    @property
    def scoring_mode(self) -> str:
        """Return the current scoring mode from the catalog."""
        return self._catalog.get_scoring_mode()

    @property
    def scoring_mode_display(self) -> str:
        """Return human-readable scoring mode description."""
        return self._catalog.get_scoring_mode_display()

    def calculate_area_score(
        self, area: SecurityArea, findings: List[NormalizedFinding]
    ) -> AreaScore:
        """Calculate score for a single security area using AWS best-practice weights.

        Formula: (sum of weights for PASS) / (sum of weights for all non-info) * 5

        For each finding, looks up its ControlMetadata to get impact_weight
        and severity_weight. The effective weight is:
            impact_weight * severity_weight / 5.0

        This ensures that both the control's criticality AND the finding's
        severity contribute to the weighted score.

        Args:
            area: The security area being scored.
            findings: All findings mapped to this area.

        Returns:
            AreaScore with computed score, counts, and explanation.
        """
        if not findings:
            return AreaScore(
                area=area,
                score=None,
                is_evaluated=False,
                passed_controls=0,
                total_controls=0,
                failed_findings=[],
                top_failures=[],
                explanation="Not Evaluated — no Prowler findings mapped to this area",
            )

        total_weighted_points = 0.0
        passed_weighted_points = 0.0
        failed: List[NormalizedFinding] = []
        passed_count = 0

        for finding in findings:
            control = self._catalog.get_control_for_finding(finding)
            # Effective weight combines impact and severity
            weight = (control.impact_weight * control.severity_weight) / 5.0

            # Skip zero-weight findings (informational)
            if weight <= 0.0:
                if finding.status == FindingStatus.PASS:
                    passed_count += 1
                continue

            total_weighted_points += weight
            if finding.status == FindingStatus.PASS:
                passed_weighted_points += weight
                passed_count += 1
            else:
                failed.append(finding)

        # If all findings are zero weight, score is 0.0
        if total_weighted_points == 0.0:
            score = 0.0
        else:
            score = (passed_weighted_points / total_weighted_points) * 5.0

        # Clamp score between 0.0 and 5.0
        score = max(0.0, min(5.0, score))

        # Sort failures by effective weight descending for top failures
        def _failure_weight(f: NormalizedFinding) -> float:
            c = self._catalog.get_control_for_finding(f)
            return (c.impact_weight * c.severity_weight) / 5.0

        sorted_failures = sorted(failed, key=_failure_weight, reverse=True)
        top_failures = [f.check_title for f in sorted_failures[:3]]

        explanation = self._generate_explanation(
            area, score, passed_weighted_points, total_weighted_points, top_failures
        )

        return AreaScore(
            area=area,
            score=round(score, 2),
            is_evaluated=True,
            passed_controls=passed_count,
            total_controls=len(findings),
            failed_findings=failed,
            top_failures=top_failures,
            explanation=explanation,
        )

    def calculate_posture(
        self, pillar_findings: Dict[SecurityArea, List[NormalizedFinding]]
    ) -> PostureScore:
        """Calculate overall posture from all area findings.

        Uses AWS best-practice weighted controls for each area. Overall score
        is the average of ONLY evaluated areas (those with findings).

        Args:
            pillar_findings: Dictionary mapping each area to its findings.

        Returns:
            PostureScore with overall score and per-area breakdown.
        """
        area_scores: Dict[SecurityArea, AreaScore] = {}

        for area in SecurityArea:
            findings = pillar_findings.get(area, [])
            area_scores[area] = self.calculate_area_score(area, findings)

        # Overall = average of evaluated area scores only
        evaluated_scores = [
            as_.score
            for as_ in area_scores.values()
            if as_.is_evaluated and as_.score is not None
        ]
        evaluated_area_count = len(evaluated_scores)
        not_evaluated_areas = [
            as_.area.value
            for as_ in area_scores.values()
            if not as_.is_evaluated
        ]

        if evaluated_area_count > 0:
            overall_score = round(sum(evaluated_scores) / evaluated_area_count, 2)
        else:
            overall_score = 0.0

        # Aggregate counts
        total_findings = 0
        total_passed = 0
        total_failed = 0

        for as_ in area_scores.values():
            total_findings += as_.total_controls
            total_passed += as_.passed_controls
            total_failed += len(as_.failed_findings)

        # Identify critical gaps
        all_failures: List[NormalizedFinding] = []
        for as_ in area_scores.values():
            for f in as_.failed_findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    all_failures.append(f)

        def _failure_weight(f: NormalizedFinding) -> float:
            c = self._catalog.get_control_for_finding(f)
            return (c.impact_weight * c.severity_weight) / 5.0

        all_failures.sort(key=_failure_weight, reverse=True)
        critical_gaps = [f.check_title for f in all_failures[:10]]

        return PostureScore(
            overall_score=overall_score,
            area_scores=area_scores,
            total_findings=total_findings,
            total_passed=total_passed,
            total_failed=total_failed,
            critical_gaps=critical_gaps,
            evaluated_area_count=evaluated_area_count,
            not_evaluated_areas=not_evaluated_areas,
            scoring_mode=self.scoring_mode,
        )

    def simulate_improvement(
        self,
        current_score: PostureScore,
        remediated_finding_ids: List[str],
    ) -> PostureScore:
        """Simulate score improvement if specific findings were remediated.

        Delegates to the base ScoringEngine for simulation logic,
        then updates the scoring_mode field.

        Args:
            current_score: The current posture score with all findings.
            remediated_finding_ids: Finding IDs to treat as remediated.

        Returns:
            New PostureScore reflecting the simulated improvement.
        """
        result = self._base_engine.simulate_improvement(
            current_score, remediated_finding_ids
        )
        result.scoring_mode = self.scoring_mode
        return result

    # Backward-compatible aliases
    def calculate_pillar_score(
        self, pillar: SecurityArea, findings: List[NormalizedFinding]
    ) -> AreaScore:
        """Backward-compatible alias for calculate_area_score."""
        return self.calculate_area_score(pillar, findings)

    def _generate_explanation(
        self,
        area: SecurityArea,
        score: float,
        passed_weighted: float,
        total_weighted: float,
        top_failures: List[str],
    ) -> str:
        """Generate a human-readable explanation for an area score."""
        passed = round(passed_weighted, 1)
        total = round(total_weighted, 1)
        area_name = area.value

        if score < 1.0:
            failures_str = ", ".join(top_failures) if top_failures else "N/A"
            return (
                f"Critical Gaps: {area_name} has significant security deficiencies. "
                f"Only {passed} of {total} weighted control points are passing. "
                f"Key issues: {failures_str}"
            )
        elif score < 2.0:
            return (
                f"Needs Attention: {area_name} has basic visibility but many gaps "
                f"remain. {passed} of {total} weighted control points passing."
            )
        elif score < 3.0:
            return (
                f"Developing: {area_name} has foundational controls but posture is "
                f"inconsistent. {passed} of {total} weighted control points passing."
            )
        elif score < 4.0:
            return (
                f"Strong: {area_name} has key controls in place with limited gaps. "
                f"{passed} of {total} weighted control points passing."
            )
        else:
            return (
                f"Optimized: {area_name} is well-aligned to security best practices. "
                f"{passed} of {total} weighted control points passing."
            )
