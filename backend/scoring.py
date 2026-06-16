"""Scoring Engine for calculating security posture maturity scores."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from backend.models import FindingStatus, NormalizedFinding, Severity
from backend.pillar_mapper import SecurityArea


@dataclass
class AreaScore:
    """Score result for a single security area."""

    area: SecurityArea
    score: Optional[float]  # None if not evaluated, 0.0-5.0 otherwise
    is_evaluated: bool
    passed_controls: int
    total_controls: int
    failed_findings: List[NormalizedFinding]
    top_failures: List[str]  # Top 3 failure descriptions
    explanation: str  # Human-readable score explanation

    @property
    def pillar(self) -> SecurityArea:
        """Backward-compatible alias for area."""
        return self.area


@dataclass
class PostureScore:
    """Overall security posture score across all areas."""

    overall_score: float  # Average of evaluated areas only
    area_scores: Dict[SecurityArea, AreaScore]
    total_findings: int
    total_passed: int
    total_failed: int
    critical_gaps: List[str]  # Top critical findings
    evaluated_area_count: int
    not_evaluated_areas: List[str]
    scoring_mode: str = "local_fallback"  # "mcp_enriched" or "local_fallback"

    @property
    def pillar_scores(self) -> Dict[SecurityArea, AreaScore]:
        """Backward-compatible alias for area_scores."""
        return self.area_scores


class ScoringEngine:
    """Calculates 0-5 maturity scores per area and overall posture."""

    SEVERITY_WEIGHTS: Dict[Severity, float] = {
        Severity.CRITICAL: 5.0,
        Severity.HIGH: 4.0,
        Severity.MEDIUM: 2.0,
        Severity.LOW: 1.0,
        Severity.INFORMATIONAL: 0.0,
    }

    def calculate_area_score(
        self, area: SecurityArea, findings: List[NormalizedFinding]
    ) -> AreaScore:
        """Calculate score for a single area.

        Formula: (Passed Weighted Points / Total Weighted Points) × 5

        If the area has zero findings, it is marked as not evaluated.

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
            weight = self.SEVERITY_WEIGHTS[finding.severity]
            total_weighted_points += weight
            if finding.status == FindingStatus.PASS:
                passed_weighted_points += weight
                passed_count += 1
            else:
                failed.append(finding)

        # If all findings are informational (weight 0), score is 0.0
        if total_weighted_points == 0.0:
            score = 0.0
        else:
            score = (passed_weighted_points / total_weighted_points) * 5.0

        # Clamp score between 0.0 and 5.0
        score = max(0.0, min(5.0, score))

        # Identify top 3 failures by severity weight (descending)
        sorted_failures = sorted(
            failed,
            key=lambda f: self.SEVERITY_WEIGHTS[f.severity],
            reverse=True,
        )
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
        """Calculate overall posture score from all area findings.

        Overall score is the average of ONLY evaluated areas (those with findings).

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
            as_.score for as_ in area_scores.values()
            if as_.is_evaluated and as_.score is not None
        ]
        evaluated_area_count = len(evaluated_scores)
        not_evaluated_areas = [
            as_.area.value for as_ in area_scores.values()
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

        # Identify critical gaps: top CRITICAL/HIGH failures across all areas
        all_failures: List[NormalizedFinding] = []
        for as_ in area_scores.values():
            for f in as_.failed_findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    all_failures.append(f)

        # Sort by severity weight descending, take top 10
        all_failures.sort(
            key=lambda f: self.SEVERITY_WEIGHTS[f.severity], reverse=True
        )
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
        )

    def simulate_improvement(
        self,
        current_score: PostureScore,
        remediated_finding_ids: List[str],
    ) -> PostureScore:
        """Simulate score improvement if specific findings were remediated.

        Takes a list of finding_ids that would be remediated. For each,
        treats the finding as PASS instead of FAIL and recalculates all scores.
        The simulated score is always >= the current score.

        Args:
            current_score: The current posture score with all findings.
            remediated_finding_ids: Finding IDs to treat as remediated.

        Returns:
            New PostureScore reflecting the simulated improvement.
        """
        remediated_set = set(remediated_finding_ids)

        simulated_area_scores: Dict[SecurityArea, AreaScore] = {}

        for area, area_score in current_score.area_scores.items():
            # Skip not-evaluated areas
            if not area_score.is_evaluated:
                simulated_area_scores[area] = area_score
                continue

            if area_score.total_controls == 0:
                simulated_area_scores[area] = area_score
                continue

            # If score is already perfect, no improvement possible
            if area_score.score is not None and area_score.score >= 5.0:
                simulated_area_scores[area] = area_score
                continue

            if area_score.score == 0.0:
                failed_total_weight = sum(
                    self.SEVERITY_WEIGHTS[f.severity]
                    for f in area_score.failed_findings
                )
                if failed_total_weight == 0.0:
                    # All informational, score stays 0
                    simulated_area_scores[area] = area_score
                    continue

            # Calculate total_weighted from the formula inversion
            failed_total_weight = sum(
                self.SEVERITY_WEIGHTS[f.severity]
                for f in area_score.failed_findings
            )

            current_area_score = area_score.score if area_score.score is not None else 0.0
            score_ratio = current_area_score / 5.0
            if score_ratio < 1.0:
                total_weighted = failed_total_weight / (1.0 - score_ratio)
            else:
                total_weighted = failed_total_weight

            passed_weighted = total_weighted - failed_total_weight

            # Now apply remediations
            remediated_weight = 0.0
            remaining_failed: List[NormalizedFinding] = []

            for finding in area_score.failed_findings:
                if finding.finding_id in remediated_set:
                    remediated_weight += self.SEVERITY_WEIGHTS[finding.severity]
                else:
                    remaining_failed.append(finding)

            new_passed_weighted = passed_weighted + remediated_weight
            # total_weighted stays the same (findings don't disappear, they flip status)

            if total_weighted == 0.0:
                new_score = 0.0
            else:
                new_score = (new_passed_weighted / total_weighted) * 5.0

            new_score = max(0.0, min(5.0, new_score))

            # Ensure simulated score >= current score
            new_score = max(new_score, current_area_score)

            new_passed_controls = area_score.passed_controls + (
                len(area_score.failed_findings) - len(remaining_failed)
            )

            # Top 3 failures from remaining
            sorted_remaining = sorted(
                remaining_failed,
                key=lambda f: self.SEVERITY_WEIGHTS[f.severity],
                reverse=True,
            )
            top_failures = [f.check_title for f in sorted_remaining[:3]]

            explanation = self._generate_explanation(
                area, new_score, new_passed_weighted, total_weighted, top_failures
            )

            simulated_area_scores[area] = AreaScore(
                area=area,
                score=round(new_score, 2),
                is_evaluated=True,
                passed_controls=new_passed_controls,
                total_controls=area_score.total_controls,
                failed_findings=remaining_failed,
                top_failures=top_failures,
                explanation=explanation,
            )

        # Recalculate overall from evaluated areas only
        evaluated_scores = [
            as_.score for as_ in simulated_area_scores.values()
            if as_.is_evaluated and as_.score is not None
        ]
        evaluated_area_count = len(evaluated_scores)
        not_evaluated_areas = [
            as_.area.value for as_ in simulated_area_scores.values()
            if not as_.is_evaluated
        ]

        if evaluated_area_count > 0:
            overall_sim = round(sum(evaluated_scores) / evaluated_area_count, 2)
        else:
            overall_sim = 0.0

        # Ensure overall >= current
        overall_sim = max(overall_sim, current_score.overall_score)

        total_findings = sum(
            as_.total_controls for as_ in simulated_area_scores.values()
        )
        total_passed = sum(
            as_.passed_controls for as_ in simulated_area_scores.values()
        )
        total_failed = sum(
            len(as_.failed_findings) for as_ in simulated_area_scores.values()
        )

        # Critical gaps from remaining failures
        all_remaining_failures: List[NormalizedFinding] = []
        for as_ in simulated_area_scores.values():
            for f in as_.failed_findings:
                if f.severity in (Severity.CRITICAL, Severity.HIGH):
                    all_remaining_failures.append(f)

        all_remaining_failures.sort(
            key=lambda f: self.SEVERITY_WEIGHTS[f.severity], reverse=True
        )
        critical_gaps = [f.check_title for f in all_remaining_failures[:10]]

        return PostureScore(
            overall_score=overall_sim,
            area_scores=simulated_area_scores,
            total_findings=total_findings,
            total_passed=total_passed,
            total_failed=total_failed,
            critical_gaps=critical_gaps,
            evaluated_area_count=evaluated_area_count,
            not_evaluated_areas=not_evaluated_areas,
        )

    def _generate_explanation(
        self,
        area: SecurityArea,
        score: float,
        passed_weighted: float,
        total_weighted: float,
        top_failures: List[str],
    ) -> str:
        """Generate a human-readable explanation for an area score.

        Args:
            area: The security area.
            score: Computed score (0.0-5.0).
            passed_weighted: Sum of weighted points for passed findings.
            total_weighted: Sum of all weighted points.
            top_failures: Top failure descriptions.

        Returns:
            Human-readable explanation string.
        """
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

    # Backward-compatible method alias
    def calculate_pillar_score(
        self, pillar: SecurityArea, findings: List[NormalizedFinding]
    ) -> "AreaScore":
        """Backward-compatible alias for calculate_area_score."""
        return self.calculate_area_score(pillar, findings)


# Backward compatibility
PillarScore = AreaScore
