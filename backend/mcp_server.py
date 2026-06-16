"""Internal posture data service for the AI assistant to query posture data.

The MCPServer class provides read-only methods used by the REST API and
the Bedrock assistant for direct method calls. There is no MCP protocol
transport — the Bedrock assistant calls these as plain Python functions.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.models import NormalizedFinding, Severity
from backend.pillar_mapper import SecurityAreaMapper, SecurityArea
from backend.scoring import AreaScore, PostureScore, ScoringEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _score_label(score: float) -> str:
    """Return the human-readable label for a numeric score.

    Labels:
        0-1: "Critical Gaps"
        1-2: "Needs Attention"
        2-3: "Developing"
        3-4: "Strong"
        4-5: "Optimized"
    """
    if score < 1.0:
        return "Critical Gaps"
    elif score < 2.0:
        return "Needs Attention"
    elif score < 3.0:
        return "Developing"
    elif score < 4.0:
        return "Strong"
    else:
        return "Optimized"


def _difficulty_for_severity(severity: Severity) -> str:
    """Assign remediation difficulty based on finding severity.

    Mapping:
        Critical -> "High"
        High -> "Medium"
        Medium -> "Low"
        Low -> "Low"
        Informational -> "Low"
    """
    if severity == Severity.CRITICAL:
        return "High"
    elif severity == Severity.HIGH:
        return "Medium"
    else:
        return "Low"


def _estimated_improvement(severity: Severity, total_findings: int) -> float:
    """Estimate score improvement from remediating a single finding.

    Uses severity weight relative to total findings as a rough estimate.
    """
    weight = ScoringEngine.SEVERITY_WEIGHTS[severity]
    if total_findings == 0:
        return 0.0
    return round(weight / max(total_findings, 1) * 0.5, 2)


# ---------------------------------------------------------------------------
# Pipeline initialization (module-level state for MCP tools)
# ---------------------------------------------------------------------------


def _run_pipeline() -> tuple:
    """Run the full import → normalize → map → score pipeline.

    Returns:
        Tuple of (ScoringEngine, PostureScore).
    """
    from backend.importer import ProwlerImporter
    from backend.normalizer import Normalizer

    # Determine data directory relative to project root
    project_root = Path(__file__).parent.parent
    data_dir = project_root / "sample-data" / "prowler-output"

    importer = ProwlerImporter(data_dir)
    raw_findings = importer.load_findings()

    normalizer = Normalizer()
    normalized = normalizer.normalize_batch(raw_findings)

    mapper = SecurityAreaMapper()
    pillar_findings = mapper.map_batch(normalized)

    engine = ScoringEngine()
    posture = engine.calculate_posture(pillar_findings)

    return engine, posture


# Module-level state — populated on first import or when run standalone
_engine: Optional[ScoringEngine] = None
_posture: Optional[PostureScore] = None


def _ensure_state() -> tuple:
    """Ensure module-level state is initialized."""
    global _engine, _posture
    if _engine is None or _posture is None:
        _engine, _posture = _run_pipeline()
    return _engine, _posture


# ---------------------------------------------------------------------------
# MCPServer class (backward-compatible interface for REST API)
# ---------------------------------------------------------------------------


class MCPServer:
    """Read-only MCP tool server for querying security posture data.

    Exposes exactly 7 tools. All tools are read-only and return
    structured JSON (dicts/lists). Used by the REST API.
    """

    def __init__(self, scoring_engine: ScoringEngine, posture_score: PostureScore):
        """Initialize MCP server with computed posture data.

        Args:
            scoring_engine: The scoring engine instance for simulation.
            posture_score: The pre-computed posture score data.
        """
        self._scoring_engine = scoring_engine
        self._posture_score = posture_score

    @property
    def _posture(self) -> PostureScore:
        """Expose posture score for backward compatibility with api.py."""
        return self._posture_score

    def get_overall_posture_score(self) -> Dict[str, Any]:
        """Return overall score with summary."""
        return _get_overall_posture_score_impl(self._posture_score)

    def get_domain_scores(self) -> Dict[str, Any]:
        """Return all 5 area scores with details."""
        return _get_domain_scores_impl(self._posture_score)

    def get_top_security_gaps(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Return top N security gaps sorted by severity."""
        return _get_top_security_gaps_impl(self._posture_score, limit)

    def explain_score(self, pillar: Optional[str] = None) -> Dict[str, Any]:
        """Explain overall or specific pillar score."""
        return _explain_score_impl(self._posture_score, pillar)

    def get_remediation_plan(self) -> List[Dict[str, Any]]:
        """Return prioritized remediation actions."""
        return _get_remediation_plan_impl(self._posture_score)

    def simulate_score_improvement(
        self, remediation_ids: List[str]
    ) -> Dict[str, Any]:
        """Simulate score improvement for specific finding remediations."""
        return _simulate_score_improvement_impl(
            self._scoring_engine, self._posture_score, remediation_ids
        )

    def generate_executive_summary(self) -> str:
        """Generate executive summary text."""
        return _generate_executive_summary_impl(self._posture_score)


# ---------------------------------------------------------------------------
# Shared tool implementation functions
# ---------------------------------------------------------------------------


def _get_overall_posture_score_impl(ps: PostureScore) -> Dict[str, Any]:
    """Implementation for get_overall_posture_score."""
    # Find the pillar with the lowest score that has findings (evaluated areas only)
    evaluated_areas = [
        a_score
        for a_score in ps.area_scores.values()
        if a_score.is_evaluated and a_score.score is not None
    ]
    if evaluated_areas:
        top_impacted_pillar = min(
            evaluated_areas, key=lambda a: a.score  # type: ignore[arg-type]
        ).area.value
    else:
        # Fallback: pick first area
        top_impacted_pillar = list(ps.area_scores.values())[0].area.value

    return {
        "overall_score": ps.overall_score,
        "score_label": _score_label(ps.overall_score),
        "total_findings": ps.total_findings,
        "total_passed": ps.total_passed,
        "total_failed": ps.total_failed,
        "critical_gaps_count": len(ps.critical_gaps),
        "top_impacted_pillar": top_impacted_pillar,
        "evaluated_area_count": ps.evaluated_area_count,
        "not_evaluated_areas": ps.not_evaluated_areas,
    }


def _get_domain_scores_impl(ps: PostureScore) -> Dict[str, Any]:
    """Implementation for get_domain_scores."""
    from backend.aws_best_practice_docs import get_docs_for_finding

    pillars = []
    for area in SecurityArea:
        area_score = ps.area_scores[area]

        if area_score.failed_findings:
            top_finding = max(
                area_score.failed_findings,
                key=lambda f: ScoringEngine.SEVERITY_WEIGHTS[f.severity],
            )
            recommended_action = (
                top_finding.remediation_text
                if top_finding.remediation_text
                else f"Address: {top_finding.check_title}"
            )
        else:
            recommended_action = "Maintain current controls and monitor for changes"

        # Build grouped_findings: deduplicate by check_id, count affected resources
        grouped_findings = _build_grouped_findings(area_score.failed_findings, area.value)

        pillars.append({
            "name": area.value,
            "score": area_score.score,
            "is_evaluated": area_score.is_evaluated,
            "explanation": area_score.explanation,
            "top_failures": area_score.top_failures,  # Retained for backward compat
            "grouped_findings": grouped_findings,
            "passed_controls": area_score.passed_controls,
            "total_controls": area_score.total_controls,
            "recommended_action": recommended_action,
        })

    return {"pillars": pillars}


def _build_grouped_findings(
    failed_findings: List[Any], pillar: str
) -> List[Dict[str, Any]]:
    """Group failed findings by check_id, deduplicating repeated controls.

    Returns a list of grouped finding objects sorted by severity (highest first),
    then by count (most affected resources first). Limited to top 5 groups.
    """
    from backend.aws_best_practice_docs import get_docs_for_finding

    if not failed_findings:
        return []

    # Group by check_id (stable key)
    groups: Dict[str, Dict[str, Any]] = {}
    for f in failed_findings:
        key = f.check_id if f.check_id else f.check_title
        if key not in groups:
            groups[key] = {
                "check_id": f.check_id,
                "check_title": f.check_title,
                "severity": f.severity.value,
                "severity_weight": ScoringEngine.SEVERITY_WEIGHTS[f.severity],
                "remediation_text": f.remediation_text or f"Remediate: {f.check_title}",
                "service": f.service,
                "count": 0,
                "resources": [],
            }
        groups[key]["count"] += 1
        groups[key]["resources"].append({
            "resource_arn": f.resource_arn,
            "region": f.region,
            "service": f.service,
            "finding_id": f.finding_id,
        })
        # Use highest severity in the group
        current_weight = ScoringEngine.SEVERITY_WEIGHTS.get(
            next((s for s in ScoringEngine.SEVERITY_WEIGHTS if s.value == groups[key]["severity"]), f.severity),
            0,
        )
        new_weight = ScoringEngine.SEVERITY_WEIGHTS[f.severity]
        if new_weight > groups[key]["severity_weight"]:
            groups[key]["severity"] = f.severity.value
            groups[key]["severity_weight"] = new_weight

    # Build final list with doc links
    result = []
    for key, group in groups.items():
        doc_links_raw = get_docs_for_finding(
            check_id=group["check_id"],
            service=group["service"],
            pillar=pillar,
        )
        doc_links = [
            {"title": d.title, "url": d.url, "reason": d.reason, "category": d.category}
            for d in doc_links_raw
        ]

        result.append({
            "check_id": group["check_id"],
            "check_title": group["check_title"],
            "severity": group["severity"],
            "count": group["count"],
            "remediation_text": group["remediation_text"],
            "doc_links": doc_links,
            "source_attribution": "Prowler finding · AWS best-practice mapping" + (" · Official AWS docs" if doc_links else ""),
            "resources": group["resources"][:10],  # Limit to 10 resources in response
        })

    # Sort by severity weight desc, then count desc
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
    result.sort(key=lambda g: (severity_order.get(g["severity"], 0), g["count"]), reverse=True)

    return result[:5]  # Top 5 groups


def _get_top_security_gaps_impl(
    ps: PostureScore, limit: int = 5
) -> List[Dict[str, Any]]:
    """Implementation for get_top_security_gaps."""
    all_failed: List[tuple] = []
    for area, area_score in ps.area_scores.items():
        for finding in area_score.failed_findings:
            all_failed.append((finding, area))

    all_failed.sort(
        key=lambda item: ScoringEngine.SEVERITY_WEIGHTS[item[0].severity],
        reverse=True,
    )

    gaps = []
    for finding, area in all_failed[:limit]:
        gaps.append({
            "finding_id": finding.finding_id,
            "title": finding.check_title,
            "severity": finding.severity.value,
            "pillar": area.value,
            "description": finding.description,
            "remediation": finding.remediation_text or f"Remediate: {finding.check_title}",
        })

    return gaps


def _explain_score_impl(
    ps: PostureScore, pillar: Optional[str] = None
) -> Dict[str, Any]:
    """Implementation for explain_score."""
    if pillar is None:
        contributing_factors = []
        for p in SecurityArea:
            a_score = ps.area_scores[p]
            if a_score.is_evaluated and a_score.score is not None:
                contributing_factors.append({
                    "pillar": p.value,
                    "score": a_score.score,
                    "impact": (
                        "dragging down"
                        if a_score.score < ps.overall_score
                        else "above average"
                    ),
                })
            else:
                contributing_factors.append({
                    "pillar": p.value,
                    "score": None,
                    "impact": "not evaluated",
                })

        return {
            "score": ps.overall_score,
            "label": _score_label(ps.overall_score),
            "explanation": (
                f"Overall score of {ps.overall_score}/5.0 "
                f"({_score_label(ps.overall_score)}) is the average of "
                f"{ps.evaluated_area_count} evaluated area scores. "
                f"{ps.total_passed} of {ps.total_findings} "
                f"controls are passing."
            ),
            "contributing_factors": contributing_factors,
        }
    else:
        target_pillar = _find_pillar(pillar)
        if target_pillar is None:
            return {
                "error": (
                    f"Unknown pillar: '{pillar}'. Valid pillars: "
                    f"{[p.value for p in SecurityArea]}"
                ),
            }

        area_score = ps.area_scores[target_pillar]
        return {
            "pillar": target_pillar.value,
            "score": area_score.score,
            "is_evaluated": area_score.is_evaluated,
            "label": _score_label(area_score.score) if area_score.score is not None else "Not Evaluated",
            "explanation": area_score.explanation,
            "passed_controls": area_score.passed_controls,
            "total_controls": area_score.total_controls,
            "top_failures": area_score.top_failures,
        }


def _get_remediation_plan_impl(ps: PostureScore) -> List[Dict[str, Any]]:
    """Implementation for get_remediation_plan."""
    actions: List[Dict[str, Any]] = []

    for area, area_score in ps.area_scores.items():
        for finding in area_score.failed_findings:
            improvement = _estimated_improvement(
                finding.severity, ps.total_findings
            )
            actions.append({
                "action": (
                    finding.remediation_text
                    or f"Remediate: {finding.check_title}"
                ),
                "pillar": area.value,
                "difficulty": _difficulty_for_severity(finding.severity),
                "estimated_improvement": improvement,
                "finding_id": finding.finding_id,
            })

    # Sort by severity weight descending (Critical first)
    severity_order = {
        "High": 0,
        "Medium": 1,
        "Low": 2,
    }
    actions.sort(key=lambda a: severity_order.get(a["difficulty"], 3))
    return actions


def _simulate_score_improvement_impl(
    engine: ScoringEngine, ps: PostureScore, finding_ids: List[str]
) -> Dict[str, Any]:
    """Implementation for simulate_score_improvement."""
    simulated = engine.simulate_improvement(ps, finding_ids)

    pillar_improvements = []
    for area in SecurityArea:
        current_area = ps.area_scores[area]
        simulated_area = simulated.area_scores[area]
        # Skip not-evaluated areas or areas with None scores
        if not current_area.is_evaluated or current_area.score is None:
            continue
        if simulated_area.score is not None and simulated_area.score > current_area.score:
            pillar_improvements.append({
                "pillar": area.value,
                "current_score": current_area.score,
                "simulated_score": simulated_area.score,
                "improvement": round(
                    simulated_area.score - current_area.score, 2
                ),
            })

    return {
        "current_score": ps.overall_score,
        "simulated_score": simulated.overall_score,
        "improvement": round(simulated.overall_score - ps.overall_score, 2),
        "current_label": _score_label(ps.overall_score),
        "simulated_label": _score_label(simulated.overall_score),
        "pillar_improvements": pillar_improvements,
    }


def _generate_executive_summary_impl(ps: PostureScore) -> str:
    """Implementation for generate_executive_summary."""
    label = _score_label(ps.overall_score)

    # Only consider evaluated areas for weakest/strongest
    evaluated_areas = [
        a_score for a_score in ps.area_scores.values()
        if a_score.is_evaluated and a_score.score is not None
    ]

    if evaluated_areas:
        sorted_areas = sorted(evaluated_areas, key=lambda a: a.score)  # type: ignore[arg-type]
        weakest = sorted_areas[0]
        strongest = sorted_areas[-1]
    else:
        # Fallback if nothing is evaluated
        all_areas = list(ps.area_scores.values())
        weakest = all_areas[0]
        strongest = all_areas[-1]

    critical_high_count = 0
    for area_score in ps.area_scores.values():
        for f in area_score.failed_findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                critical_high_count += 1

    summary_lines = [
        "Security Posture Executive Summary",
        "=" * 40,
        "",
        f"Overall Score: {ps.overall_score}/5.0 ({label})",
        "",
        "Findings Overview:",
        f"  - Total Controls Evaluated: {ps.total_findings}",
        f"  - Passing: {ps.total_passed}",
        f"  - Failing: {ps.total_failed}",
        f"  - Critical/High Failures: {critical_high_count}",
        f"  - Evaluated Areas: {ps.evaluated_area_count}/5",
        "",
        f"Weakest Area: {weakest.area.value} (Score: {weakest.score}/5.0)",
        f"Strongest Area: {strongest.area.value} (Score: {strongest.score}/5.0)",
        "",
        "Key Recommendations:",
    ]

    plan = _get_remediation_plan_impl(ps)
    for i, action in enumerate(plan[:3], 1):
        summary_lines.append(
            f"  {i}. [{action['difficulty']} difficulty] {action['action']}"
        )

    summary_lines.extend([
        "",
        f"Next Steps: Focus on {weakest.area.value} to achieve the "
        f"greatest score improvement.",
    ])

    return "\n".join(summary_lines)


def _find_pillar(pillar_name: str) -> Optional[SecurityArea]:
    """Find a SecurityArea by its display name (case-insensitive)."""
    normalized = pillar_name.strip().lower()
    for pillar in SecurityArea:
        if pillar.value.lower() == normalized:
            return pillar
    return None
