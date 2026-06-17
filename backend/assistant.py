"""Simulated Security Assistant using MCP tools for grounded responses."""

from typing import List, Optional

from backend.mcp_server import MCPServer


# ---------------------------------------------------------------------------
# Intent classification keywords
# ---------------------------------------------------------------------------

_INTENT_KEYWORDS = {
    "score": ["score", "overall", "rating", "grade", "how am i doing"],
    "gaps": ["gaps", "risks", "findings", "failing", "problems", "issues", "hurting"],
    "remediation": ["fix", "remediate", "improve", "action", "plan", "should i do", "what next"],
    "explain_pillar": [
        "identity", "data", "network", "vulnerability",
        "incident", "why is",
    ],
    "simulate": ["simulate", "what if", "after fixing", "would be", "projection"],
    "summary": ["summarize", "leadership", "executive", "report", "brief"],
}

# Keywords for mapping user terms to finding ID substrings (simulate intent)
_FINDING_TERM_MAP = {
    "mfa": "mfa",
    "cloudtrail": "cloudtrail",
    "s3": "s3-public",
    "public": "s3-public",
    "encryption": "encryption",
    "kms": "encryption",
    "guardduty": "guardduty",
}

# Area name fragments for detecting which area the user asks about
_PILLAR_FRAGMENTS = [
    "identity",
    "data",
    "network",
    "vulnerability",
    "incident",
]

_PILLAR_DISPLAY_MAP = {
    "identity": "Identity & Access",
    "data": "Data Protection",
    "network": "Network Security",
    "vulnerability": "Vulnerability Management",
    "incident": "Incident Readiness",
}


class SimulatedAssistant:
    """Simulated assistant that answers security posture questions by calling MCP tool methods.

    Classifies user intent via keyword matching and generates grounded
    responses from actual posture data.
    """

    def __init__(self, mcp_server: MCPServer):
        """Initialize with MCP server instance for data access."""
        self._mcp = mcp_server

    def respond(self, user_message: str) -> str:
        """Generate a response grounded in posture data.

        Classifies user intent and routes to the appropriate handler.
        Every response includes a [Simulated Assistant] indicator and
        a production note about Amazon Bedrock.
        """
        intent = self._classify_intent(user_message)

        handlers = {
            "score": self._handle_score,
            "gaps": self._handle_gaps,
            "remediation": self._handle_remediation,
            "explain_pillar": self._handle_explain_pillar,
            "simulate": self._handle_simulate,
            "summary": self._handle_summary,
        }

        handler = handlers.get(intent)
        if handler:
            if intent == "explain_pillar":
                body = handler(user_message)
            elif intent == "simulate":
                body = handler(user_message)
            else:
                body = handler()
        else:
            body = self._handle_general()

        return self._wrap_response(body)

    # ------------------------------------------------------------------
    # Intent classification
    # ------------------------------------------------------------------

    def _classify_intent(self, message: str) -> str:
        """Classify user message intent using keyword matching."""
        lower = message.lower()

        # Check simulate first (higher priority to avoid "fix" matching remediation)
        for keyword in _INTENT_KEYWORDS["simulate"]:
            if keyword in lower:
                return "simulate"

        # Check explain_pillar before general keyword matches
        for keyword in _INTENT_KEYWORDS["explain_pillar"]:
            if keyword in lower:
                return "explain_pillar"

        # Check remaining intents in priority order
        for intent in ["score", "gaps", "remediation", "summary"]:
            for keyword in _INTENT_KEYWORDS[intent]:
                if keyword in lower:
                    return intent

        return "general"

    # ------------------------------------------------------------------
    # Intent handlers
    # ------------------------------------------------------------------

    def _handle_score(self) -> str:
        """Handle score intent using MCP tools."""
        score_data = self._mcp.get_overall_posture_score()
        explain_data = self._mcp.explain_score()

        overall = score_data["overall_score"]
        label = score_data["score_label"]
        top_pillar = score_data["top_impacted_pillar"]
        explanation = explain_data["explanation"]

        return (
            f"Your overall security posture score is {overall}/5.0 ({label}). "
            f"{explanation}. The most impacted pillar is {top_pillar}."
        )

    def _handle_gaps(self) -> str:
        """Handle gaps intent using MCP tools."""
        gaps = self._mcp.get_top_security_gaps(limit=5)

        if not gaps:
            return "No security gaps found. Your posture looks strong!"

        lines = ["Here are your top security gaps:\n"]
        for i, gap in enumerate(gaps, 1):
            lines.append(
                f"{i}. [{gap['severity']}] {gap['title']} "
                f"(Pillar: {gap['pillar']})"
            )

        return "\n".join(lines)

    def _handle_remediation(self) -> str:
        """Handle remediation intent using MCP tools."""
        plan = self._mcp.get_remediation_plan()

        if not plan:
            return "No remediation actions needed. Your posture is strong!"

        lines = ["Here's your prioritized remediation plan:\n"]
        for i, action in enumerate(plan[:5], 1):
            lines.append(
                f"{i}. [{action['difficulty']} difficulty] {action['action']} "
                f"(Pillar: {action['pillar']})"
            )

        return "\n".join(lines)

    def _handle_explain_pillar(self, message: str) -> str:
        """Handle explain_pillar intent by detecting and explaining a specific pillar."""
        pillar_name = self._detect_pillar(message)

        if pillar_name:
            data = self._mcp.explain_score(pillar=pillar_name)
            if "error" in data:
                return data["error"]
            return (
                f"Pillar: {data['pillar']} — Score: {data['score']}/5.0 ({data['label']})\n"
                f"{data['explanation']}\n"
                f"Passed controls: {data['passed_controls']}/{data['total_controls']}"
            )
        else:
            # No specific pillar detected — explain overall
            data = self._mcp.explain_score()
            return data["explanation"]

    def _handle_simulate(self, message: str) -> str:
        """Handle simulate intent by detecting findings to remediate."""
        finding_ids = self._detect_finding_ids(message)

        if not finding_ids:
            return (
                "I couldn't identify which findings to simulate. "
                "Try mentioning specific items like MFA, CloudTrail, S3, "
                "encryption, or GuardDuty."
            )

        data = self._mcp.simulate_score_improvement(finding_ids)

        items_desc = ", ".join(finding_ids)
        current = data["current_score"]
        simulated = data["simulated_score"]
        improvement = data["improvement"]

        return (
            f"If you remediated [{items_desc}], your score would improve "
            f"from {current}/5.0 to {simulated}/5.0 (+{improvement})."
        )

    def _handle_summary(self) -> str:
        """Handle summary intent using MCP tools."""
        return self._mcp.generate_executive_summary()

    def _handle_general(self) -> str:
        """Handle general/fallback intent."""
        return (
            "I can help you with the following security posture questions:\n\n"
            "• **Score** — Ask about your overall security score or rating\n"
            "• **Gaps** — Ask about top security gaps, risks, or failing controls\n"
            "• **Remediation** — Ask for a fix plan or what to do next\n"
            "• **Pillar details** — Ask about a specific pillar (e.g., 'Why is Identity low?')\n"
            "• **Simulate** — Ask 'What if I fix MFA?' to see projected improvements\n"
            "• **Summary** — Ask for an executive summary or leadership brief\n\n"
            "Try asking something like: 'What's my security score?' or 'What are my top gaps?'"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _detect_pillar(self, message: str) -> Optional[str]:
        """Detect which pillar the user is asking about from the message."""
        lower = message.lower()
        for fragment in _PILLAR_FRAGMENTS:
            if fragment in lower:
                return _PILLAR_DISPLAY_MAP[fragment]
        return None

    def _detect_finding_ids(self, message: str) -> List[str]:
        """Detect finding IDs from user message by mapping common terms.

        Maps user-friendly terms (e.g. 'mfa', 'cloudtrail') to finding ID
        substrings, then searches the remediation plan for matching IDs.
        """
        lower = message.lower()
        target_substrings = []

        for term, id_fragment in _FINDING_TERM_MAP.items():
            if term in lower:
                if id_fragment not in target_substrings:
                    target_substrings.append(id_fragment)

        if not target_substrings:
            return []

        # Get all finding IDs from the remediation plan
        plan = self._mcp.get_remediation_plan()
        matched_ids = []
        for action in plan:
            finding_id = action.get("finding_id", "")
            for substring in target_substrings:
                if substring in finding_id.lower():
                    matched_ids.append(finding_id)
                    break

        return matched_ids

    def _wrap_response(self, body: str) -> str:
        """Wrap response with simulation indicator and production note."""
        production_note = (
            "\n\n---\n"
            "In production, Amazon Bedrock would provide more natural "
            "responses using these same MCP tools."
        )
        return f"[Simulated Assistant] {body}{production_note}"
