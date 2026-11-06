"""First workflow agent: explain verified findings and propose checks."""

from typing import Any

from src.agents.llm_explanation import LLMExplanationAgent
from src.agents.security_test_generator import SecurityTestGenerator


class ReportAndPlanAgent:
    """Produce an AI explanation and a deterministic, unapproved test plan."""

    def __init__(self, explainer: Any | None = None, test_generator: Any | None = None):
        self._explainer = explainer or LLMExplanationAgent()
        self._test_generator = test_generator or SecurityTestGenerator()

    def run(self, finding: dict) -> dict:
        if not isinstance(finding, dict) or not finding.get("cve_id"):
            raise ValueError("A vulnerability finding with a CVE ID is required.")

        explanation = self._explainer.explain(finding)
        plan = self._test_generator.generate(finding)

        if not isinstance(explanation, dict):
            raise TypeError("The explanation agent must return a dictionary.")
        if not isinstance(plan, dict):
            raise TypeError("The test generator must return a dictionary.")
        if plan.get("approval_status") != "PENDING_APPROVAL":
            raise ValueError("The proposed plan must await human approval.")
        if plan.get("execution_status") != "NOT_STARTED":
            raise ValueError("A proposed plan must not have started execution.")

        return {"explanation": explanation, "test_plan": plan}
