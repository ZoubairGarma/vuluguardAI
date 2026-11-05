from pprint import pprint

from src.services.analysis_service import AnalysisService
from src.services.enrichment_adapter import EnrichmentAdapter
from src.services.risk_scoring_adapter import RiskScoringAdapter
from src.agents.human_approval import HumanApprovalManager
from src.agents.security_test_executor import SecurityTestExecutor
from src.agents.llm.ollama_provider import OllamaProvider
from src.agents.llm_explanation import LLMExplanationAgent
from src.agents.security_test_generator import SecurityTestGenerator


def main():
    print("\n=== VULNGUARD AI: COMPLETE SECURITY WORKFLOW ===")

    service = AnalysisService(
        enrichment_adapter=EnrichmentAdapter.from_intelligence_engine(),
        risk_scorer=RiskScoringAdapter(),
        llm_explainer=LLMExplanationAgent(provider=OllamaProvider()),
        test_generator=SecurityTestGenerator(),
    )

    dependencies = [
        {
            "ecosystem": "PyPI",
            "name": "pyload-ng",
            "version": "0.5.0",
        }
    ]

    print("\n[1/5] Analyzing dependencies...")
    result = service.analyze_with_security_workflow(
        scan_id="full-security-workflow-001",
        dependencies=dependencies,
    )

    print(f"Findings: {len(result.vulnerabilities)}")
    print(f"LLM explanations: {len(result.llm_explanations)}")
    print(f"Security test plans: {len(result.security_test_plans)}")

    print("\n[2/5] Risk assessment:")
    pprint(result.risk_assessment)

    print("\n[3/5] LLM explanations:")
    for explanation in result.llm_explanations:
        print(f"\nCVE: {explanation.get('cve_id')}")
        print(explanation.get("explanation", ""))

    print("\n[4/5] Human approval:")
    approval_manager = HumanApprovalManager()
    executor = SecurityTestExecutor()

    for index, plan in enumerate(result.security_test_plans, start=1):
        print(f"\nTest plan {index}:")
        pprint(plan)

        decision = input(
            "\nApprove this test plan? (yes/no): "
        ).strip().lower()

        if decision == "yes":
            approved_plan = approval_manager.approve(
                plan,
                reviewer="Human Reviewer",
            )

            print("Approval: APPROVED")

            execution_result = executor.execute(approved_plan)

            print("Execution result:")
            pprint(execution_result)

        else:
            rejected_plan = approval_manager.reject(
                plan,
                reviewer="Human Reviewer",
                reason="Rejected by human reviewer.",
            )

            print("Approval: REJECTED")
            print(
                "Execution status:",
                rejected_plan.get("execution_status"),
            )

    print("\n[5/5] Workflow completed.")
    print("No test was executed without human approval.")


if __name__ == "__main__":
    main()