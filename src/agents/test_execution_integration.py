
from src.agents.vulnerability_analyzer import VulnerabilityAnalyzer
from src.agents.security_test_generator import SecurityTestGenerator
from src.agents.human_approval import HumanApprovalManager
from src.agents.security_test_executor import SecurityTestExecutor


def main():
    print("\n========== VULNGUARD AI ==========")
    print("Controlled Security Test Workflow\n")

    # 1. Analyze vulnerability
    print("[1] Analyzing vulnerability...")

    cve_id = input("Enter a CVE ID (default: CVE-2023-0297): ").strip()
    if not cve_id:
        cve_id = "CVE-2023-0297"

    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze(cve_id)

    if not analysis:
        print("No vulnerability analysis returned.")
        return

    print(f"CVE: {cve_id}")
    print(f"Risk level: {analysis.get('risk', {}).get('risk_level', 'UNKNOWN')}")

    # 2. Generate security test plan
    print("\n[2] Generating security test plan...")

    generator = SecurityTestGenerator()
    test_plan = generator.generate(analysis)

    print(f"Generated tests: {test_plan['total_tests']}")

    if not test_plan["tests"]:
        print("No security tests were generated.")
        return

    for test in test_plan["tests"]:
        print(f"- {test['test_id']}: {test['title']}")
        print(f"  Package: {test['target']['package_name']}")

    # 3. Human approval
    print("\n[3] Human approval required.")

    decision = input("Approve this test plan? (yes/no): ").strip().lower()
    reviewer = input("Reviewer name: ").strip()

    approval_manager = HumanApprovalManager()

    if decision == "yes":
        approved_plan = approval_manager.approve(
            test_plan,
            reviewer=reviewer,
        )
    elif decision == "no":
        reason = input("Reason for rejection: ").strip()

        rejected_plan = approval_manager.reject(
            test_plan,
            reviewer=reviewer,
            reason=reason,
        )

        print("\nTest plan rejected.")
        print(f"Approval status: {rejected_plan['approval_status']}")
        print(f"Execution status: {rejected_plan['execution_status']}")
        return
    else:
        print("Invalid decision. Execution cancelled.")
        return

    print(f"Approval status: {approved_plan['approval_status']}")
    print(f"Reviewer: {approved_plan['approval']['reviewer']}")

    # 4. Controlled execution
    print("\n[4] Executing approved security checks...")

    executor = SecurityTestExecutor()
    execution_result = executor.execute(approved_plan)

    print("\n========== EXECUTION RESULTS ==========")
    print(f"Execution status: {execution_result['execution_status']}")

    for result in execution_result.get("execution_results", []):
        print(f"\nTest ID: {result['test_id']}")
        print(f"Package: {result['package_name']}")
        print(f"Installed version: {result['installed_version']}")
        print(f"Version status: {result['version_status']}")
        print(f"Execution status: {result['execution_status']}")
        print(f"Message: {result['message']}")

    print("\nOriginal test plan remains unchanged.")
    print(f"Original execution status: {test_plan['execution_status']}")

    print("\n========== WORKFLOW COMPLETED ==========")


if __name__ == "__main__":
    main()
