
from src.agents.vulnerability_analyzer import VulnerabilityAnalyzer
from src.agents.security_test_generator import SecurityTestGenerator
from src.agents.human_approval import HumanApprovalManager


def main():
    cve_id = "CVE-2023-0297"

    print("=" * 65)
    print("VULNGUARD AI - HUMAN APPROVAL INTEGRATION TEST")
    print("=" * 65)

    # Step 1: Analyze vulnerability
    print("\n[1/3] Analyzing vulnerability...")

    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze(cve_id)

    print(f"CVE: {analysis['cve_id']}")
    print(f"Risk: {analysis['risk']['level']}")

    # Step 2: Generate security tests
    print("\n[2/3] Generating security tests...")

    generator = SecurityTestGenerator()
    test_plan = generator.generate(analysis)

    print(f"Generated tests: {test_plan['total_tests']}")
    print(f"Status: {test_plan['approval_status']}")

    # Step 3: Human approval simulation
    print("\n[3/3] Human approval...")

    approval_manager = HumanApprovalManager()

    decision = input("Approve this test plan? (yes/no): ").strip().lower()

    if decision == "yes":
        result = approval_manager.approve(
            test_plan,
            reviewer="security_reviewer",
        )
    elif decision == "no":
        reason = input("Enter rejection reason: ").strip()

        result = approval_manager.reject(
            test_plan,
            reviewer="security_reviewer",
            reason=reason,
        )
    else:
        print("Invalid decision. No approval was granted.")
        return

    print("\nAPPROVAL RESULT")
    print("-" * 65)
    print(f"CVE: {result['cve_id']}")
    print(f"Decision: {result['approval_status']}")
    print(f"Reviewer: {result['approval']['reviewer']}")
    print(f"Execution: {result['execution_status']}")

    for test in result["tests"]:
        print(f"\nTest ID: {test['test_id']}")
        print(f"Approval: {test['approval_status']}")
        print(f"Execution: {test['execution_status']}")

    print("\n" + "=" * 65)
    print("HUMAN APPROVAL WORKFLOW COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()
