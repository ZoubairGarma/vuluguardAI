
from src.agents.vulnerability_analyzer import VulnerabilityAnalyzer
from src.agents.security_test_generator import SecurityTestGenerator


def main():
    cve_id = "CVE-2023-0297"

    print("=" * 65)
    print("VULNGUARD AI - SECURITY TEST GENERATION INTEGRATION")
    print("=" * 65)

    # Step 1: Analyze the vulnerability
    print("\n[1/2] Running VulnerabilityAnalyzer...")

    analyzer = VulnerabilityAnalyzer()
    analysis = analyzer.analyze(cve_id)

    print("Vulnerability analysis completed.")
    print(f"CVE: {analysis['cve_id']}")
    print(f"Risk level: {analysis['risk']['level']}")
    print(f"Affected packages: {len(analysis['affected_packages'])}")

    # Step 2: Generate security test scenarios
    print("\n[2/2] Generating security test scenarios...")

    generator = SecurityTestGenerator()
    result = generator.generate(analysis)

    print("\nGENERATION RESULT")
    print("-" * 65)
    print(f"CVE: {result['cve_id']}")
    print(f"Total generated tests: {result['total_tests']}")
    print(f"Approval status: {result['approval_status']}")
    print(f"Execution status: {result['execution_status']}")

    for test in result["tests"]:
        print("\n" + "-" * 50)
        print(f"Test ID: {test['test_id']}")
        print(f"Title: {test['title']}")
        print(f"Package: {test['target']['package_name']}")
        print(f"Version status: {test['evidence']['version_status']}")
        print(f"Objective: {test['objective']}")
        print(f"Safety: {test['safety']}")
        print(f"Approval: {test['approval_status']}")
        print(f"Execution: {test['execution_status']}")

    print("\n" + "=" * 65)
    print("INTEGRATION TEST COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()
