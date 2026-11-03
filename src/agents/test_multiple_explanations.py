
from src.agents.vulnerability_analyzer import analyze_vulnerability
from src.agents.llm_explanation import LLMExplanationAgent


TEST_CASES = [
    {
        "name": "KEV + CVSS + EPSS",
        "cve_id": "CVE-2026-59822",
    },
    {
        "name": "CVSS + EPSS (non-KEV)",
        "cve_id": "CVE-2023-0297",
    },
    {
        "name": "EPSS only",
        "cve_id": "CVE-2011-3587",
    },
    {
        "name": "CVSS only",
        "cve_id": "CVE-2024-9052",
    },
    {
        "name": "No CVSS and no EPSS",
        "cve_id": "CVE-2018-7574",
    },
    {
        "name": "Multiple affected packages",
        "cve_id": "CVE-2022-21726",
    },
]


def main():
    agent = LLMExplanationAgent()

    successful = 0
    failed = 0

    print("=" * 70)
    print("VULNGUARD AI - MULTIPLE CVE EXPLANATION TEST")
    print("=" * 70)

    for index, case in enumerate(TEST_CASES, start=1):
        cve_id = case["cve_id"]

        print("\n" + "=" * 70)
        print(f"TEST {index}/{len(TEST_CASES)}: {case['name']}")
        print(f"CVE: {cve_id}")
        print("=" * 70)

        try:
            # Step 1: Analyze the vulnerability
            print("\n[1/2] Running VulnerabilityAnalyzer...")

            analysis = analyze_vulnerability(cve_id)

            print("Analysis completed.")
            print(f"Risk level: {analysis['risk']['level']}")
            print(f"Risk score: {analysis['risk']['score']}")
            print(
                "Affected package entries:",
                len(analysis["affected_packages"])
            )

            # Step 2: Generate the LLM explanation
            print("\n[2/2] Generating LLM explanation...")
            print("Please wait...")

            result = agent.explain(analysis)

            print("\nEXPLANATION:")
            print("-" * 70)
            print(result["explanation"])
            print("-" * 70)

            successful += 1
            print("\nTest completed successfully.")

        except Exception as error:
            failed += 1
            print(f"\nTest failed: {type(error).__name__}: {error}")

    print("\n" + "=" * 70)
    print("FINAL TEST SUMMARY")
    print("=" * 70)
    print(f"Total tests: {len(TEST_CASES)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print("=" * 70)


if __name__ == "__main__":
    main()
