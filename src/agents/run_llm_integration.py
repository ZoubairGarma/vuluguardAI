
import csv
import json
from pathlib import Path

from src.agents.vulnerability_analyzer import analyze_vulnerability
from src.agents.llm_explanation import LLMExplanationAgent


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RISK_FILE = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "risk"
    / "risk_assessment.csv"
)


def select_test_cve() -> str:
    """Select the highest-scoring CVE from the local risk assessment."""

    if not RISK_FILE.exists():
        raise FileNotFoundError(
            f"Risk assessment file not found: {RISK_FILE}"
        )

    with RISK_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    valid_rows = [
        row for row in rows
        if row.get("cve_id") and row.get("risk_score")
    ]

    if not valid_rows:
        raise ValueError("No CVE with a valid risk score was found.")

    valid_rows.sort(
        key=lambda row: float(row["risk_score"]),
        reverse=True,
    )

    return valid_rows[0]["cve_id"]


def main():
    print("=" * 65)
    print("VULNGUARD AI - LLM INTEGRATION TEST")
    print("=" * 65)

    # Step 1: Select a real CVE
    print("\n[1/4] Selecting a CVE from local data...")

    cve_id = select_test_cve()
    print(f"Selected CVE: {cve_id}")

    # Step 2: Analyze the vulnerability
    print("\n[2/4] Running VulnerabilityAnalyzer...")

    analysis = analyze_vulnerability(cve_id)

    print("Vulnerability analysis completed.")
    print(f"Risk level: {analysis['risk']['level']}")
    print(f"Risk score: {analysis['risk']['score']}")
    print(
        "Affected package entries:",
        len(analysis["affected_packages"]),
    )

    # Step 3: Generate the LLM explanation
    print("\n[3/4] Generating explanation with Ollama...")
    print("Model: llama3.2:3b")
    print("This may take a little time...")

    agent = LLMExplanationAgent()
    result = agent.explain(analysis)

    # Step 4: Display the result
    print("\n[4/4] LLM explanation generated successfully.")

    print("\n" + "=" * 65)
    print("VULNERABILITY EXPLANATION")
    print("=" * 65)

    print(f"\nCVE: {result['cve_id']}")
    print("\n" + result["explanation"])

    print("\n" + "=" * 65)
    print("METADATA")
    print("=" * 65)

    print(json.dumps(result["metadata"], indent=4))

    print("\nIntegration test completed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("\nINTEGRATION TEST FAILED")
        print(f"{type(error).__name__}: {error}")
        raise
