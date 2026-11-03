
import json

from src.agents.vulnerability_analyzer import analyze_vulnerability

TEST_CVES = [
    "CVE-2011-3587",
    "CVE-2018-7574",
    "CVE-2022-21726",
    "CVE-2024-9052",
]

for cve_id in TEST_CVES:
    print("\n" + "=" * 75)
    print(f"CVE: {cve_id}")
    print("=" * 75)

    analysis = analyze_vulnerability(cve_id)

    print("\nRISK:")
    print(json.dumps(analysis["risk"], indent=2, ensure_ascii=False))

    print("\nDESCRIPTION:")
    print(analysis.get("description"))

    print("\nADVISORIES:")
    print(json.dumps(
        analysis.get("advisories", []),
        indent=2,
        ensure_ascii=False
    ))

    print("\nAFFECTED PACKAGES:")
    for package in analysis["affected_packages"]:
        print(json.dumps(package, indent=2, ensure_ascii=False))
