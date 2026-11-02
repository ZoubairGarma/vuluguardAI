
from pathlib import Path

import pandas as pd


RISK_FILE = Path("data/processed/risk/risk_assessment.csv")
CVSS_FILE = Path("data/processed/cvss_scores.csv")
CVE_FILE = Path("data/processed/cve_features.csv")


def main():
    risk = pd.read_csv(RISK_FILE)
    cvss = pd.read_csv(CVSS_FILE)
    cve = pd.read_csv(CVE_FILE)

    # Exclude vulnerabilities listed in KEV
    critical = risk[
        (risk["is_kev"] == False)
        & (risk["risk_level"] == "CRITICAL")
    ].copy()

    # Inspect the 15 highest-risk non-KEV vulnerabilities
    critical = critical.sort_values(
        "risk_score", ascending=False
    ).head(15)

    # Retrieve source CVSS and EPSS information
    result = critical.merge(
        cvss,
        on="cve_id",
        how="left",
        suffixes=("", "_source"),
    )

    result = result.merge(
        cve[["cve_id", "epss_score", "epss_percentile"]],
        on="cve_id",
        how="left",
        suffixes=("", "_source"),
    )

    columns = [
        "cve_id",
        "risk_score",
        "risk_level",
        "scoring_basis",
        "cvss_score",
        "cvss_v3_score",
        "cvss_v4_score",
        "epss_score_source",
        "epss_percentile",
    ]

    available = [col for col in columns if col in result.columns]

    print("\n========== TOP 15 NON-KEV CRITICAL CVEs ==========")
    print(result[available].to_string(index=False))

    print("\nTotal non-KEV critical vulnerabilities:", len(
        risk[
            (risk["is_kev"] == False)
            & (risk["risk_level"] == "CRITICAL")
        ]
    ))


if __name__ == "__main__":
    main()
