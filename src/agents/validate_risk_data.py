
from pathlib import Path

import pandas as pd


RISK_FILE = Path("data/processed/risk/risk_assessment.csv")
CVSS_FILE = Path("data/processed/cvss_scores.csv")
CVE_FILE = Path("data/processed/cve_features.csv")


def compare_numeric_columns(left, right):
    """Count differences between two numeric columns, ignoring missing pairs."""
    left = pd.to_numeric(left, errors="coerce")
    right = pd.to_numeric(right, errors="coerce")

    comparable = left.notna() & right.notna()

    mismatches = (
        left[comparable] - right[comparable]
    ).abs() > 1e-10

    return int(mismatches.sum()), int(comparable.sum())


def main():
    risk = pd.read_csv(RISK_FILE)
    cvss = pd.read_csv(CVSS_FILE)
    cve = pd.read_csv(CVE_FILE)

    print("\n========== RISK DATA VALIDATION ==========")

    # 1. Unique CVE identifiers
    print("\n1. Unique CVE identifiers")
    print("Risk duplicates:", risk["cve_id"].duplicated().sum())
    print("CVSS duplicates:", cvss["cve_id"].duplicated().sum())
    print("CVE feature duplicates:", cve["cve_id"].duplicated().sum())

    # 2. Display actual columns
    print("\n2. Available columns")
    print("Risk:", risk.columns.tolist())
    print("CVSS:", cvss.columns.tolist())


    # 3. CVSS source consistency
    merged_cvss = risk.merge(
        cvss[
            [
                "cve_id",
                "cvss_v3_score",
                "cvss_v4_score",
            ]
        ],
        on="cve_id",
        how="left",
        validate="one_to_one",
    )

    # The scoring engine prefers v3, then falls back to v4.
    expected_cvss = merged_cvss["cvss_v3_score"].combine_first(
        merged_cvss["cvss_v4_score"]
    )

    actual_cvss = pd.to_numeric(
        merged_cvss["cvss_score_used"],
        errors="coerce",
    )

    comparable = expected_cvss.notna() & actual_cvss.notna()

    mismatches = (
        (expected_cvss[comparable] - actual_cvss[comparable])
        .abs() > 1e-10
    ).sum()

    print("\n3. CVSS consistency")
    print("Comparable CVSS records:", int(comparable.sum()))
    print("CVSS mismatches:", int(mismatches))
    print("Missing expected CVSS:", int(expected_cvss.isna().sum()))
    print("Missing selected CVSS:", int(actual_cvss.isna().sum()))

    # 4. EPSS source consistency
    print("\n4. EPSS consistency")

    epss_columns = [
        col for col in ["epss_score", "epss_percentile"]
        if col in risk.columns and col in cve.columns
    ]

    merged_epss = risk.merge(
        cve[["cve_id"] + epss_columns],
        on="cve_id",
        how="left",
        suffixes=("_risk", "_source"),
        validate="one_to_one",
    )

    for col in epss_columns:
        mismatch, compared = compare_numeric_columns(
            merged_epss[f"{col}_risk"],
            merged_epss[f"{col}_source"],
        )

        print(f"{col} mismatches: {mismatch} / {compared}")

    if "epss_score" in merged_epss.columns:
        print(
            "Missing EPSS in source:",
            merged_epss["epss_score_source"].isna().sum()
        )

    # 5. Risk score bounds
    print("\n5. Risk score bounds")

    valid_scores = risk["risk_score"].dropna()

    print("Below 0:", (valid_scores < 0).sum())
    print("Above 100:", (valid_scores > 100).sum())

    # 6. KEV override
    print("\n6. KEV override")

    kev = risk[risk["is_kev"] == True]

    print("KEV records:", len(kev))
    print(
        "KEV scores different from 100:",
        (kev["risk_score"] != 100).sum()
    )

    print("\nValidation completed.")


if __name__ == "__main__":
    main()
