
from pathlib import Path

import pandas as pd


INPUT_FILE = Path("data/processed/risk/risk_assessment.csv")


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"File not found: {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE)

    print("\n========== RISK SCORE DISTRIBUTION ==========")

    print("\n1. Overall risk levels:")
    print(df["risk_level"].value_counts(dropna=False))

    print("\n2. Risk levels (percentages):")
    print(
        (df["risk_level"].value_counts(normalize=True) * 100)
        .round(2)
    )

    print("\n3. Risk score statistics:")
    print(df["risk_score"].describe().round(2))

    non_kev = df[df["is_kev"] == False].copy()

    print("\n4. Non-KEV vulnerabilities:")
    print(f"Total: {len(non_kev)}")

    print("\nNon-KEV risk levels:")
    print(non_kev["risk_level"].value_counts(dropna=False))

    print("\n5. Non-KEV risk score statistics:")
    print(non_kev["risk_score"].describe().round(2))

    print("\n6. Highest-risk non-KEV vulnerabilities:")

    columns = [
        "cve_id",
        "risk_score",
        "risk_level",
        "cvss_score",
        "epss_score",
        "scoring_basis",
    ]

    available_columns = [
        col for col in columns if col in non_kev.columns
    ]

    print(
        non_kev[available_columns]
        .sort_values("risk_score", ascending=False)
        .head(15)
        .to_string(index=False)
    )

    print("\n7. Risk levels by scoring basis:")
    print(
        pd.crosstab(
            non_kev["scoring_basis"],
            non_kev["risk_level"],
        )
    )

    print("\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()
