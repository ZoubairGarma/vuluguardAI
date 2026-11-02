
from pathlib import Path

import pandas as pd


DATA_DIR = Path("data/processed")

FILES = [
    "risk/risk_assessment.csv",
    "osv_records.csv",
    "osv_affected_packages.csv",
    "cvss_scores.csv",
    "cve_features.csv",
]


def inspect_file(filename):
    path = DATA_DIR / filename

    print("\n" + "=" * 75)
    print(f"FILE: {filename}")
    print("=" * 75)

    if not path.exists():
        print("ERROR: File not found")
        return

    df = pd.read_csv(path)

    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")

    print("\nColumn names:")
    for column in df.columns:
        print(f"- {column}")

    print("\nFirst record:")
    if not df.empty:
        for column in df.columns:
            value = df.iloc[0][column]
            print(f"\n{column}: {str(value)[:500]}")

    print("\nMissing values:")
    missing = df.isna().sum()
    print(missing[missing > 0].to_string() if missing.any() else "None")


def main():
    for filename in FILES:
        inspect_file(filename)

    print("\nInspection completed.")


if __name__ == "__main__":
    main()
