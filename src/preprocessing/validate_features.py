from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FEATURES_PATH = PROJECT_ROOT / "data" / "processed" / "ml_features.csv"


def main():
    if not FEATURES_PATH.exists():
        raise FileNotFoundError(
            f"Feature dataset not found: {FEATURES_PATH}"
        )

    df = pd.read_csv(FEATURES_PATH)

    print("=" * 65)
    print("ML FEATURE DATASET VALIDATION")
    print("=" * 65)

    print(f"\nRows: {len(df):,}")
    print(f"Columns: {len(df.columns):,}")

    print("\nDuplicate CVE IDs:")
    print(df["cve_id"].duplicated().sum())

    print("\nMissing values:")
    missing = df.isna().sum()
    print(missing[missing > 0].to_string() or "No missing values")

    print("\nData types:")
    print(df.dtypes.value_counts().to_string())

    print("\nKEV distribution:")
    print(df["is_kev"].value_counts(dropna=False).to_string())

    print("\nEPSS summary:")
    print(df["epss_score"].describe().to_string())

    print("\nCVSS coverage:")
    print("CVSS v3:", df["has_cvss_v3"].sum())
    print("CVSS v4:", df["has_cvss_v4"].sum())

    print("\nPackage feature summary:")
    for col in [
        "linked_package_count",
        "ecosystem_count",
        "linked_osv_count",
    ]:
        if col in df.columns:
            print(f"{col}:")
            print(df[col].describe().to_string())

    non_numeric = [
        col for col in df.columns
        if col != "cve_id"
        and not pd.api.types.is_numeric_dtype(df[col])
    ]

    print("\nNon-numeric columns other than cve_id:")
    print(non_numeric or "None")

    print("\nFirst 5 rows:")
    print(df.head().to_string(index=False))

    # Basic integrity checks.
    assert len(df) == 6773, "Unexpected number of CVE rows."
    assert df["cve_id"].is_unique, "CVE IDs are not unique."
    assert df["is_kev"].sum() == 21, "Unexpected KEV count."
    assert df["epss_score"].isna().sum() == 64, (
        "EPSS missing-value count changed."
    )
    assert not non_numeric, (
        "Unexpected non-numeric model features were found."
    )

    print("\nAll basic validation checks passed.")


if __name__ == "__main__":
    main()