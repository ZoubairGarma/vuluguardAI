
import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data" / "processed"


def validate_datasets():

    files = {
        "OSV records": "osv_records.csv",
        "Affected packages": "osv_affected_packages.csv",
        "CVE features": "cve_features.csv",
    }

    # --------------------------------------------------
    # 1. Inspect all processed datasets
    # --------------------------------------------------

    for name, filename in files.items():

        path = DATA_DIR / filename

        if not path.exists():
            print(f"\nERROR: Missing file: {path}")
            return

        df = pd.read_csv(path)

        print(f"\n========== {name} ==========")
        print("Rows:", len(df))
        print("Columns:", len(df.columns))
        print("Column names:", df.columns.tolist())
        print("Exact duplicate rows:", df.duplicated().sum())

    # --------------------------------------------------
    # 2. Load datasets for validation
    # --------------------------------------------------

    cve_df = pd.read_csv(DATA_DIR / "cve_features.csv")

    packages_df = pd.read_csv(
        DATA_DIR / "osv_affected_packages.csv"
    )

    # --------------------------------------------------
    # 3. CVE data quality checks
    # --------------------------------------------------

    print("\n========== DATA QUALITY CHECKS ==========")

    print("Unique CVEs:", cve_df["cve_id"].nunique())

    print(
        "Duplicate CVE IDs:",
        cve_df["cve_id"].duplicated().sum()
    )

    print(
        "Missing EPSS scores:",
        cve_df["epss_score"].isna().sum()
    )

    print("KEV entries:", cve_df["is_kev"].sum())

    print(
        "Missing package names:",
        packages_df["package_name"].isna().sum()
    )

    print("\nSample CVE features:")

    print(
        cve_df[
            ["cve_id", "epss_score", "epss_percentile", "is_kev"]
        ].head(10).to_string(index=False)
    )

    # --------------------------------------------------
    # 4. Analyze repeated package groups
    # --------------------------------------------------

    print("\n========== DUPLICATE PACKAGE ANALYSIS ==========")

    group_columns = [
        "osv_id",
        "ecosystem",
        "package_name"
    ]

    duplicate_mask = packages_df.duplicated(
        subset=group_columns,
        keep=False
    )

    duplicates = packages_df[duplicate_mask]

    grouped = duplicates.groupby(
        group_columns,
        dropna=False
    )

    print("Repeated package groups:", grouped.ngroups)
    print("Rows belonging to these groups:", len(duplicates))

    print("\nShowing first 5 groups only:")

    for (osv_id, ecosystem, package), group in list(grouped)[:5]:

        print("\n----------------------------------------")
        print("OSV ID:", osv_id)
        print("Ecosystem:", ecosystem)
        print("Package:", package)
        print("Affected entries:", len(group))

        for index, row in enumerate(
            group.itertuples(index=False),
            start=1
        ):

            print(f"\n  Affected entry {index}:")

            # Display affected version ranges
            try:
                ranges = json.loads(row.ranges)

                if not ranges:
                    print("    No range information")

                for version_range in ranges:

                    print(
                        "    Range type:",
                        version_range.get("type")
                    )

                    for event in version_range.get("events", []):
                        print("    Event:", event)

            except (ValueError, TypeError, json.JSONDecodeError):
                print("    Could not parse version ranges")

            # Display explicit versions
            try:
                versions = json.loads(row.versions)

                print("    Explicit version count:", len(versions))

                if versions:
                    print(
                        "    Sample versions:",
                        ", ".join(versions[:5])
                    )

            except (ValueError, TypeError, json.JSONDecodeError):
                print("    Could not parse explicit versions")

    # --------------------------------------------------
    # 5. Final result
    # --------------------------------------------------

    print("\n========== VALIDATION COMPLETE ==========")


if __name__ == "__main__":
    validate_datasets()
