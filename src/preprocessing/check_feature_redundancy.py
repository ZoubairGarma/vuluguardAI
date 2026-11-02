
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data" / "processed"

cve = pd.read_csv(DATA_DIR / "cve_features.csv")
ml = pd.read_csv(DATA_DIR / "ml_features.csv")

comparisons = [
    ("osv_record_count", "linked_osv_count"),
    ("affected_package_count", "linked_package_count"),
    ("cvss_v3_entry_count", "cvss_v3_entry_count_derived"),
    ("cvss_v4_entry_count", "cvss_v4_entry_count_derived"),
]

print("\nFEATURE REDUNDANCY CHECK")
print("=" * 65)

for original, derived in comparisons:

    print(f"\n{original} vs {derived}")
    print("-" * 55)

    if original not in ml.columns or derived not in ml.columns:
        print("One or both columns are missing.")
        continue

    comparison = pd.DataFrame({
        "original": ml[original],
        "derived": ml[derived],
    })

    comparison = comparison.dropna()

    differences = (
        comparison["original"] != comparison["derived"]
    ).sum()

    print("Rows compared:", len(comparison))
    print("Different values:", differences)
    print(
        "Correlation:",
        comparison["original"].corr(comparison["derived"])
    )

    print(
        "Original unique values:",
        comparison["original"].nunique()
    )

    print(
        "Derived unique values:",
        comparison["derived"].nunique()
    )

print("\nCHECK COMPLETE")
