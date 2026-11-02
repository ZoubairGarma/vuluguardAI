
from pathlib import Path
import importlib.util
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data" / "processed"

features = pd.read_csv(DATA_DIR / "ml_features.csv")
severity = pd.read_csv(DATA_DIR / "osv_severity.csv")

print("\n========== EPSS AND KEV ==========")

columns = [
    "cve_id",
    "epss_score",
    "epss_percentile",
    "has_epss",
    "is_kev",
]

print(features[columns].head(10).to_string(index=False))

print("\nColumn data types:")
print(features[columns].dtypes)

print("\n========== CVSS VECTORS ==========")

print(
    severity[
        ["cve_ids", "severity_type", "cvss_version", "vector"]
    ].head(10).to_string(index=False)
)

print("\nMissing vectors:")
print(severity["vector"].isna().sum())

print("\nCVSS versions:")
print(severity["cvss_version"].value_counts(dropna=False))

print("\n========== CVSS LIBRARY ==========")

if importlib.util.find_spec("cvss"):
    print("The cvss package is already installed.")
else:
    print("The cvss package is NOT installed.")

print("\nCheck completed.")
