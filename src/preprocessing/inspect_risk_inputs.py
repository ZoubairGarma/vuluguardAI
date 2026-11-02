
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
PROCESSED_DIR = BASE_DIR / "data" / "processed"

files = {
    "ML features": "ml_features.csv",
    "CVE features": "cve_features.csv",
    "OSV severity": "osv_severity.csv",
}

for label, filename in files.items():
    path = PROCESSED_DIR / filename

    print("\n" + "=" * 70)
    print(label)
    print("=" * 70)

    if not path.exists():
        print(f"FILE NOT FOUND: {path}")
        continue

    df = pd.read_csv(path)

    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")
    print("\nColumn names:")

    for column in df.columns:
        print(f" - {column}")

    print("\nFirst 3 rows:")
    print(df.head(3).to_string(index=False))

    if "vector" in df.columns:
        print("\nCVSS vector types:")
        print(df["severity_type"].value_counts(dropna=False))

        print("\nCVSS vector examples:")
        print(df[["severity_type", "vector"]].head(5).to_string(index=False))

print("\nInspection completed.")
