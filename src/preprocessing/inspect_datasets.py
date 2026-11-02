
import gzip
import json
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OSV_DIR = PROJECT_ROOT / "data" / "raw" / "osv"
EPSS_FILE = PROJECT_ROOT / "data" / "raw" / "epss" / "epss_scores-current.csv.gz"
KEV_FILE = PROJECT_ROOT / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"


def inspect_osv():
    print("\n========== OSV DATASET ==========")

    files = list(OSV_DIR.glob("*.json"))
    print("Total files:", len(files))

    if not files:
        print("No OSV records found.")
        return

    with files[0].open("r", encoding="utf-8") as file:
        record = json.load(file)

    print("Sample ID:", record.get("id"))
    print("Available fields:", list(record.keys()))

    affected = record.get("affected", [])
    print("Affected package entries:", len(affected))

    aliases = record.get("aliases", [])
    print("Aliases:", aliases)


def inspect_epss():
    print("\n========== EPSS DATASET ==========")

    if not EPSS_FILE.exists():
        print("EPSS file not found.")
        return

    df = pd.read_csv(
        EPSS_FILE,
        compression="gzip",
        comment="#"
    )

    print("Total records:", len(df))
    print("Columns:", list(df.columns))
    print("\nFirst 5 records:")
    print(df.head().to_string(index=False))

    print("\nMissing values:")
    print(df.isnull().sum().to_string())

    print("\nEPSS score statistics:")
    print(df["epss"].describe().to_string())


def inspect_kev():
    print("\n========== CISA KEV DATASET ==========")

    if not KEV_FILE.exists():
        print("KEV file not found.")
        return

    with KEV_FILE.open("r", encoding="utf-8") as file:
        data = json.load(file)

    vulnerabilities = data.get("vulnerabilities", [])

    print("Catalog version:", data.get("catalogVersion"))
    print("Total records:", len(vulnerabilities))

    if vulnerabilities:
        record = vulnerabilities[0]
        print("Available fields:", list(record.keys()))
        print("Sample CVE:", record.get("cveID"))
        print("Sample vendor:", record.get("vendorProject"))
        print("Sample product:", record.get("product"))


if __name__ == "__main__":
    inspect_osv()
    inspect_epss()
    inspect_kev()

    print("\n========== INSPECTION COMPLETE ==========")

