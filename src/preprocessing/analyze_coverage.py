
import json
import re
from pathlib import Path
from collections import Counter

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OSV_DIR = PROJECT_ROOT / "data" / "raw" / "osv"
EPSS_FILE = PROJECT_ROOT / "data" / "raw" / "epss" / "epss_scores-current.csv.gz"
KEV_FILE = PROJECT_ROOT / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def analyze_coverage():
    print("LOADING DATASETS...")

    epss_df = pd.read_csv(EPSS_FILE, compression="gzip", comment="#")
    epss_cves = set(epss_df["cve"].dropna().str.upper())

    with KEV_FILE.open("r", encoding="utf-8") as file:
        kev_data = json.load(file)

    kev_cves = {
        item["cveID"].upper()
        for item in kev_data.get("vulnerabilities", [])
        if item.get("cveID")
    }

    osv_files = list(OSV_DIR.glob("*.json"))

    osv_records_with_cve = 0
    osv_records_without_cve = 0
    all_osv_cves = set()
    ecosystems = Counter()
    unique_packages = set()
    affected_entries = 0

    print("ANALYZING OSV RECORDS...")

    for path in osv_files:
        with path.open("r", encoding="utf-8") as file:
            record = json.load(file)

        aliases = record.get("aliases", [])
        cves = {
            alias.upper()
            for alias in aliases
            if isinstance(alias, str)
            and CVE_PATTERN.match(alias.upper())
        }

        if cves:
            osv_records_with_cve += 1
            all_osv_cves.update(cves)
        else:
            osv_records_without_cve += 1

        for affected in record.get("affected", []):
            affected_entries += 1

            package = affected.get("package", {})
            ecosystem = package.get("ecosystem")
            name = package.get("name")

            if ecosystem:
                ecosystems[ecosystem] += 1

            if ecosystem and name:
                unique_packages.add((ecosystem, name))

    osv_epss_matches = all_osv_cves & epss_cves
    osv_kev_matches = all_osv_cves & kev_cves
    kev_osv_matches = kev_cves & all_osv_cves

    print("\n========== COVERAGE REPORT ==========")

    print("\nOSV:")
    print("Total records:", len(osv_files))
    print("Records with CVE aliases:", osv_records_with_cve)
    print("Records without CVE aliases:", osv_records_without_cve)
    print("Unique CVEs extracted:", len(all_osv_cves))
    print("Affected package entries:", affected_entries)
    print("Unique ecosystem/package combinations:", len(unique_packages))

    print("\nTop ecosystems:")
    for ecosystem, count in ecosystems.most_common(10):
        print(f"{ecosystem}: {count}")

    print("\nEPSS:")
    print("Total unique CVEs:", len(epss_cves))
    print("OSV CVEs matched in EPSS:", len(osv_epss_matches))

    print("\nCISA KEV:")
    print("Total unique KEV CVEs:", len(kev_cves))
    print("OSV CVEs matched in KEV:", len(osv_kev_matches))
    print("KEV CVEs matched in OSV:", len(kev_osv_matches))

    print("\n========== ANALYSIS COMPLETE ==========")


if __name__ == "__main__":
    analyze_coverage()
