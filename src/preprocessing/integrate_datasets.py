
import json
import re
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

OSV_DIR = PROJECT_ROOT / "data" / "raw" / "osv"
EPSS_FILE = PROJECT_ROOT / "data" / "raw" / "epss" / "epss_scores-current.csv.gz"
KEV_FILE = PROJECT_ROOT / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"

OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def extract_cves(record):
    """Extract CVE identifiers from an OSV record."""
    identifiers = set()

    possible_ids = [record.get("id")]
    possible_ids.extend(record.get("aliases", []))

    for identifier in possible_ids:
        if isinstance(identifier, str):
            identifier = identifier.upper()

            if CVE_PATTERN.match(identifier):
                identifiers.add(identifier)

    return sorted(identifiers)


def integrate_datasets():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading EPSS dataset...")

    epss_df = pd.read_csv(
        EPSS_FILE,
        compression="gzip",
        comment="#"
    )

    epss_df["cve"] = epss_df["cve"].str.upper()

    epss_df = epss_df.rename(
        columns={
            "cve": "cve_id",
            "epss": "epss_score",
            "percentile": "epss_percentile"
        }
    )

    print("Loading CISA KEV dataset...")

    with KEV_FILE.open("r", encoding="utf-8") as file:
        kev_data = json.load(file)

    kev_lookup = {
        item["cveID"].upper(): item
        for item in kev_data.get("vulnerabilities", [])
        if item.get("cveID")
    }

    print("Processing OSV records...")

    osv_records = []
    affected_packages = []
    cve_metadata = {}

    for path in OSV_DIR.glob("*.json"):

        with path.open("r", encoding="utf-8") as file:
            record = json.load(file)

        osv_id = record.get("id", path.stem)

        cves = extract_cves(record)

        osv_records.append({
            "osv_id": osv_id,
            "summary": record.get("summary"),
            "details": record.get("details"),
            "published": record.get("published"),
            "modified": record.get("modified"),
            "aliases": json.dumps(record.get("aliases", [])),
            "cve_ids": json.dumps(cves),
            "affected_entry_count": len(record.get("affected", []))
        })

        for affected in record.get("affected", []):

            package = affected.get("package", {})

            affected_packages.append({
                "osv_id": osv_id,
                "ecosystem": package.get("ecosystem"),
                "package_name": package.get("name"),
                "purl": package.get("purl"),
                "ranges": json.dumps(affected.get("ranges", [])),
                "versions": json.dumps(affected.get("versions", []))
            })

        for cve in cves:

            if cve not in cve_metadata:
                cve_metadata[cve] = {
                    "cve_id": cve,
                    "osv_record_count": 0,
                    "osv_ids": set(),
                    "package_combinations": set()
                }

            metadata = cve_metadata[cve]

            metadata["osv_record_count"] += 1
            metadata["osv_ids"].add(osv_id)

            for affected in record.get("affected", []):
                package = affected.get("package", {})

                ecosystem = package.get("ecosystem")
                package_name = package.get("name")

                if ecosystem and package_name:
                    metadata["package_combinations"].add(
                        (ecosystem, package_name)
                    )

    print("Building CVE feature dataset...")

    cve_rows = []

    for cve, metadata in cve_metadata.items():

        kev_record = kev_lookup.get(cve)

        cve_rows.append({
            "cve_id": cve,
            "osv_record_count": metadata["osv_record_count"],
            "osv_ids": json.dumps(sorted(metadata["osv_ids"])),
            "affected_package_count": len(metadata["package_combinations"]),
            "is_kev": kev_record is not None,
            "kev_date_added": (
                kev_record.get("dateAdded") if kev_record else None
            ),
            "kev_vendor": (
                kev_record.get("vendorProject") if kev_record else None
            ),
            "kev_product": (
                kev_record.get("product") if kev_record else None
            ),
            "known_ransomware_campaign_use": (
                kev_record.get("knownRansomwareCampaignUse")
                if kev_record else None
            )
        })

    cve_df = pd.DataFrame(cve_rows)

    # Left join preserves every CVE extracted from OSV.
    cve_df = cve_df.merge(
        epss_df[
            ["cve_id", "epss_score", "epss_percentile"]
        ],
        on="cve_id",
        how="left"
    )

    # Explicitly keep unmatched EPSS values as missing.
    cve_df["has_epss"] = cve_df["epss_score"].notna()

    osv_df = pd.DataFrame(osv_records)
    packages_df = pd.DataFrame(affected_packages)

    print("Saving processed datasets...")

    osv_df.to_csv(
        OUTPUT_DIR / "osv_records.csv",
        index=False
    )

    packages_df.to_csv(
        OUTPUT_DIR / "osv_affected_packages.csv",
        index=False
    )

    cve_df.to_csv(
        OUTPUT_DIR / "cve_features.csv",
        index=False
    )

    print("\n========== INTEGRATION REPORT ==========")

    print("OSV records:", len(osv_df))
    print("Affected package entries:", len(packages_df))
    print("Unique CVEs:", len(cve_df))
    print("CVEs with EPSS:", cve_df["has_epss"].sum())
    print("CVEs without EPSS:", (~cve_df["has_epss"]).sum())
    print("CVEs in KEV:", cve_df["is_kev"].sum())

    print("\nSaved files:")
    print("data/processed/osv_records.csv")
    print("data/processed/osv_affected_packages.csv")
    print("data/processed/cve_features.csv")

    print("\nINTEGRATION COMPLETE")


if __name__ == "__main__":
    integrate_datasets()
