
import json
import re
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

OSV_DIR = PROJECT_ROOT / "data" / "raw" / "osv"
EPSS_FILE = PROJECT_ROOT / "data" / "raw" / "epss" / "epss_scores-current.csv.gz"
KEV_FILE = PROJECT_ROOT / "data" / "raw" / "kev" / "known_exploited_vulnerabilities.json"

OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$",
    re.IGNORECASE
)


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


def parse_cvss_vector(vector):
    """
    Parse a CVSS vector into its version and individual metrics.

    The original vector is preserved separately.
    """
    if not isinstance(vector, str):
        return {}

    if not vector.startswith("CVSS:"):
        return {}

    parts = vector.split("/")
    parsed = {}

    # First component identifies the CVSS version.
    parsed["cvss_version"] = parts[0].replace("CVSS:", "", 1)

    # Remaining components contain metrics such as AV:N or AC:L.
    for part in parts[1:]:
        if ":" not in part:
            continue

        key, value = part.split(":", 1)
        parsed[key] = value

    return parsed


def extract_severity_entries(record, osv_id, cves):
    """
    Extract all severity entries from one OSV record.

    One row is retained per severity entry, even when its
    vector is missing or cannot be parsed.
    """
    entries = []

    severity_list = record.get("severity", [])

    if not isinstance(severity_list, list):
        return entries

    for severity in severity_list:
        if not isinstance(severity, dict):
            continue

        vector = severity.get("score")
        severity_type = severity.get("type")

        metrics = parse_cvss_vector(vector)

        entries.append({
            "osv_id": osv_id,
            "cve_ids": json.dumps(cves),
            "severity_type": severity_type,
            "cvss_version": metrics.get("cvss_version"),
            "vector": vector,

            # Common CVSS metrics
            "attack_vector": metrics.get("AV"),
            "attack_complexity": metrics.get("AC"),
            "privileges_required": metrics.get("PR"),
            "user_interaction": metrics.get("UI"),

            # CVSS v3 metrics
            "scope": metrics.get("S"),
            "confidentiality_impact": metrics.get("C"),
            "integrity_impact": metrics.get("I"),
            "availability_impact": metrics.get("A"),

            # CVSS v4 metrics
            "attack_requirements": metrics.get("AT"),
            "vulnerable_system_confidentiality": metrics.get("VC"),
            "vulnerable_system_integrity": metrics.get("VI"),
            "vulnerable_system_availability": metrics.get("VA"),
            "subsequent_system_confidentiality": metrics.get("SC"),
            "subsequent_system_integrity": metrics.get("SI"),
            "subsequent_system_availability": metrics.get("SA"),
            "exploit_maturity": metrics.get("E")
        })

    return entries


def integrate_datasets():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading EPSS dataset...", flush=True)

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

    print("Loading CISA KEV dataset...", flush=True)

    with KEV_FILE.open("r", encoding="utf-8") as file:
        kev_data = json.load(file)

    kev_lookup = {
        item["cveID"].upper(): item
        for item in kev_data.get("vulnerabilities", [])
        if item.get("cveID")
    }

    print("Processing OSV records...", flush=True)

    osv_records = []
    affected_packages = []
    severity_records = []
    cve_metadata = {}

    osv_files = list(OSV_DIR.glob("*.json"))
    total_files = len(osv_files)

    print("OSV files found:", total_files, flush=True)

    for index, path in enumerate(osv_files, start=1):

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

        # Extract affected package information.
        affected_entries = record.get("affected", [])

        for affected in affected_entries:

            package = affected.get("package", {})

            affected_packages.append({
                "osv_id": osv_id,
                "ecosystem": package.get("ecosystem"),
                "package_name": package.get("name"),
                "purl": package.get("purl"),
                "ranges": json.dumps(affected.get("ranges", [])),
                "versions": json.dumps(affected.get("versions", []))
            })

        # Extract CVSS severity entries.
        record_severity = extract_severity_entries(
            record,
            osv_id,
            cves
        )

        severity_records.extend(record_severity)

        # Build CVE-level metadata.
        for cve in cves:

            if cve not in cve_metadata:
                cve_metadata[cve] = {
                    "cve_id": cve,
                    "osv_record_count": 0,
                    "osv_ids": set(),
                    "package_combinations": set(),
                    "cvss_v3_vectors": set(),
                    "cvss_v4_vectors": set(),
                    "cvss_v3_entry_count": 0,
                    "cvss_v4_entry_count": 0
                }

            metadata = cve_metadata[cve]

            metadata["osv_record_count"] += 1
            metadata["osv_ids"].add(osv_id)

            for affected in affected_entries:
                package = affected.get("package", {})

                ecosystem = package.get("ecosystem")
                package_name = package.get("name")

                if ecosystem and package_name:
                    metadata["package_combinations"].add(
                        (ecosystem, package_name)
                    )

            # Associate severity entries with each CVE alias
            # belonging to this OSV record.
            for severity_entry in record_severity:

                vector = severity_entry.get("vector")
                severity_type = severity_entry.get("severity_type")

                if severity_type == "CVSS_V3":
                    metadata["cvss_v3_entry_count"] += 1

                    if isinstance(vector, str):
                        metadata["cvss_v3_vectors"].add(vector)

                elif severity_type == "CVSS_V4":
                    metadata["cvss_v4_entry_count"] += 1

                    if isinstance(vector, str):
                        metadata["cvss_v4_vectors"].add(vector)

        # Display progress so the terminal does not look frozen.
        if index % 1000 == 0 or index == total_files:
            print(
                f"Processed {index}/{total_files} OSV files",
                flush=True
            )

    print("\nBuilding CVE feature dataset...", flush=True)

    cve_rows = []

    for cve, metadata in cve_metadata.items():

        kev_record = kev_lookup.get(cve)

        cve_rows.append({
            "cve_id": cve,
            "osv_record_count": metadata["osv_record_count"],
            "osv_ids": json.dumps(sorted(metadata["osv_ids"])),
            "affected_package_count": len(
                metadata["package_combinations"]
            ),

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
            ),

            # CVSS features
            "cvss_v3_entry_count": metadata["cvss_v3_entry_count"],
            "cvss_v4_entry_count": metadata["cvss_v4_entry_count"],

            "cvss_v3_vectors": json.dumps(
                sorted(metadata["cvss_v3_vectors"])
            ),

            "cvss_v4_vectors": json.dumps(
                sorted(metadata["cvss_v4_vectors"])
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
    severity_df = pd.DataFrame(severity_records)

    print("\nSaving processed datasets...", flush=True)

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

    severity_df.to_csv(
        OUTPUT_DIR / "osv_severity.csv",
        index=False
    )

    print("\n========== INTEGRATION REPORT ==========")

    print("OSV records:", len(osv_df))
    print("Affected package entries:", len(packages_df))
    print("Severity entries:", len(severity_df))
    print("Unique CVEs:", len(cve_df))

    print("CVEs with EPSS:", cve_df["has_epss"].sum())
    print("CVEs without EPSS:", (~cve_df["has_epss"]).sum())
    print("CVEs in KEV:", cve_df["is_kev"].sum())

    print(
        "CVEs with CVSS v3:",
        (cve_df["cvss_v3_entry_count"] > 0).sum()
    )

    print(
        "CVEs with CVSS v4:",
        (cve_df["cvss_v4_entry_count"] > 0).sum()
    )

    print("\nSaved files:")
    print("data/processed/osv_records.csv")
    print("data/processed/osv_affected_packages.csv")
    print("data/processed/cve_features.csv")
    print("data/processed/osv_severity.csv")

    print("\nINTEGRATION COMPLETE")


if __name__ == "__main__":
    integrate_datasets()
