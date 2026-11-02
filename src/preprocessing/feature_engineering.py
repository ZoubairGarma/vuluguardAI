import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"


def parse_id_list(value):
    """Convert a JSON list or delimited string into a list of IDs."""
    if pd.isna(value):
        return []

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]

    value = str(value).strip()

    if not value:
        return []

    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [
                str(item).strip()
                for item in parsed
                if str(item).strip()
            ]
        if isinstance(parsed, str):
            return [parsed.strip()] if parsed.strip() else []
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback for comma- or semicolon-separated values.
    separator = ";" if ";" in value else ","

    return [
        item.strip().strip('"').strip("'")
        for item in value.split(separator)
        if item.strip()
    ]


def load_datasets():
    """Load the four processed datasets."""
    files = {
        "cve": "cve_features.csv",
        "severity": "osv_severity.csv",
        "records": "osv_records.csv",
        "packages": "osv_affected_packages.csv",
    }

    datasets = {}

    for key, filename in files.items():
        path = PROCESSED_DIR / filename

        if not path.exists():
            raise FileNotFoundError(f"Missing input file: {path}")

        datasets[key] = pd.read_csv(path)

        print(f"Loaded {filename}: {len(datasets[key]):,} rows")

    return datasets


def add_ransomware_features(features):
    """Encode ransomware information without treating Unknown as No."""
    values = (
        features["known_ransomware_campaign_use"]
        .fillna("Unknown")
        .astype(str)
        .str.strip()
        .str.lower()
    )

    features["ransomware_use_known"] = values.isin(
        ["yes", "no"]
    ).astype(int)

    features["ransomware_campaign_use"] = values.map(
        {"yes": 1, "no": 0}
    )

    return features


def build_package_features(features, records, packages):
    """Aggregate package and ecosystem information by CVE."""

    records = records.copy()
    packages = packages.copy()

    records["cve_id_list"] = records["cve_ids"].apply(parse_id_list)

    # Connect each OSV record to its CVEs.
    cve_osv = records[["osv_id", "cve_id_list"]].explode("cve_id_list")
    cve_osv = cve_osv.rename(columns={"cve_id_list": "cve_id"})
    cve_osv = cve_osv.dropna(subset=["cve_id"])

    cve_osv["cve_id"] = cve_osv["cve_id"].astype(str).str.upper()

    # Keep unique CVE-to-OSV relationships.
    cve_osv = cve_osv.drop_duplicates(["cve_id", "osv_id"])

    # Avoid counting exact duplicate package rows twice in derived features.
    package_keys = [
        "osv_id",
        "ecosystem",
        "package_name",
        "purl",
    ]

    packages = packages.drop_duplicates(subset=package_keys)

    linked = cve_osv.merge(
        packages,
        on="osv_id",
        how="left",
    )

    linked["ecosystem"] = (
        linked["ecosystem"].fillna("").astype(str).str.strip()
    )

    linked["package_name"] = (
        linked["package_name"].fillna("").astype(str).str.strip()
    )

    linked = linked[
        (linked["ecosystem"] != "")
        & (linked["package_name"] != "")
    ].copy()

    if linked.empty:
        print("Warning: no CVE-to-package relationships were found.")
        return features

    # Unique package combinations per CVE.
    package_counts = (
        linked.groupby("cve_id")
        .agg(
            linked_package_count=("package_name", "nunique"),
            ecosystem_count=("ecosystem", "nunique"),
            linked_osv_count=("osv_id", "nunique"),
        )
    )

    features = features.join(package_counts, on="cve_id")

    # Count packages per ecosystem for each CVE.
    ecosystem_counts = (
        linked.groupby(["cve_id", "ecosystem"])["package_name"]
        .nunique()
        .unstack(fill_value=0)
    )

    ecosystem_counts.columns = [
        "ecosystem_" + str(col).lower().replace(".", "_").replace("-", "_")
        + "_package_count"
        for col in ecosystem_counts.columns
    ]

    features = features.join(ecosystem_counts, on="cve_id")

    return features


def build_cvss_features(features, severity):
    """Create numeric CVSS metric-count features per CVE."""

    severity = severity.copy()

    severity["cve_id_list"] = severity["cve_ids"].apply(parse_id_list)

    severity = severity.explode("cve_id_list")
    severity = severity.dropna(subset=["cve_id_list"])

    severity["cve_id"] = (
        severity["cve_id_list"].astype(str).str.upper()
    )

    severity["severity_type"] = severity["severity_type"].astype(str)

    # Each CVSS entry is linked to each CVE listed in its OSV record.
    severity = severity.drop_duplicates(
        subset=["cve_id", "osv_id", "severity_type", "vector"]
    )

    for version_type, prefix in [
        ("CVSS_V3", "cvss_v3"),
        ("CVSS_V4", "cvss_v4"),
    ]:
        subset = severity[
            severity["severity_type"] == version_type
        ].copy()

        if subset.empty:
            continue

        metrics = [
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
        ]

        if version_type == "CVSS_V3":
            metrics += [
                "scope",
                "confidentiality_impact",
                "integrity_impact",
                "availability_impact",
            ]
        else:
            metrics += [
                "attack_requirements",
                "vulnerable_system_confidentiality",
                "vulnerable_system_integrity",
                "vulnerable_system_availability",
                "subsequent_system_confidentiality",
                "subsequent_system_integrity",
                "subsequent_system_availability",
                "exploit_maturity",
            ]

        # Number of CVSS entries of this version per CVE.
        entry_counts = subset.groupby("cve_id").size()

        features = features.join(
            entry_counts.rename(f"{prefix}_entry_count_derived"),
            on="cve_id",
        )

        for metric in metrics:
            if metric not in subset.columns:
                continue

            values = subset[["cve_id", metric]].copy()

            values[metric] = (
                values[metric]
                .fillna("")
                .astype(str)
                .str.strip()
                .str.upper()
            )

            values = values[values[metric] != ""]

            if values.empty:
                continue

            counts = (
                values.groupby(["cve_id", metric])
                .size()
                .unstack(fill_value=0)
            )

            counts.columns = [
                f"{prefix}_{metric}_{str(value).lower()}_count"
                for value in counts.columns
            ]

            features = features.join(counts, on="cve_id")

    # Presence flags are useful even when a CVSS metric is unavailable.
    features["has_cvss_v3"] = (
        features["cvss_v3_entry_count"].fillna(0) > 0
    ).astype(int)

    features["has_cvss_v4"] = (
        features["cvss_v4_entry_count"].fillna(0) > 0
    ).astype(int)

    return features


def main():
    print("\nLoading processed datasets...")
    data = load_datasets()

    features = data["cve"].copy()

    features["cve_id"] = (
        features["cve_id"].astype(str).str.upper().str.strip()
    )

    if features["cve_id"].duplicated().any():
        raise ValueError("Duplicate CVE IDs found in cve_features.csv")

    # Convert boolean fields to numeric values.
    features["is_kev"] = features["is_kev"].astype(int)
    features["has_epss"] = features["has_epss"].astype(int)

    # Ensure EPSS values remain numeric and missing scores remain NaN.
    features["epss_score"] = pd.to_numeric(
        features["epss_score"], errors="coerce"
    )

    features["epss_percentile"] = pd.to_numeric(
        features["epss_percentile"], errors="coerce"
    )

    # Add ransomware indicators.


    # Add package and ecosystem features.
    print("\nBuilding package features...")
    features = build_package_features(
        features,
        data["records"],
        data["packages"],
    )

    # Add CVSS metric features.
    print("\nBuilding CVSS features...")
    features = build_cvss_features(
        features,
        data["severity"],
    )

    # Keep source metadata out of the initial numeric model dataset.
    metadata_columns = [
        "kev_date_added",
        "kev_vendor",
        "kev_product",
        "known_ransomware_campaign_use",
        "osv_ids",
        "cvss_v3_vectors",
        "cvss_v4_vectors",
    ]

    features = features.drop(
        columns=metadata_columns,
        errors="ignore",
    )

    # Fill missing count features with zero.
    count_columns = [

        col for col in features.columns
        if "_count" in col
    ]

    features[count_columns] = features[count_columns].fillna(0)

    features = features.drop(

        columns=[
            "ransomware_use_known",
            "ransomware_campaign_use",
        ],
        errors="ignore",
    )    

    # Keep CVE identifier as the row key, not as an ML feature.
    features = features.sort_values("cve_id").reset_index(drop=True)

    output_path = PROCESSED_DIR / "ml_features.csv"
    features.to_csv(output_path, index=False)

    print("\nFeature engineering completed.")
    print(f"Output: {output_path}")
    print(f"CVEs: {len(features):,}")
    print(f"Total columns: {len(features.columns):,}")
    print(f"Numeric feature columns: {len(features.select_dtypes(include='number').columns):,}")
    print(f"Missing EPSS scores preserved: {features['epss_score'].isna().sum():,}")
    print(f"KEV CVEs: {features['is_kev'].sum():,}")
    print(f"CVEs with CVSS v3: {features['has_cvss_v3'].sum():,}")
    print(f"CVEs with CVSS v4: {features['has_cvss_v4'].sum():,}")


if __name__ == "__main__":
    main()