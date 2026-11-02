
import json
from pathlib import Path

import pandas as pd
from cvss import CVSS3, CVSS4


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data" / "processed"

INPUT_FILE = DATA_DIR / "osv_severity.csv"
DETAIL_OUTPUT = DATA_DIR / "cvss_scores_detail.csv"
SUMMARY_OUTPUT = DATA_DIR / "cvss_scores.csv"



def calculate_cvss(vector):
    """Calculate the CVSS base score and severity from a vector."""

    try:
        if not isinstance(vector, str) or not vector.strip():
            return None, None, "Empty vector"

        # Remove accidental whitespace and trailing slashes.
        vector = vector.strip().rstrip("/")

        if vector.startswith("CVSS:3."):
            calculator = CVSS3(vector)

        elif vector.startswith("CVSS:4."):
            calculator = CVSS4(vector)

        else:
            return None, None, "Unsupported CVSS version"

        scores = calculator.scores()
        severities = calculator.severities()

        base_score = float(scores[0])
        severity = severities[0]

        return base_score, severity, None

    except Exception as error:
        return None, None, str(error)



def parse_cve_ids(value):
    """Convert the JSON CVE list into a Python list."""

    try:
        result = json.loads(value)

        if isinstance(result, list):
            return [
                cve.strip().upper()
                for cve in result
                if isinstance(cve, str) and cve.strip()
            ]

    except (json.JSONDecodeError, TypeError):
        pass

    return []


def main():
    print("Loading OSV severity data...")

    if not INPUT_FILE.exists():
        raise FileNotFoundError(INPUT_FILE)

    severity_df = pd.read_csv(INPUT_FILE)

    print(f"Input entries: {len(severity_df)}")

    detail_rows = []

    for index, row in severity_df.iterrows():
        vector = row["vector"]

        score, severity, error = calculate_cvss(vector)

        detail_rows.append({
            "osv_id": row["osv_id"],
            "cve_ids": row["cve_ids"],
            "severity_type": row["severity_type"],
            "cvss_version": row["cvss_version"],
            "vector": vector,
            "cvss_base_score": score,
            "cvss_severity": severity,
            "calculation_error": error,
        })

        if (index + 1) % 2000 == 0:
            print(f"Processed {index + 1}/{len(severity_df)} entries")

    detail_df = pd.DataFrame(detail_rows)

    detail_df.to_csv(DETAIL_OUTPUT, index=False)

    print("\nDetailed CVSS results saved:")
    print(DETAIL_OUTPUT)

    # Build a CVE-level summary.
    # Keep CVSS v3 and v4 separate.
    cve_rows = []

    for _, row in detail_df.iterrows():
        cve_ids = parse_cve_ids(row["cve_ids"])

        for cve_id in cve_ids:
            cve_rows.append({
                "cve_id": cve_id,
                "osv_id": row["osv_id"],
                "severity_type": row["severity_type"],
                "cvss_version": row["cvss_version"],
                "vector": row["vector"],
                "cvss_base_score": row["cvss_base_score"],
                "cvss_severity": row["cvss_severity"],
            })

    associations = pd.DataFrame(cve_rows)

    if associations.empty:
        raise ValueError("No CVE associations found in severity data.")

    summary_rows = []

    for cve_id, group in associations.groupby("cve_id"):
        v3 = group[
            group["severity_type"] == "CVSS_V3"
        ]

        v4 = group[
            group["severity_type"] == "CVSS_V4"
        ]

        valid_v3 = v3["cvss_base_score"].dropna()
        valid_v4 = v4["cvss_base_score"].dropna()

        v3_max = valid_v3.max() if not valid_v3.empty else None
        v4_max = valid_v4.max() if not valid_v4.empty else None

        summary_rows.append({
            "cve_id": cve_id,
            "cvss_v3_score": v3_max,
            "cvss_v3_severity": (
                v3.loc[
                    v3["cvss_base_score"].idxmax(),
                    "cvss_severity"
                ]
                if not valid_v3.empty else None
            ),
            "cvss_v3_entry_count": len(v3),
            "cvss_v4_score": v4_max,
            "cvss_v4_severity": (
                v4.loc[
                    v4["cvss_base_score"].idxmax(),
                    "cvss_severity"
                ]
                if not valid_v4.empty else None
            ),
            "cvss_v4_entry_count": len(v4),
            "cvss_vector_count": len(group),
            "cvss_vectors": json.dumps(
                group["vector"].dropna().unique().tolist()
            ),
            "osv_ids": json.dumps(
                group["osv_id"].dropna().unique().tolist()
            ),
        })

    summary_df = pd.DataFrame(summary_rows)

    summary_df.to_csv(SUMMARY_OUTPUT, index=False)

    print("\nCVSS summary saved:")
    print(SUMMARY_OUTPUT)

    print("\n========== RESULTS ==========")
    print(f"Original severity entries: {len(severity_df)}")
    print(f"Successfully calculated: {detail_df['cvss_base_score'].notna().sum()}")
    print(f"Calculation errors: {detail_df['calculation_error'].notna().sum()}")
    print(f"Unique CVEs with CVSS: {summary_df['cve_id'].nunique()}")
    print(f"CVEs with CVSS v3: {summary_df['cvss_v3_score'].notna().sum()}")
    print(f"CVEs with CVSS v4: {summary_df['cvss_v4_score'].notna().sum()}")

    print("\nSample CVE scores:")
    print(
        summary_df[
            [
                "cve_id",
                "cvss_v3_score",
                "cvss_v3_severity",
                "cvss_v4_score",
                "cvss_v4_severity",
            ]
        ].head(10).to_string(index=False)
    )

    print("\nCVSS calculation completed.")


if __name__ == "__main__":
    main()
