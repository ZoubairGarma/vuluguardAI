
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

CVE_FEATURES_FILE = PROCESSED_DIR / "cve_features.csv"
CVSS_FILE = PROCESSED_DIR / "cvss_scores.csv"

OUTPUT_DIR = PROCESSED_DIR / "risk"
OUTPUT_FILE = OUTPUT_DIR / "risk_assessment.csv"

# Provisional weights for non-KEV vulnerabilities.
CVSS_WEIGHT = 0.60
EPSS_WEIGHT = 0.40

# Provisional risk-level thresholds.
RISK_THRESHOLDS = {
    "LOW": 30,
    "MEDIUM": 60,
    "HIGH": 80,
    "CRITICAL": 100,
}


def parse_boolean(value, column_name):
    """Convert a source value into a validated Python boolean."""

    if pd.isna(value):
        raise ValueError(f"Missing value in {column_name}.")

    if isinstance(value, (bool, np.bool_)):
        return bool(value)

    if isinstance(value, (int, np.integer)) and value in (0, 1):
        return bool(value)

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in ("true", "1", "yes"):
            return True

        if normalized in ("false", "0", "no"):
            return False

    raise ValueError(
        f"Invalid boolean value in {column_name}: {value!r}"
    )


def load_datasets():
    """Load CVE metadata and calculated CVSS scores."""

    if not CVE_FEATURES_FILE.exists():
        raise FileNotFoundError(CVE_FEATURES_FILE)

    if not CVSS_FILE.exists():
        raise FileNotFoundError(CVSS_FILE)

    cve_df = pd.read_csv(CVE_FEATURES_FILE)
    cvss_df = pd.read_csv(CVSS_FILE)

    required_cve_columns = {
        "cve_id",
        "is_kev",
        "epss_score",
        "epss_percentile",
    }

    required_cvss_columns = {
        "cve_id",
        "cvss_v3_score",
        "cvss_v3_severity",
        "cvss_v4_score",
        "cvss_v4_severity",
    }

    missing_cve = required_cve_columns - set(cve_df.columns)
    missing_cvss = required_cvss_columns - set(cvss_df.columns)

    if missing_cve:
        raise ValueError(
            f"Missing columns in cve_features.csv: {sorted(missing_cve)}"
        )

    if missing_cvss:
        raise ValueError(
            f"Missing columns in cvss_scores.csv: {sorted(missing_cvss)}"
        )

    for name, df in (
        ("CVE features", cve_df),
        ("CVSS scores", cvss_df),
    ):
        if df["cve_id"].isna().any():
            raise ValueError(f"{name} contains missing CVE IDs.")

        if df["cve_id"].duplicated().any():
            raise ValueError(f"{name} contains duplicate CVE IDs.")

    # Convert source columns to numeric values.
    numeric_columns = [
        "epss_score",
        "epss_percentile",
    ]

    for column in numeric_columns:
        cve_df[column] = pd.to_numeric(
            cve_df[column],
            errors="coerce",
        )

    for column in ("cvss_v3_score", "cvss_v4_score"):
        cvss_df[column] = pd.to_numeric(
            cvss_df[column],
            errors="coerce",
        )

    # Validate known score ranges.
    for column in ("epss_score", "epss_percentile"):
        invalid = (
            cve_df[column].notna()
            & ~cve_df[column].between(0, 1)
        )

        if invalid.any():
            raise ValueError(
                f"{column} contains values outside [0, 1]."
            )

    for column in ("cvss_v3_score", "cvss_v4_score"):
        invalid = (
            cvss_df[column].notna()
            & ~cvss_df[column].between(0, 10)
        )

        if invalid.any():
            raise ValueError(
                f"{column} contains values outside [0, 10]."
            )

    cve_df["is_kev"] = cve_df["is_kev"].apply(
        lambda value: parse_boolean(value, "is_kev")
    )

    # CVE metadata is the base: CVEs without CVSS remain included.
    merged = cve_df.merge(
        cvss_df,
        on="cve_id",
        how="left",
        validate="one_to_one",
    )

    return merged


def select_cvss(row):
    """Prefer CVSS v3; use v4 only when v3 is unavailable."""

    v3_score = row["cvss_v3_score"]
    v4_score = row["cvss_v4_score"]

    if pd.notna(v3_score):
        return (
            float(v3_score),
            row["cvss_v3_severity"],
            "CVSS_V3",
        )

    if pd.notna(v4_score):
        return (
            float(v4_score),
            row["cvss_v4_severity"],
            "CVSS_V4",
        )

    return np.nan, None, "NONE"


def _selected_cvss_version(row, cvss_type):
    """Return the version of the selected CVSS vector, when recorded."""
    if cvss_type == "CVSS_V3":
        column = "cvss_v3_version"
    elif cvss_type == "CVSS_V4":
        column = "cvss_v4_version"
    else:
        return None

    value = row.get(column)
    if pd.isna(value):
        return None
    value = str(value).strip().removeprefix("CVSS:")
    return value or None


def calculate_risk(row):
    """
    Calculate an explainable risk-prioritization score.

    KEV membership overrides the numerical score.
    For other CVEs, available CVSS and EPSS components
    are combined using normalized available weights.
    """

    cve_id = row["cve_id"]
    is_kev = row["is_kev"]

    cvss_score, cvss_severity, cvss_type = select_cvss(row)
    cvss_version = _selected_cvss_version(row, cvss_type)
    cvss_provider = "OSV" if pd.notna(cvss_score) else None
    epss_score = row["epss_score"]

    if is_kev:
        return {
            "cve_id": cve_id,
            "risk_score": 100.0,
            "risk_level": "CRITICAL",
            "cvss_score_used": cvss_score,
            "cvss_severity_used": cvss_severity,
            "cvss_source": cvss_type,
            "cvss_provider": cvss_provider,
            "cvss_version_used": cvss_version,
            "epss_score_used": epss_score,
            "is_kev": True,
            "scoring_basis": "KEV_OVERRIDE",
            "risk_explanation": (
                "Listed in CISA KEV: known exploitation. "
                "Assigned maximum priority regardless of CVSS or EPSS."
            ),
        }

    available_components = []
    explanation_parts = []

    if pd.notna(cvss_score):
        available_components.append(
            (CVSS_WEIGHT, cvss_score / 10)
        )
        version_label = (
            f"CVSS {cvss_version}"
            if cvss_version
            else "CVSS version unavailable"
        )
        explanation_parts.append(
            f"{cvss_type} ({version_label}, source OSV) score is "
            f"{cvss_score:.1f}/10"
        )

    if pd.notna(epss_score):
        available_components.append(
            (EPSS_WEIGHT, float(epss_score))
        )
        explanation_parts.append(
            f"EPSS score is {epss_score:.5f}"
        )

    if not available_components:
        return {
            "cve_id": cve_id,
            "risk_score": np.nan,
            "risk_level": "UNKNOWN",
            "cvss_score_used": np.nan,
            "cvss_severity_used": None,
            "cvss_source": "NONE",
            "cvss_provider": None,
            "cvss_version_used": None,
            "epss_score_used": np.nan,
            "is_kev": False,
            "scoring_basis": "NO_DATA",
            "risk_explanation": (
                "No CVSS score or EPSS score available. "
                "Risk cannot be calculated."
            ),
        }

    total_weight = sum(
        weight for weight, _ in available_components
    )

    weighted_score = sum(
        weight * value
        for weight, value in available_components
    )

    risk_score = 100 * weighted_score / total_weight
    risk_score = round(float(risk_score), 2)

    if risk_score < RISK_THRESHOLDS["LOW"]:
        risk_level = "LOW"
    elif risk_score < RISK_THRESHOLDS["MEDIUM"]:
        risk_level = "MEDIUM"
    elif risk_score < RISK_THRESHOLDS["HIGH"]:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    if len(available_components) == 2:
        scoring_basis = "CVSS_EPSS"
    elif pd.notna(cvss_score):
        scoring_basis = "CVSS_ONLY"
    else:
        scoring_basis = "EPSS_ONLY"

    explanation = (
        "Risk score calculated from available components: "
        + "; ".join(explanation_parts)
        + f". Result: {risk_score:.2f}/100 ({risk_level})."
    )

    return {
        "cve_id": cve_id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "cvss_score_used": cvss_score,
        "cvss_severity_used": cvss_severity,
        "cvss_source": cvss_type,
        "cvss_provider": cvss_provider,
        "cvss_version_used": cvss_version,
        "epss_score_used": epss_score,
        "is_kev": False,
        "scoring_basis": scoring_basis,
        "risk_explanation": explanation,
    }


def build_risk_assessment(df):
    """Calculate risk for every CVE."""

    records = [
        calculate_risk(row)
        for _, row in df.iterrows()
    ]

    results = pd.DataFrame(records)

    # Add EPSS percentile as contextual information.
    percentile_lookup = df.set_index("cve_id")["epss_percentile"]

    results["epss_percentile"] = results["cve_id"].map(
        percentile_lookup
    )

    # Put highest-priority CVEs first.
    results = results.sort_values(
        by="risk_score",
        ascending=False,
        na_position="last",
    ).reset_index(drop=True)

    return results


def validate_results(results, source_count):
    """Check the integrity of the generated assessment."""

    if len(results) != source_count:
        raise ValueError(
            "Some CVEs were lost during risk assessment."
        )

    if results["cve_id"].duplicated().any():
        raise ValueError("Duplicate CVE IDs in risk results.")

    kev_rows = results[results["is_kev"]]

    if not (kev_rows["risk_score"] == 100).all():
        raise ValueError("A KEV vulnerability does not have score 100.")

    if not (kev_rows["risk_level"] == "CRITICAL").all():
        raise ValueError("A KEV vulnerability is not CRITICAL.")

    invalid_scores = (
        results["risk_score"].notna()
        & ~results["risk_score"].between(0, 100)
    )

    if invalid_scores.any():
        raise ValueError("Risk scores outside [0, 100].")


def main():
    print("=" * 65)
    print("VULNGUARD AI - RISK SCORING ENGINE")
    print("=" * 65)

    df = load_datasets()

    print(f"\nCVE records loaded: {len(df)}")
    print(f"KEV records: {int(df['is_kev'].sum())}")
    print(f"Non-KEV records: {int((~df['is_kev']).sum())}")

    results = build_risk_assessment(df)

    validate_results(results, len(df))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_FILE, index=False)

    print("\nRisk-level distribution:")
    print(
        results["risk_level"]
        .value_counts()
        .reindex(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
            fill_value=0,
        )
        .to_string()
    )

    print("\nScoring-basis distribution:")
    print(results["scoring_basis"].value_counts().to_string())

    print("\nTop 10 CVEs:")
    display_columns = [
        "cve_id",
        "risk_score",
        "risk_level",
        "cvss_source",
        "cvss_provider",
        "cvss_version_used",
        "epss_score_used",
        "is_kev",
    ]

    print(
        results[display_columns]
        .head(10)
        .to_string(index=False)
    )

    print("\nValidation:")
    print(f"  Input CVEs: {len(df)}")
    print(f"  Output CVEs: {len(results)}")
    print(f"  Duplicate CVEs: {results['cve_id'].duplicated().sum()}")
    print(
        "  KEV records with score 100: "
        f"{int((results.loc[results['is_kev'], 'risk_score'] == 100).sum())}"
    )

    print(f"\nOutput file: {OUTPUT_FILE}")
    print("\nRisk scoring completed successfully.")


if __name__ == "__main__":
    main()
