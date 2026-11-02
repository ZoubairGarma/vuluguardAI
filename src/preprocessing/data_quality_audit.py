
import json
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
AUDIT_DIR = PROCESSED_DIR / "audit"

ML_FEATURES_PATH = PROCESSED_DIR / "ml_features.csv"
CVSS_SCORES_PATH = PROCESSED_DIR / "cvss_scores.csv"
AFFECTED_PACKAGES_PATH = PROCESSED_DIR / "osv_affected_packages.csv"

AUDIT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOAD DATASETS
# ============================================================

def load_datasets():
    print("\n" + "=" * 65)
    print("VULNGUARD AI - DATA QUALITY AUDIT")
    print("=" * 65)

    required_files = [
        ML_FEATURES_PATH,
        CVSS_SCORES_PATH,
        AFFECTED_PACKAGES_PATH,
    ]

    for file_path in required_files:
        if not file_path.exists():
            raise FileNotFoundError(
                f"Required dataset not found: {file_path}"
            )

    ml_features = pd.read_csv(ML_FEATURES_PATH)
    cvss_scores = pd.read_csv(CVSS_SCORES_PATH)
    affected_packages = pd.read_csv(AFFECTED_PACKAGES_PATH)

    print("\nDATASETS LOADED")
    print("-" * 65)

    print(
        f"ML Features: {ml_features.shape[0]} rows, "
        f"{ml_features.shape[1]} columns"
    )

    print(
        f"CVSS Scores: {cvss_scores.shape[0]} rows, "
        f"{cvss_scores.shape[1]} columns"
    )

    print(
        f"Affected Packages: {affected_packages.shape[0]} rows, "
        f"{affected_packages.shape[1]} columns"
    )

    return ml_features, cvss_scores, affected_packages


# ============================================================
# BASIC DATA QUALITY
# ============================================================

def check_basic_quality(ml_features, cvss_scores, affected_packages):

    print("\n" + "=" * 65)
    print("1. BASIC DATA QUALITY")
    print("=" * 65)

    datasets = {
        "ML Features": ml_features,
        "CVSS Scores": cvss_scores,
        "Affected Packages": affected_packages,
    }

    for name, df in datasets.items():

        print(f"\n{name}")
        print("-" * 45)

        print(f"Rows: {len(df)}")
        print(f"Columns: {len(df.columns)}")
        print(f"Exact duplicate rows: {df.duplicated().sum()}")

    if "cve_id" in ml_features.columns:

        print("\nML FEATURES - CVE ID CHECK")
        print("-" * 45)

        print(
            "Duplicate CVE IDs:",
            ml_features["cve_id"].duplicated().sum()
        )

        print(
            "Missing CVE IDs:",
            ml_features["cve_id"].isna().sum()
        )

    return {
        "ml_duplicate_rows": int(ml_features.duplicated().sum()),
        "cvss_duplicate_rows": int(cvss_scores.duplicated().sum()),
        "packages_duplicate_rows": int(affected_packages.duplicated().sum()),
    }


# ============================================================
# FEATURE QUALITY
# ============================================================

def analyze_feature_quality(ml_features):

    print("\n" + "=" * 65)
    print("2. FEATURE QUALITY ANALYSIS")
    print("=" * 65)

    numeric = ml_features.select_dtypes(include=[np.number])

    print(f"\nTotal features: {len(ml_features.columns) - 1}")
    print(f"Numeric features: {len(numeric.columns)}")

    non_numeric = [
        col for col in ml_features.columns
        if col != "cve_id" and col not in numeric.columns
    ]

    print("Non-numeric features:", non_numeric)

    # Missing values
    missing = ml_features.isna().sum()
    missing = missing[missing > 0]

    print("\nMISSING VALUES")
    print("-" * 45)

    if missing.empty:
        print("No missing values.")
    else:
        print(missing.to_string())

    # Infinite values
    infinite_counts = {}

    for column in numeric.columns:
        count = int(np.isinf(numeric[column]).sum())

        if count > 0:
            infinite_counts[column] = count

    print("\nINFINITE VALUES")
    print("-" * 45)

    if not infinite_counts:
        print("No infinite values.")
    else:
        print(infinite_counts)

    # Constant, low-cardinality and near-constant features
    constant_features = []
    low_cardinality_features = []
    near_constant_features = []

    for column in numeric.columns:

        values = numeric[column].dropna()

        if values.empty:
            continue

        unique_count = values.nunique()

        # Constant: only one unique value
        if unique_count <= 1:
            constant_features.append(column)
            continue

        # Low cardinality: at most 10 distinct values
        if unique_count <= 10:
            low_cardinality_features.append({
                "feature": column,
                "unique_values": int(unique_count),
            })

        # Near-constant: one value represents at least 99%
        dominant_share = values.value_counts(
            normalize=True
        ).iloc[0]

        if dominant_share >= 0.99:

            dominant_value = values.value_counts().index[0]

            near_constant_features.append({
                "feature": column,
                "dominant_value": dominant_value,
                "dominant_value_percentage": round(
                    dominant_share * 100, 2
                ),
                "unique_values": int(unique_count),
            })

    print("\nCONSTANT FEATURES")
    print("-" * 45)

    if constant_features:
        for feature in constant_features:
            print(f"- {feature}")
    else:
        print("None")

    print("\nLOW-CARDINALITY FEATURES (<= 10 unique values)")
    print("-" * 45)

    if low_cardinality_features:
        for item in low_cardinality_features:
            print(
                f"- {item['feature']}: "
                f"{item['unique_values']} unique values"
            )
    else:
        print("None")

    print("\nNEAR-CONSTANT FEATURES (dominant value >= 99%)")
    print("-" * 45)

    if near_constant_features:
        for item in near_constant_features:
            print(
                f"- {item['feature']}: "
                f"{item['dominant_value_percentage']}% "
                f"dominant value "
                f"(value={item['dominant_value']}, "
                f"unique={item['unique_values']})"
            )
    else:
        print("None")

    # Feature statistics
    statistics = numeric.describe().T

    statistics["missing_count"] = numeric.isna().sum()
    statistics["missing_percentage"] = (
        numeric.isna().mean() * 100
    )

    statistics.to_csv(
        AUDIT_DIR / "feature_statistics.csv"
    )

    # Feature quality report
    quality_rows = []

    for column in numeric.columns:

        values = numeric[column].dropna()

        if values.empty:
            continue

        quality_rows.append({
            "feature": column,
            "dtype": str(numeric[column].dtype),
            "missing_count": int(numeric[column].isna().sum()),
            "missing_percentage": round(
                numeric[column].isna().mean() * 100, 4
            ),
            "unique_values": int(values.nunique()),
            "is_constant": column in constant_features,
            "is_low_cardinality": any(
                item["feature"] == column
                for item in low_cardinality_features
            ),
            "is_near_constant": any(
                item["feature"] == column
                for item in near_constant_features
            ),
            "infinite_count": int(
                np.isinf(numeric[column]).sum()
            ),
        })

    quality_report = pd.DataFrame(quality_rows)

    quality_report.to_csv(
        AUDIT_DIR / "feature_quality_report.csv",
        index=False
    )

    return numeric, constant_features, low_cardinality_features, near_constant_features


# ============================================================
# OUTLIER ANALYSIS
# ============================================================

def analyze_outliers(numeric):

    print("\n" + "=" * 65)
    print("3. OUTLIER ANALYSIS - IQR METHOD")
    print("=" * 65)

    outlier_rows = []

    for column in numeric.columns:

        values = numeric[column].dropna()

        if values.empty:
            continue

        q1 = values.quantile(0.25)
        q3 = values.quantile(0.75)

        iqr = q3 - q1

        if iqr == 0:
            outlier_count = 0
        else:
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr

            outlier_count = int(
                (
                    (values < lower_bound)
                    | (values > upper_bound)
                ).sum()
            )

        outlier_percentage = (
            outlier_count / len(values) * 100
        )

        if outlier_count > 0:

            outlier_rows.append({
                "feature": column,
                "outlier_count": outlier_count,
                "outlier_percentage": round(
                    outlier_percentage, 2
                ),
                "q1": q1,
                "q3": q3,
                "iqr": iqr,
            })

    outlier_report = pd.DataFrame(outlier_rows)

    if not outlier_report.empty:

        outlier_report = outlier_report.sort_values(
            by="outlier_count",
            ascending=False
        )

        print(
            outlier_report.head(20).to_string(index=False)
        )

    else:
        print("No IQR outliers detected.")

    outlier_report.to_csv(
        AUDIT_DIR / "outlier_report.csv",
        index=False
    )

    print("\nNote: IQR outliers are flagged for investigation.")
    print("They are NOT automatically removed.")


# ============================================================
# CORRELATION ANALYSIS
# ============================================================

def analyze_correlations(numeric):

    print("\n" + "=" * 65)
    print("4. HIGHLY CORRELATED FEATURES")
    print("=" * 65)

    correlation_matrix = numeric.corr(
        method="pearson"
    ).abs()

    upper_triangle = correlation_matrix.where(
        np.triu(
            np.ones(correlation_matrix.shape),
            k=1
        ).astype(bool)
    )

    correlation_rows = []

    for column in upper_triangle.columns:

        for index in upper_triangle.index:

            correlation = upper_triangle.loc[index, column]

            if pd.notna(correlation) and correlation >= 0.90:

                correlation_rows.append({
                    "feature_1": index,
                    "feature_2": column,
                    "absolute_correlation": round(
                        float(correlation), 6
                    ),
                })

    correlation_report = pd.DataFrame(correlation_rows)

    if not correlation_report.empty:

        correlation_report = correlation_report.sort_values(
            by="absolute_correlation",
            ascending=False
        )

        print(
            correlation_report.to_string(index=False)
        )

    else:
        print("No feature pairs with correlation >= 0.90.")

    correlation_report.to_csv(
        AUDIT_DIR / "high_correlations.csv",
        index=False
    )


# ============================================================
# DOMAIN-SPECIFIC VALIDATION
# ============================================================

def validate_domain_values(ml_features, cvss_scores):

    print("\n" + "=" * 65)
    print("5. DOMAIN-SPECIFIC VALIDATION")
    print("=" * 65)

    # EPSS
    if "epss_score" in ml_features.columns:

        epss = ml_features["epss_score"]

        print("\nEPSS")
        print("-" * 45)

        print("Missing:", int(epss.isna().sum()))
        print(
            "Outside [0, 1]:",
            int(((epss < 0) | (epss > 1)).sum())
        )

    # KEV
    if "is_kev" in ml_features.columns:

        print("\nKEV")
        print("-" * 45)

        print(ml_features["is_kev"].value_counts(dropna=False))

        valid_kev_values = {0, 1}

        invalid_kev = ~ml_features["is_kev"].isin(
            valid_kev_values
        )

        print(
            "Invalid KEV values:",
            int(invalid_kev.sum())
        )

    # CVSS scores
    print("\nCVSS SCORES")
    print("-" * 45)

    for column in ["cvss_v3_score", "cvss_v4_score"]:

        if column in cvss_scores.columns:

            scores = cvss_scores[column]

            print(f"\n{column}")
            print("Missing:", int(scores.isna().sum()))

            print(
                "Outside [0, 10]:",
                int(
                    ((scores < 0) | (scores > 10)).sum()
                )
            )

    if "cve_id" in cvss_scores.columns:

        print(
            "\nDuplicate CVE IDs in CVSS:",
            int(cvss_scores["cve_id"].duplicated().sum())
        )


# ============================================================
# FINAL SUMMARY
# ============================================================

def print_final_summary(
    ml_features,
    numeric,
    constant_features,
    low_cardinality_features,
    near_constant_features,
):

    print("\n" + "=" * 65)
    print("6. FINAL AUDIT SUMMARY")
    print("=" * 65)

    print(f"ML dataset rows: {len(ml_features)}")
    print(f"Total columns: {len(ml_features.columns)}")
    print(f"Numeric features: {len(numeric.columns)}")

    print(
        "Missing numeric cells:",
        int(numeric.isna().sum().sum())
    )

    print(
        "Duplicate CVE IDs:",
        int(ml_features["cve_id"].duplicated().sum())
        if "cve_id" in ml_features.columns
        else "cve_id column not found"
    )

    print("Constant features:", len(constant_features))
    print(
        "Low-cardinality features:",
        len(low_cardinality_features)
    )
    print(
        "Near-constant features:",
        len(near_constant_features)
    )

    print("\nREPORT FILES")
    print("-" * 45)

    report_files = [
        "feature_statistics.csv",
        "feature_quality_report.csv",
        "outlier_report.csv",
        "high_correlations.csv",
    ]

    for filename in report_files:
        print(f"- {AUDIT_DIR / filename}")

    print("\nAudit completed successfully.")
    print("Original datasets were not modified.")


# ============================================================
# MAIN
# ============================================================

def main():

    ml_features, cvss_scores, affected_packages = load_datasets()

    check_basic_quality(
        ml_features,
        cvss_scores,
        affected_packages
    )

    (
        numeric,
        constant_features,
        low_cardinality_features,
        near_constant_features,
    ) = analyze_feature_quality(ml_features)

    analyze_outliers(numeric)

    analyze_correlations(numeric)

    validate_domain_values(
        ml_features,
        cvss_scores
    )

    print_final_summary(
        ml_features,
        numeric,
        constant_features,
        low_cardinality_features,
        near_constant_features,
    )


if __name__ == "__main__":
    main()
