
import json
from pathlib import Path

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "data" / "processed" / "ml_features.csv"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed" / "ml"

X_OUTPUT = OUTPUT_DIR / "X_features.csv"
Y_OUTPUT = OUTPUT_DIR / "y_kev.csv"
METADATA_OUTPUT = OUTPUT_DIR / "dataset_metadata.json"

ID_COLUMN = "cve_id"
TARGET_COLUMN = "is_kev"


def load_dataset():
    """Load and validate the engineered feature dataset."""

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_FILE}\n"
            "Run feature_engineering.py first."
        )

    df = pd.read_csv(INPUT_FILE)

    required_columns = {ID_COLUMN, TARGET_COLUMN}
    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Required columns are missing: {sorted(missing_columns)}"
        )

    if df[ID_COLUMN].isna().any():
        raise ValueError("Some rows have a missing CVE ID.")

    if df[ID_COLUMN].duplicated().any():
        raise ValueError("Duplicate CVE IDs detected.")

    return df


def prepare_features_and_target(df):
    """Separate model inputs (X) from the exploratory KEV target (y)."""

    # is_kev is the target, so it must not be included in X.
    excluded_columns = [ID_COLUMN, TARGET_COLUMN]

    feature_columns = [
        column
        for column in df.columns
        if column not in excluded_columns
    ]

    X = df[feature_columns].copy()

    # All model input columns must be numeric.
    non_numeric_columns = X.select_dtypes(exclude=["number"]).columns.tolist()

    if non_numeric_columns:
        raise TypeError(
            f"Non-numeric model features detected: {non_numeric_columns}"
        )

    # Replace infinite values with NaN, then validate.
    X = X.replace([np.inf, -np.inf], np.nan)

    # Do not impute missing values here.
    # Imputation must be fitted on training data only.
    y = df[[ID_COLUMN, TARGET_COLUMN]].copy()

    if y[TARGET_COLUMN].isna().any():
        raise ValueError("The KEV target contains missing values.")

    target_values = set(y[TARGET_COLUMN].unique())

    if not target_values.issubset({0, 1}):
        raise ValueError(
            f"Unexpected values in {TARGET_COLUMN}: {target_values}"
        )

    return X, y, feature_columns


def save_outputs(X, y, feature_columns):
    """Save the feature matrix, target labels, and dataset metadata."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    X.to_csv(X_OUTPUT, index=False)
    y.to_csv(Y_OUTPUT, index=False)

    target_distribution = {
        str(key): int(value)
        for key, value in y[TARGET_COLUMN].value_counts().sort_index().items()
    }

    metadata = {
        "source_file": str(INPUT_FILE.relative_to(PROJECT_ROOT)),
        "feature_file": str(X_OUTPUT.relative_to(PROJECT_ROOT)),
        "target_file": str(Y_OUTPUT.relative_to(PROJECT_ROOT)),
        "rows": int(len(X)),
        "number_of_features": int(X.shape[1]),
        "feature_columns": feature_columns,
        "target_column": TARGET_COLUMN,
        "target_distribution": target_distribution,
        "missing_values_per_feature": {
            column: int(count)
            for column, count in X.isna().sum().items()
            if count > 0
        },
        "missing_values_total": int(X.isna().sum().sum()),
        "preprocessing_notes": [
            "cve_id is kept in the target file for traceability.",
            "is_kev is excluded from X to avoid target leakage.",
            "Missing EPSS values are preserved.",
            "No imputation or scaling has been applied.",
            "Imputation and scaling must be fitted on training data only.",
            "KEV target is highly imbalanced and is exploratory only."
        ]
    }

    with open(METADATA_OUTPUT, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4, ensure_ascii=False)

    return metadata


def main():
    print("=" * 65)
    print("VULNGUARD AI - ML DATASET PREPARATION")
    print("=" * 65)

    df = load_dataset()

    print(f"\nSource dataset: {INPUT_FILE}")
    print(f"Source rows: {len(df)}")
    print(f"Source columns: {len(df.columns)}")

    X, y, feature_columns = prepare_features_and_target(df)

    print("\nFeature matrix (X):")
    print(f"  Rows: {X.shape[0]}")
    print(f"  Features: {X.shape[1]}")
    print(f"  Missing values: {X.isna().sum().sum()}")

    print("\nKEV target (y):")
    print(y[TARGET_COLUMN].value_counts().sort_index().to_string())

    print("\nMissing values by feature:")
    missing = X.isna().sum()
    missing = missing[missing > 0]

    if missing.empty:
        print("  None")
    else:
        print(missing.to_string())

    metadata = save_outputs(X, y, feature_columns)

    print("\nFiles created:")
    print(f"  {X_OUTPUT}")
    print(f"  {Y_OUTPUT}")
    print(f"  {METADATA_OUTPUT}")

    print("\nPreparation summary:")
    print(f"  Total rows: {metadata['rows']}")
    print(f"  Model features: {metadata['number_of_features']}")
    print(f"  KEV distribution: {metadata['target_distribution']}")
    print(f"  Missing cells in X: {metadata['missing_values_total']}")

    print("\nDataset preparation completed successfully.")


if __name__ == "__main__":
    main()
