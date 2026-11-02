
from pathlib import Path

import pandas as pd

from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data" / "processed" / "ml"

X_FILE = DATA_DIR / "X_features.csv"
Y_FILE = DATA_DIR / "y_kev.csv"

OUTPUT_FILE = DATA_DIR / "feature_group_comparison.csv"
SUMMARY_FILE = DATA_DIR / "feature_group_summary.csv"

RANDOM_STATE = 42
N_SPLITS = 3


def load_data():
    X = pd.read_csv(X_FILE)
    y_df = pd.read_csv(Y_FILE)

    if len(X) != len(y_df):
        raise ValueError("X and y have different row counts.")

    if not X.columns.is_unique:
        raise ValueError("Duplicate feature column names detected.")

    if y_df["cve_id"].duplicated().any():
        raise ValueError("Duplicate CVE IDs detected.")

    if set(y_df["is_kev"].unique()) != {0, 1}:
        raise ValueError("Expected both KEV classes: 0 and 1.")

    return X, y_df["is_kev"].astype(int)


def build_feature_groups(X):
    epss_columns = ["epss_score", "epss_percentile"]

    missing = [col for col in epss_columns if col not in X.columns]
    if missing:
        raise ValueError(f"Missing EPSS columns: {missing}")

    return {
        "A_all_features": X.columns.tolist(),
        "B_without_EPSS": [
            col for col in X.columns if col not in epss_columns
        ],
        "C_EPSS_only": epss_columns,
    }


def build_model():
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    class_weight="balanced",
                    C=0.1,
                    solver="liblinear",
                    max_iter=5000,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )


def main():
    print("=" * 65)
    print("VULNGUARD AI - FEATURE GROUP ABLATION")
    print("=" * 65)

    X, y = load_data()
    feature_groups = build_feature_groups(X)

    cv = StratifiedKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    results = []

    for group_name, columns in feature_groups.items():
        print(f"\n{'-' * 55}")
        print(f"Feature group: {group_name}")
        print(f"Number of features: {len(columns)}")

        X_group = X[columns]

        for fold, (train_idx, test_idx) in enumerate(
            cv.split(X_group, y),
            start=1,
        ):
            X_train = X_group.iloc[train_idx]
            X_test = X_group.iloc[test_idx]

            y_train = y.iloc[train_idx]
            y_test = y.iloc[test_idx]

            model = build_model()
            model.fit(X_train, y_train)

            predictions = model.predict(X_test)
            probabilities = model.predict_proba(X_test)[:, 1]

            result = {
                "feature_group": group_name,
                "fold": fold,
                "number_of_features": len(columns),
                "train_kev": int(y_train.sum()),
                "test_kev": int(y_test.sum()),
                "precision": precision_score(
                    y_test, predictions, zero_division=0
                ),
                "recall": recall_score(
                    y_test, predictions, zero_division=0
                ),
                "f1": f1_score(
                    y_test, predictions, zero_division=0
                ),
                "average_precision": average_precision_score(
                    y_test, probabilities
                ),
                "roc_auc": roc_auc_score(
                    y_test, probabilities
                ),
            }

            results.append(result)

            print(
                f"Fold {fold}: "
                f"Precision={result['precision']:.4f}, "
                f"Recall={result['recall']:.4f}, "
                f"F1={result['f1']:.4f}, "
                f"AP={result['average_precision']:.4f}, "
                f"ROC AUC={result['roc_auc']:.4f}"
            )

    results_df = pd.DataFrame(results)

    metric_columns = [
        "precision",
        "recall",
        "f1",
        "average_precision",
        "roc_auc",
    ]

    summary = (
        results_df.groupby("feature_group")[metric_columns]
        .agg(["mean", "std"])
        .round(4)
    )

    results_df.to_csv(OUTPUT_FILE, index=False)
    summary.to_csv(SUMMARY_FILE)

    print("\n" + "=" * 65)
    print("FEATURE GROUP COMPARISON SUMMARY")
    print("=" * 65)
    print(summary.to_string())

    print("\nFiles created:")
    print(OUTPUT_FILE)
    print(SUMMARY_FILE)

    print("\nExperiment completed.")


if __name__ == "__main__":
    main()
