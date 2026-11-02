
from pathlib import Path

import pandas as pd

from sklearn.dummy import DummyClassifier
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

RESULTS_FILE = DATA_DIR / "baseline_cv_results.csv"
SUMMARY_FILE = DATA_DIR / "baseline_cv_summary.csv"

RANDOM_STATE = 42
N_SPLITS = 3


def load_data():
    """Load features and KEV labels, preserving row alignment."""

    if not X_FILE.exists() or not Y_FILE.exists():
        raise FileNotFoundError(
            "Prepared ML files are missing. "
            "Run prepare_ml_dataset.py first."
        )

    X = pd.read_csv(X_FILE)
    y_df = pd.read_csv(Y_FILE)

    if len(X) != len(y_df):
        raise ValueError("X and y have different numbers of rows.")

    if "cve_id" not in y_df.columns or "is_kev" not in y_df.columns:
        raise ValueError("The target file must contain cve_id and is_kev.")

    if y_df["cve_id"].isna().any():
        raise ValueError("Missing CVE IDs in target file.")

    if y_df["cve_id"].duplicated().any():
        raise ValueError("Duplicate CVE IDs in target file.")

    y = y_df["is_kev"].astype(int)

    if set(y.unique()) != {0, 1}:
        raise ValueError("The target must contain both classes 0 and 1.")

    if X.isna().sum().sum() == 0:
        print("No missing feature values detected.")
    else:
        print(
            "Missing feature values:",
            int(X.isna().sum().sum())
        )

    return X, y, y_df["cve_id"]


def build_models():
    """Create a naive reference model and a logistic regression pipeline."""

    logistic_pipeline = Pipeline(
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

    dummy_pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            (
                "classifier",
                DummyClassifier(strategy="prior"),
            ),
        ]
    )

    return {
        "Dummy_baseline": dummy_pipeline,
        "Logistic_regression": logistic_pipeline,
    }


def evaluate_models(X, y, cve_ids):
    """Evaluate models with stratified cross-validation."""

    cv = StratifiedKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    models = build_models()
    results = []

    for fold_number, (train_idx, test_idx) in enumerate(
        cv.split(X, y),
        start=1,
    ):
        X_train = X.iloc[train_idx]
        X_test = X.iloc[test_idx]

        y_train = y.iloc[train_idx]
        y_test = y.iloc[test_idx]

        print(f"\nFold {fold_number}")
        print(f"  Training rows: {len(train_idx)}")
        print(f"  Test rows: {len(test_idx)}")
        print(f"  KEV in training: {int(y_train.sum())}")
        print(f"  KEV in test: {int(y_test.sum())}")

        for model_name, model in models.items():
            # The pipeline is fitted only on this fold's training data.
            model.fit(X_train, y_train)

            predictions = model.predict(X_test)
            probabilities = model.predict_proba(X_test)[:, 1]

            fold_result = {
                "model": model_name,
                "fold": fold_number,
                "train_rows": len(train_idx),
                "test_rows": len(test_idx),
                "train_kev": int(y_train.sum()),
                "test_kev": int(y_test.sum()),
                "precision": precision_score(
                    y_test,
                    predictions,
                    zero_division=0,
                ),
                "recall": recall_score(
                    y_test,
                    predictions,
                    zero_division=0,
                ),
                "f1": f1_score(
                    y_test,
                    predictions,
                    zero_division=0,
                ),
                "average_precision": average_precision_score(
                    y_test,
                    probabilities,
                ),
                "roc_auc": roc_auc_score(
                    y_test,
                    probabilities,
                ),
            }

            results.append(fold_result)

            print(f"  {model_name}")
            print(f"    Precision: {fold_result['precision']:.4f}")
            print(f"    Recall: {fold_result['recall']:.4f}")
            print(f"    F1: {fold_result['f1']:.4f}")
            print(
                "    Average precision: "
                f"{fold_result['average_precision']:.4f}"
            )
            print(f"    ROC AUC: {fold_result['roc_auc']:.4f}")

    return pd.DataFrame(results)


def save_results(results):
    """Save individual fold results and aggregate metrics."""

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    results.to_csv(RESULTS_FILE, index=False)

    metric_columns = [
        "precision",
        "recall",
        "f1",
        "average_precision",
        "roc_auc",
    ]

    summary = (
        results.groupby("model")[metric_columns]
        .agg(["mean", "std"])
        .round(4)
    )

    summary.to_csv(SUMMARY_FILE)

    return summary


def main():
    print("=" * 65)
    print("VULNGUARD AI - BASELINE ML EXPERIMENT")
    print("=" * 65)

    X, y, cve_ids = load_data()

    print(f"\nDataset rows: {len(X)}")
    print(f"Number of features: {X.shape[1]}")
    print(f"KEV positive examples: {int(y.sum())}")
    print(f"Non-KEV examples: {int((y == 0).sum())}")
    print(f"Cross-validation folds: {N_SPLITS}")

    results = evaluate_models(X, y, cve_ids)
    summary = save_results(results)

    print("\n" + "=" * 65)
    print("CROSS-VALIDATION SUMMARY")
    print("=" * 65)
    print(summary.to_string())

    print("\nFiles created:")
    print(f"  {RESULTS_FILE}")
    print(f"  {SUMMARY_FILE}")

    print("\nIMPORTANT:")
    print(
        "This is an exploratory experiment, not evidence "
        "of production-ready KEV prediction."
    )


if __name__ == "__main__":
    main()
