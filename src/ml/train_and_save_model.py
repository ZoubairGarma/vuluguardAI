"""
VulnGuard AI - Local ML Model Training and Serialization
Trains a machine learning pipeline to predict high exploitation risk (KEV),
evaluates its performance, and serializes the model to data/models/risk_model.joblib.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data" / "processed" / "ml"
MODELS_DIR = PROJECT_ROOT / "data" / "models"

X_FILE = DATA_DIR / "X_features.csv"
Y_FILE = DATA_DIR / "y_kev.csv"
MODEL_OUTPUT = MODELS_DIR / "risk_model.joblib"
METADATA_OUTPUT = MODELS_DIR / "model_metadata.json"

RANDOM_STATE = 42
N_SPLITS = 5


def train_and_save():
    print("=" * 65)
    print("VULNGUARD AI - LOCAL ML MODEL TRAINING & SERIALIZATION")
    print("=" * 65)

    if not X_FILE.exists() or not Y_FILE.exists():
        raise FileNotFoundError(
            f"Missing dataset files in {DATA_DIR}. "
            "Please run 'python -m src.preprocessing.prepare_ml_dataset' first."
        )

    # 1. Load data
    print(f"\n[1/4] Loading dataset from {DATA_DIR}...")
    X = pd.read_csv(X_FILE)
    y_df = pd.read_csv(Y_FILE)
    y = y_df["is_kev"].astype(int)
    feature_names = list(X.columns)

    print(f"  Total samples: {len(X)}")
    print(f"  Features count: {len(feature_names)}")
    print(f"  Positive cases (KEV): {int(y.sum())} ({y.sum() / len(y):.2%})")
    print(f"  Negative cases: {int((y == 0).sum())}")

    # 2. Build Pipeline
    print("\n[2/4] Assembling ML Pipeline (Imputer + Scaler + Balanced Random Forest)...")
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        (
            "classifier",
            RandomForestClassifier(
                n_estimators=100,
                max_depth=6,
                class_weight="balanced",
                random_state=RANDOM_STATE,
                n_jobs=-1,
            ),
        ),
    ])

    # 3. Cross-Validation Evaluation
    print(f"\n[3/4] Evaluating model with {N_SPLITS}-Fold Stratified Cross-Validation...")
    cv = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    cv_scores = cross_validate(
        pipeline,
        X,
        y,
        cv=cv,
        scoring=["roc_auc", "average_precision", "f1", "recall", "precision"],
        return_train_score=False,
    )

    metrics = {
        "roc_auc_mean": round(float(cv_scores["test_roc_auc"].mean()), 4),
        "roc_auc_std": round(float(cv_scores["test_roc_auc"].std()), 4),
        "pr_auc_mean": round(float(cv_scores["test_average_precision"].mean()), 4),
        "pr_auc_std": round(float(cv_scores["test_average_precision"].std()), 4),
        "f1_mean": round(float(cv_scores["test_f1"].mean()), 4),
        "recall_mean": round(float(cv_scores["test_recall"].mean()), 4),
        "precision_mean": round(float(cv_scores["test_precision"].mean()), 4),
    }

    print("\nCross-Validation Results:")
    print(f"  ROC-AUC:            {metrics['roc_auc_mean']} ± {metrics['roc_auc_std']}")
    print(f"  Average Precision:  {metrics['pr_auc_mean']} ± {metrics['pr_auc_std']}")
    print(f"  F1-Score:           {metrics['f1_mean']}")
    print(f"  Recall (Detection): {metrics['recall_mean']}")

    # 4. Train final model on full dataset and serialize
    print(f"\n[4/4] Fitting final pipeline and serializing to {MODEL_OUTPUT}...")
    pipeline.fit(X, y)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_OUTPUT)

    metadata = {
        "model_name": "VulnGuard KEV Risk Classifier",
        "algorithm": "RandomForestClassifier(balanced)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(X),
        "total_features": len(feature_names),
        "feature_names": feature_names,
        "evaluation_metrics": metrics,
        "model_file": str(MODEL_OUTPUT.relative_to(PROJECT_ROOT)),
    }

    with open(METADATA_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("\n" + "=" * 65)
    print("SUCCESS: Model successfully trained and saved!")
    print(f"  Model binary:   {MODEL_OUTPUT}")
    print(f"  Model metadata: {METADATA_OUTPUT}")
    print("=" * 65)


if __name__ == "__main__":
    train_and_save()

